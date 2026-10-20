package okta

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/helper/credentials"
)

// memHelper is an in-memory credentials store for tests.
type memHelper struct {
	store  map[string]*credentials.Credentials
	getErr error
	addErr error
}

func (m *memHelper) Add(c *credentials.Credentials) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.store[c.ServerURL] = c
	return nil
}

func (m *memHelper) Delete(serverURL string) error {
	delete(m.store, serverURL)
	return nil
}

func (m *memHelper) Get(serverURL string) (string, string, error) {
	if m.getErr != nil {
		return "", "", m.getErr
	}
	c, ok := m.store[serverURL]
	if !ok {
		return "", "", credentials.ErrCredentialsNotFound
	}
	return c.Username, c.Secret, nil
}

func (m *memHelper) SupportsCredentialStorage() bool { return true }

func useMemHelper(t *testing.T) *memHelper {
	t.Helper()
	old := credentials.CurrentHelper
	h := &memHelper{store: map[string]*credentials.Credentials{}}
	credentials.CurrentHelper = h
	t.Cleanup(func() { credentials.CurrentHelper = old })
	return h
}

func dtCookie(t *testing.T, oc *Client, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	for _, c := range oc.client.Jar.Cookies(&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}) {
		if c.Name == "DT" {
			return c.Value
		}
	}
	t.Fatal("DT cookie not set")
	return ""
}

func TestDeviceTokenIsRandomAndStable(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	h := useMemHelper(t)

	oc, loginDetails := setupTestClient(t, ts, "PUSH")
	require.NoError(t, oc.setDeviceTokenCookie(loginDetails))
	first := dtCookie(t, oc, loginDetails.URL)

	assert.NotContains(t, first, loginDetails.Username, "device token must not be derived from the username")
	assert.NotEqual(t, "okta_"+loginDetails.Username+"_saml2aws", first)
	_, stored, err := h.Get(loginDetails.URL + "/deviceToken")
	require.NoError(t, err, "device token must be persisted in the credential store")
	assert.Equal(t, first, stored)

	// A second run (new client) reuses the stored token.
	oc2, loginDetails2 := setupTestClient(t, ts, "PUSH")
	require.NoError(t, oc2.setDeviceTokenCookie(loginDetails2))
	assert.Equal(t, first, dtCookie(t, oc2, loginDetails2.URL))

	// A different install (empty store) gets a different token.
	useMemHelper(t)
	oc3, loginDetails3 := setupTestClient(t, ts, "PUSH")
	require.NoError(t, oc3.setDeviceTokenCookie(loginDetails3))
	assert.NotEqual(t, first, dtCookie(t, oc3, loginDetails3.URL))
	assert.False(t, strings.HasPrefix(dtCookie(t, oc3, loginDetails3.URL), "okta_"))
}

func TestDeviceTokenFileFallbackWithoutCredentialStore(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	dir := t.TempDir()
	useDeviceTokenDir(t, dir)

	// The default helper has no storage, so the token goes to a private file.
	oc, loginDetails := setupTestClient(t, ts, "PUSH")
	require.NoError(t, oc.setDeviceTokenCookie(loginDetails))
	first := dtCookie(t, oc, loginDetails.URL)
	assert.NotContains(t, first, loginDetails.Username)

	files, err := filepath.Glob(filepath.Join(dir, "okta-device-token-*"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(files[0])
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
	}

	// A later run reads the same token back.
	oc2, loginDetails2 := setupTestClient(t, ts, "PUSH")
	require.NoError(t, oc2.setDeviceTokenCookie(loginDetails2))
	assert.Equal(t, first, dtCookie(t, oc2, loginDetails2.URL))
}

func TestDeviceTokenTransientGetErrorDoesNotRotate(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	h := useMemHelper(t)

	oc, loginDetails := setupTestClient(t, ts, "PUSH")
	require.NoError(t, oc.setDeviceTokenCookie(loginDetails))
	stored := dtCookie(t, oc, loginDetails.URL)

	// The keychain is locked or unavailable for this run.
	h.getErr = errors.New("keychain locked")
	hook := logtest.NewGlobal()
	oc2, loginDetails2 := setupTestClient(t, ts, "PUSH")
	require.NoError(t, oc2.setDeviceTokenCookie(loginDetails2))

	_, still, err := (&memHelper{store: h.store}).Get(loginDetails.URL + "/deviceToken")
	require.NoError(t, err)
	assert.Equal(t, stored, still, "a transient Get error must not overwrite the stored token")
	assert.True(t, hasWarning(hook), "a transient Get error must be reported as a warning")
}

func TestDeviceTokenSaveErrorWarnsAndUsesFile(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	h := useMemHelper(t)
	h.addErr = errors.New("keychain write denied")
	dir := t.TempDir()
	useDeviceTokenDir(t, dir)

	hook := logtest.NewGlobal()
	oc, loginDetails := setupTestClient(t, ts, "PUSH")
	require.NoError(t, oc.setDeviceTokenCookie(loginDetails))
	first := dtCookie(t, oc, loginDetails.URL)

	assert.NotEqual(t, "okta_"+loginDetails.Username+"_saml2aws", first, "must not fall back to the predictable token")
	assert.True(t, hasWarning(hook), "a failed save must be reported as a warning")

	// The token kept in the file is reused while saves keep failing.
	oc2, loginDetails2 := setupTestClient(t, ts, "PUSH")
	require.NoError(t, oc2.setDeviceTokenCookie(loginDetails2))
	assert.Equal(t, first, dtCookie(t, oc2, loginDetails2.URL))
}

func hasWarning(hook *logtest.Hook) bool {
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel && strings.Contains(e.Message, "device token") {
			return true
		}
	}
	return false
}

func useDeviceTokenDir(t *testing.T, dir string) {
	t.Helper()
	old := deviceTokenDir
	deviceTokenDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { deviceTokenDir = old })
}

// TestMain keeps every test in this package away from the real
// ~/.aws/saml2aws directory.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "saml2aws-okta-test")
	if err != nil {
		panic(err)
	}
	deviceTokenDir = func() (string, error) { return dir, nil }
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
