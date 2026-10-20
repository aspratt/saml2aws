package okta

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/helper/credentials"
)

// memHelper is an in-memory credentials store for tests.
type memHelper struct {
	store map[string]*credentials.Credentials
}

func (m *memHelper) Add(c *credentials.Credentials) error {
	m.store[c.ServerURL] = c
	return nil
}

func (m *memHelper) Delete(serverURL string) error {
	delete(m.store, serverURL)
	return nil
}

func (m *memHelper) Get(serverURL string) (string, string, error) {
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

func TestDeviceTokenLegacyWithoutCredentialStore(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	// The default helper has no storage; keep the old value so remembered devices still work.
	oc, loginDetails := setupTestClient(t, ts, "PUSH")
	require.NoError(t, oc.setDeviceTokenCookie(loginDetails))
	assert.Equal(t, "okta_user@example.com_saml2aws", dtCookie(t, oc, loginDetails.URL))
}
