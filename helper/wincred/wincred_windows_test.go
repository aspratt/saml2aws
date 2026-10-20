package wincred

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/helper/credentials"
)

// TestWincredRoundTrip stores, reads, lists and deletes a credential in the
// real Windows Credential Manager. wincred v1.2.2 built with Go >= 1.25 fails
// the write with "The stub received bad data" (aspratt/saml2aws#1).
func TestWincredRoundTrip(t *testing.T) {
	h := Wincred{}
	url := fmt.Sprintf("https://saml2aws-test.invalid/%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = h.Delete(url) })

	err := h.Add(&credentials.Credentials{ServerURL: url, Username: "e2e-user", Secret: "s3cr3t-value"})
	require.NoError(t, err, "storing the credential must succeed")

	user, secret, err := h.Get(url)
	require.NoError(t, err)
	require.Equal(t, "e2e-user", user)
	require.Equal(t, "s3cr3t-value", secret)

	all, err := h.List()
	require.NoError(t, err)
	require.Equal(t, "e2e-user", all[url])

	require.NoError(t, h.Delete(url))
	_, _, err = h.Get(url)
	require.ErrorIs(t, err, credentials.ErrCredentialsNotFound)
}
