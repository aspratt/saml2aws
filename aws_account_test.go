package saml2aws

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// singleRoleAssertion returns testdata/assertion.xml, base64 encoded, with the
// second role removed, so the assertion carries exactly one role.
func singleRoleAssertion(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)
	xml := strings.Replace(string(data),
		"\n        <AttributeValue>arn:aws:iam::123123123123:saml-provider/ExampleADFS,arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSNonProd</AttributeValue>", "", 1)
	assert.NotEqual(t, string(data), xml)
	return base64.StdEncoding.EncodeToString([]byte(xml))
}

// A single-role user: AWS answers the sign-in POST with a 302 to the console
// instead of the role chooser, so the chooser page is never served.
func TestParseAWSAccountsSingleRoleRedirect(t *testing.T) {
	assertion := singleRoleAssertion(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/saml", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, assertion, r.FormValue("SAMLResponse"))
		http.Redirect(w, r, "/console", http.StatusFound)
	})
	mux.HandleFunc("/console", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>AWS Management Console</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	accounts, err := ParseAWSAccounts(srv.URL+"/saml", assertion)
	require.NoError(t, err)
	require.Len(t, accounts, 1)

	account := accounts[0]
	assert.Equal(t, "Account: 123123123123", account.Name)
	require.Len(t, account.Roles, 1)
	assert.Equal(t, "arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSBuild", account.Roles[0].RoleARN)
	assert.Equal(t, "AWS-Admin-CloudOPSBuild", account.Roles[0].Name)
}

// Regression guard: a multi-role user gets the chooser page, which is parsed
// as before.
func TestParseAWSAccountsChooserPage(t *testing.T) {
	data, err := os.ReadFile("testdata/saml.html")
	assert.Nil(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	accounts, err := ParseAWSAccounts(srv.URL, singleRoleAssertion(t))
	require.NoError(t, err)
	require.Len(t, accounts, 2)
	assert.Equal(t, "Account: account-alias (000000000001)", accounts[0].Name)
}

func TestExtractAWSAccounts(t *testing.T) {
	data, err := os.ReadFile("testdata/saml.html")
	assert.Nil(t, err)

	accounts, err := ExtractAWSAccounts(data)
	assert.Nil(t, err)
	assert.Len(t, accounts, 2)

	account := accounts[0]
	assert.Equal(t, account.Name, "Account: account-alias (000000000001)")

	assert.Len(t, account.Roles, 2)
	role := account.Roles[0]
	assert.Equal(t, role.RoleARN, "arn:aws:iam::000000000001:role/Development")
	assert.Equal(t, role.Name, "Development")
	role = account.Roles[1]
	assert.Equal(t, role.RoleARN, "arn:aws:iam::000000000001:role/Production")
	assert.Equal(t, role.Name, "Production")

	account = accounts[1]
	assert.Equal(t, account.Name, "Account: 000000000002")

	assert.Len(t, account.Roles, 1)
	role = account.Roles[0]
	assert.Equal(t, role.RoleARN, "arn:aws:iam::000000000002:role/Production")
	assert.Equal(t, role.Name, "Production")
}

func TestAssignPrincipals(t *testing.T) {
	awsRoles := []*AWSRole{
		{
			PrincipalARN: "arn:aws:iam::000000000001:saml-provider/test-idp",
			RoleARN:      "arn:aws:iam::000000000001:role/Development",
		},
	}

	awsAccounts := []*AWSAccount{
		{
			Roles: []*AWSRole{
				{
					RoleARN: "arn:aws:iam::000000000001:role/Development",
				},
			},
		},
	}

	AssignPrincipals(awsRoles, awsAccounts)

	assert.Equal(t, "arn:aws:iam::000000000001:saml-provider/test-idp", awsAccounts[0].Roles[0].PrincipalARN)
}

func TestLocateRole(t *testing.T) {
	awsRoles := []*AWSRole{
		{
			PrincipalARN: "arn:aws:iam::000000000001:saml-provider/test-idp",
			RoleARN:      "arn:aws:iam::000000000001:role/Development",
		},
		{
			PrincipalARN: "arn:aws:iam::000000000002:saml-provider/test-idp",
			RoleARN:      "arn:aws:iam::000000000002:role/Development",
		},
	}

	role, err := LocateRole(awsRoles, "arn:aws:iam::000000000001:role/Development")

	assert.Empty(t, err)

	assert.Equal(t, "arn:aws:iam::000000000001:role/Development", role.RoleARN)
}

// A redirect that lands on an error page must not be read as a single-role
// user: the fallback only applies to a successful sign-in.
func TestParseAWSAccountsRedirectToErrorPage(t *testing.T) {
	assertion := singleRoleAssertion(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/saml", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/forbidden", http.StatusFound)
	})
	mux.HandleFunc("/forbidden", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html><body>Access denied</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	accounts, err := ParseAWSAccounts(srv.URL+"/saml", assertion)
	require.NoError(t, err)
	assert.Empty(t, accounts)
}

// A redirect loop must stop after Go's default cap of 10 redirects, not
// follow forever.
func TestParseAWSAccountsRedirectLoop(t *testing.T) {
	assertion := singleRoleAssertion(t)

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits > 50 {
			// Bound the test if the cap is missing; the assertion below then fails.
			_, _ = w.Write([]byte("<html></html>"))
			return
		}
		http.Redirect(w, r, "/saml", http.StatusFound)
	}))
	defer srv.Close()

	_, err := ParseAWSAccounts(srv.URL+"/saml", assertion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stopped after 10 redirects")
	assert.LessOrEqual(t, hits, 11)
}
