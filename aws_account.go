package saml2aws

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
)

// AWSAccount holds the AWS account name and roles
type AWSAccount struct {
	Name  string
	Roles []*AWSRole
}

// ParseAWSAccounts extract the aws accounts from the saml assertion
func ParseAWSAccounts(audience string, samlAssertion string) ([]*AWSAccount, error) {
	// A user with a single role is redirected to the console instead of being
	// shown the role chooser, so note any redirect for the fallback below.
	redirected := false
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirected = true
			return nil
		},
	}

	res, err := client.PostForm(audience, url.Values{"SAMLResponse": {samlAssertion}})
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving AWS login form")
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving AWS login body")
	}

	accounts, err := ExtractAWSAccounts(data)
	if err != nil {
		return nil, err
	}

	if len(accounts) == 0 && redirected {
		return accountsFromAssertion(samlAssertion)
	}

	return accounts, nil
}

// accountsFromAssertion builds the accounts from the roles in the SAML
// assertion. It is the fallback for when AWS redirects instead of serving the
// role chooser. The assertion carries no account alias, so accounts are named
// by id, as the chooser names accounts that have no alias.
func accountsFromAssertion(samlAssertion string) ([]*AWSAccount, error) {
	data, err := base64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding saml assertion")
	}

	roles, err := ExtractAwsRoles(data)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing aws roles")
	}

	awsRoles, err := ParseAWSRoles(roles)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing aws roles")
	}

	accounts := []*AWSAccount{}
	byID := make(map[string]*AWSAccount)
	for _, awsRole := range awsRoles {
		id := accountIDFromRoleARN(awsRole.RoleARN)

		account, ok := byID[id]
		if !ok {
			account = &AWSAccount{Name: "Account: " + id}
			byID[id] = account
			accounts = append(accounts, account)
		}

		account.Roles = append(account.Roles, &AWSRole{
			RoleARN: awsRole.RoleARN,
			Name:    roleNameFromRoleARN(awsRole.RoleARN),
		})
	}

	return accounts, nil
}

// accountIDFromRoleARN returns the account id from an ARN of the form
// arn:partition:service:region:account-id:resource
func accountIDFromRoleARN(roleARN string) string {
	parts := strings.Split(roleARN, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

// roleNameFromRoleARN returns the role name, the last path segment of the ARN
func roleNameFromRoleARN(roleARN string) string {
	return roleARN[strings.LastIndex(roleARN, "/")+1:]
}

// ExtractAWSAccounts extract the accounts from the AWS html page
func ExtractAWSAccounts(data []byte) ([]*AWSAccount, error) {
	accounts := []*AWSAccount{}

	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("fieldset > div.saml-account").Each(func(i int, s *goquery.Selection) {
		account := new(AWSAccount)
		account.Name = s.Find("div.saml-account-name").Text()
		s.Find("label").Each(func(i int, s *goquery.Selection) {
			role := new(AWSRole)
			role.Name = s.Text()
			role.RoleARN, _ = s.Attr("for")
			account.Roles = append(account.Roles, role)
		})
		accounts = append(accounts, account)
	})

	return accounts, nil
}

// AssignPrincipals assign principal from roles
func AssignPrincipals(awsRoles []*AWSRole, awsAccounts []*AWSAccount) {

	awsPrincipalARNs := make(map[string]string)
	for _, awsRole := range awsRoles {
		awsPrincipalARNs[awsRole.RoleARN] = awsRole.PrincipalARN
	}

	for _, awsAccount := range awsAccounts {
		for _, awsRole := range awsAccount.Roles {
			awsRole.PrincipalARN = awsPrincipalARNs[awsRole.RoleARN]
		}
	}

}

// LocateRole locate role by name
func LocateRole(awsRoles []*AWSRole, roleName string) (*AWSRole, error) {
	for _, awsRole := range awsRoles {
		if awsRole.RoleARN == roleName {
			return awsRole, nil
		}
	}

	return nil, fmt.Errorf("Supplied RoleArn not found in saml assertion: %s", roleName)
}
