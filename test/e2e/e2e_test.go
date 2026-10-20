//go:build e2e

// Package e2e drives the saml2aws binary, built unmodified from this
// checkout, against a live Keycloak IdP and either moto (E2E_TARGET=moto) or
// real AWS STS (E2E_TARGET=aws). Run it through test/e2e/Makefile, which
// provides the services and the environment below.
package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"
)

const (
	profile = "e2e"
	region  = "ap-southeast-2"
)

func mustEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set; run the tests through test/e2e/Makefile", name)
	}
	return v
}

// run executes saml2aws with HOME set to home and a clean environment, so
// nothing from the caller's ~/.saml2aws, ~/.aws or SAML2AWS_* leaks in.
// Each run is capped so a saml2aws that loops or waits for input fails the
// test instead of hanging it.
func run(t *testing.T, home string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "saml2aws", args...)
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	if v := os.Getenv("SSL_CERT_FILE"); v != "" {
		cmd.Env = append(cmd.Env, "SSL_CERT_FILE="+v)
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	t.Logf("saml2aws %s\n%s", redact(strings.Join(args, " ")), redact(string(out)))
	return string(out), err
}

func redact(s string) string {
	if p := os.Getenv("E2E_PASSWORD"); p != "" {
		s = strings.ReplaceAll(s, p, "****")
	}
	return s
}

func idpArgs(t *testing.T) []string {
	return []string{
		"--idp-provider=KeyCloak",
		"--url=" + mustEnv(t, "E2E_IDP_URL"),
		"--username=" + mustEnv(t, "E2E_USERNAME"),
		"--mfa=Auto",
		"--region=" + region,
		"--disable-keychain",
		"--skip-prompt",
	}
}

func loginArgs(t *testing.T, password string) []string {
	return append(append([]string{"login"}, idpArgs(t)...),
		"--password="+password,
		"--role="+mustEnv(t, "E2E_ROLE_ARN"),
		"--profile="+profile,
		"--session-duration=3600",
	)
}

func assumedRoleARN(t *testing.T) string {
	return "arn:aws:sts::" + mustEnv(t, "E2E_ACCOUNT_ID") + ":assumed-role/saml2aws-e2e/" + mustEnv(t, "E2E_USERNAME")
}

func readProfile(t *testing.T, home string) *ini.Section {
	t.Helper()
	f, err := ini.Load(filepath.Join(home, ".aws", "credentials"))
	require.NoError(t, err, "saml2aws should write ~/.aws/credentials")
	s, err := f.GetSection(profile)
	require.NoError(t, err, "credentials should contain the [%s] profile", profile)
	return s
}

func TestLoginWritesCredentials(t *testing.T) {
	home := t.TempDir()
	_, err := run(t, home, loginArgs(t, mustEnv(t, "E2E_PASSWORD"))...)
	require.NoError(t, err)

	s := readProfile(t, home)
	for _, k := range []string{"aws_access_key_id", "aws_secret_access_key", "aws_session_token"} {
		require.NotEmpty(t, s.Key(k).String(), k)
	}
	// x_principal_arn holds the assumed-role ARN, not the SAML provider ARN.
	require.Equal(t, assumedRoleARN(t), s.Key("x_principal_arn").String())

	expires, err := time.Parse(time.RFC3339, s.Key("x_security_token_expires").String())
	require.NoError(t, err)
	require.WithinDuration(t, time.Now().Add(time.Hour), expires, 5*time.Minute)

	// The written credentials must work: STS should see the assumed role.
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
		Credentials: credentials.NewStaticCredentials(
			s.Key("aws_access_key_id").String(),
			s.Key("aws_secret_access_key").String(),
			s.Key("aws_session_token").String()),
	}))
	id, err := sts.New(sess).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	require.NoError(t, err)
	require.Equal(t, mustEnv(t, "E2E_ACCOUNT_ID"), aws.StringValue(id.Account))
	require.Equal(t, assumedRoleARN(t), aws.StringValue(id.Arn))
}

func TestScriptPrintsLoggedInCredentials(t *testing.T) {
	home := t.TempDir()
	_, err := run(t, home, loginArgs(t, mustEnv(t, "E2E_PASSWORD"))...)
	require.NoError(t, err)
	key := readProfile(t, home).Key("aws_access_key_id").String()

	// script only reads stored credentials, but still validates the IdP account,
	// so it needs the IdP flags too.
	out, err := run(t, home, append(append([]string{"script"}, idpArgs(t)...),
		"--shell=env", "--profile="+profile)...)
	require.NoError(t, err)
	require.Contains(t, out, "AWS_ACCESS_KEY_ID="+key)
}

// list-roles reads account names from the AWS sign-in role chooser, but with a
// single role AWS skips the chooser and redirects to the console. Once the
// redirect finds no accounts, list-roles falls back to the roles in the
// assertion (fork issue aspratt/saml2aws#14).
func TestListRolesSingleRole(t *testing.T) {
	// list-roles always posts to the real AWS sign-in page, which moto doesn't
	// stand in for and the offline lane can't reach, so this runs in e2e-aws only.
	if mustEnv(t, "E2E_TARGET") != "aws" {
		t.Skip("needs the real AWS sign-in page; runs in the e2e-aws lane only")
	}
	home := t.TempDir()
	out, err := run(t, home, append(append([]string{"list-roles"}, idpArgs(t)...),
		"--password="+mustEnv(t, "E2E_PASSWORD"))...)
	require.NoError(t, err)
	require.Contains(t, out, mustEnv(t, "E2E_ROLE_ARN"))
}

// requireNoCredentials checks a failed login wrote no credentials. saml2aws
// creates ~/.aws/credentials, and an empty [profile] section, before it
// authenticates, so only the keys are meaningful.
func requireNoCredentials(t *testing.T, home string) {
	t.Helper()
	f, err := ini.LooseLoad(filepath.Join(home, ".aws", "credentials"))
	require.NoError(t, err)
	if f.HasSection(profile) {
		s := f.Section(profile)
		for _, k := range []string{"aws_access_key_id", "aws_secret_access_key", "aws_session_token"} {
			require.Empty(t, s.Key(k).String(), "a failed login must not write %s", k)
		}
	}
}

// Known bug: Keycloak 26's login theme reports a bad password in
// div#input-error-password, which the default kc_auth_error_element
// ("span#input-error, div#input-error-username") does not match. saml2aws
// then never sees the error and re-posts the login form until the run is
// killed. Set E2E_KNOWN_BUGS=1 to run it.
func TestWrongPasswordFailsDefaultConfig(t *testing.T) {
	if os.Getenv("E2E_KNOWN_BUGS") == "" {
		t.Skip("known bug: wrong password loops against Keycloak 26 with the default kc_auth_error_element")
	}
	home := t.TempDir()
	_, err := run(t, home, loginArgs(t, "definitely-not-the-password")...)
	require.Error(t, err)
	require.NotErrorIs(t, err, context.DeadlineExceeded, "saml2aws should fail fast, not loop")
	requireNoCredentials(t, home)
}

// The documented workaround: point kc_auth_error_element at the Keycloak 26
// element in the IdP account config.
func TestWrongPasswordFailsWithErrorElementConfig(t *testing.T) {
	home := t.TempDir()
	cfg := "[default]\nprovider = KeyCloak\nkc_auth_error_element = div#input-error-password\n"
	require.NoError(t, os.WriteFile(filepath.Join(home, ".saml2aws"), []byte(cfg), 0o600))

	_, err := run(t, home, loginArgs(t, "definitely-not-the-password")...)
	require.Error(t, err)
	require.NotErrorIs(t, err, context.DeadlineExceeded, "saml2aws should fail fast, not loop")
	requireNoCredentials(t, home)
}
