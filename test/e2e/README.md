# saml2aws end-to-end harness

Tests saml2aws **as it is in this checkout**: no saml2aws source or `go.mod`
changes. Everything runs in Docker Compose, with every image built from a
build context and no bind mounts, so it works against a local or a remote
Docker daemon and from a clean checkout.

| Target | What runs | Needs |
|---|---|---|
| `make unit` | The repository's own `go test ./...`, unchanged | Docker, internet (one browser test opens google.com) |
| `make e2e` | Integration tests: Keycloak IdP + moto standing in for STS | Docker |
| `make e2e-aws` | The same integration tests against **real AWS STS** | Docker, AWS CLI, `AWS_PROFILE` |
| `make aws-teardown` | Deletes the IAM resources `e2e-aws` created | `AWS_PROFILE` |
| `make down` / `make clean` | Stop the stack / also delete `.work/` | |

Run from this directory (`make -C test/e2e e2e` from the repo root).

## How it works

```
 runner (golang:1.22.5, saml2aws built from this checkout)
   │  go test -tags e2e ./test/e2e/  →  exec saml2aws login/list-roles/script
   │
   ├── idp network ─────── keycloak   realm "e2e", user e2e-user, SAML client
   │                                  urn:amazon:webservices (IdP-initiated SSO)
   └── fakeaws network ─── sts        moto, answering as sts.amazonaws.com
       (make e2e only)     signin     stand-in for signin.aws.amazon.com/saml
```

- **No endpoint override.** saml2aws (aws-sdk-go v1) has no setting for a
  custom STS endpoint. Instead, on the `fakeaws` network, moto takes the real
  hostnames (`sts.amazonaws.com`, `sts.<region>.amazonaws.com`) as Docker
  network aliases and serves TLS with a certificate from a throwaway test CA.
  The runner trusts that CA through `SSL_CERT_FILE`.
- **`signin`** stands in for `https://signin.aws.amazon.com/saml`.
  `saml2aws list-roles` POSTs the assertion there to read account names, and
  like AWS, the stand-in renders the role page from the assertion's Role
  attributes.
- `scripts/render.sh` writes everything generated into `.work/` (gitignored):
  the CA and STS certificate, a random user password, the realm (from
  `keycloak/realm.json.tmpl`) and `e2e.env`.
- Each test runs saml2aws with a fresh `HOME`, so it never reads or writes
  your `~/.saml2aws` or `~/.aws`. Credentials land in that `HOME`'s
  `.aws/credentials`. Every saml2aws run is capped at 60s.

### Unit tests and Playwright

The pinned `playwright-go v0.4702.0` downloads driver 1.47.2 from the retired
`playwright.azureedge.net` CDN, so the four `pkg/provider/browser` tests fail
anywhere today (404, then a nil-pointer panic in `TestAutoFill`). The runner
image works around this through the environment only. It assembles the same
driver from npm (`playwright-core@1.47.2` + Node 20) at
`$PLAYWRIGHT_DRIVER_PATH/ms-playwright-go/1.47.2`, and sets
`PLAYWRIGHT_DOWNLOAD_HOST` to the current CDN for the Chromium download.

## Integration tests (`e2e_test.go`, build tag `e2e`)

| Test | Checks |
|---|---|
| `TestLoginWritesCredentials` | `login --skip-prompt` writes the `[e2e]` profile with key, secret and session token; `x_principal_arn` is the assumed-role ARN; expiry is about 1h out; the credentials work: `GetCallerIdentity` returns the assumed role |
| `TestScriptPrintsLoggedInCredentials` | `script --shell=env` prints the stored credentials |
| `TestListRolesShowsAssertionRole` | `list-roles` shows the role from the assertion |
| `TestWrongPasswordFailsWithErrorElementConfig` | a wrong password fails fast and writes no credentials, with `kc_auth_error_element` set for Keycloak 26 |
| `TestWrongPasswordFailsDefaultConfig` | the same with the default config. **Known bug, skipped** unless `E2E_KNOWN_BUGS=1` (see below) |

## Real AWS tier (`make e2e-aws`)

```sh
aws sso login --sso-session <session> --use-device-code
make e2e-aws AWS_PROFILE=<profile>
make aws-teardown AWS_PROFILE=<profile>   # when finished with the account
```

AWS never contacts the IdP. STS only checks the assertion's signature against
the IAM SAML provider's metadata, so a local Keycloak is enough. `e2e-aws`:

1. renders the realm with the profile's account id and starts Keycloak;
2. fetches Keycloak's SAML metadata (`metadata` service);
3. `scripts/aws-setup.sh` creates the IAM SAML provider `saml2aws-e2e`, or
   updates it, since Keycloak makes a new signing key each start. It also
   creates the role `saml2aws-e2e`, which has **no policies**, and a trust
   policy that allows only `sts:AssumeRoleWithSAML` from that provider for
   audience `https://signin.aws.amazon.com/saml`. Both are tagged
   `purpose=saml2aws-e2e`;
4. runs the integration tests with no `fakeaws` network, so the real
   `sts.amazonaws.com` and `signin.aws.amazon.com` are used.

`aws-teardown.sh` refuses to delete the role if anything has attached a policy
to it.

## Findings so far

1. **Build:** `go build ./cmd/saml2aws` and `go vet ./...` are clean (Go 1.22.5
   in the runner; Go 1.27 also builds it).
2. **Browser provider tests fail outside this harness**: the Playwright CDN is
   retired (see above). The real fix is a `playwright-go` upgrade.
3. **Keycloak 26: a wrong password loops forever.** Keycloak 26's login
   theme (`keycloak.v2`) shows "Invalid username or password." under
   `div#input-error-password`. `DefaultAuthErrorElement` is
   `span#input-error, div#input-error-username`, so `passwordValid()` never
   sees the error, and `doAuthenticate` re-posts the login form recursively
   until the process is killed. This hits the IdP on every loop. Reproduce
   with `E2E_KNOWN_BUGS=1`; the test reaches its 60s cap. Workaround: set
   `kc_auth_error_element = div#input-error-password` in the IdP account.
   Even then the error reads "unable to locate saml response field" rather
   than naming the bad password.
4. `login` creates `~/.aws/credentials` and an empty `[profile]` section
   *before* it authenticates, so a failed login leaves them behind.
5. `script` validates the IdP account (it needs `--url` and the provider)
   even though it only prints stored credentials.

## PingOne tier: not built yet

**Blocker: which environment to use.** customer-a's PingOne is the NFT org,
which msp-agent records as read-only. A live PingOne test needs a SAML app
(SP entity `urn:amazon:webservices`, ACS `https://signin.aws.amazon.com/saml`,
the Role / RoleSessionName attributes) and a test user. That needs either our
own PingOne trial, a customer-a sandbox, or sign-off for the NFT org. The AWS
side would reuse `aws-setup.sh` with PingOne's metadata instead of Keycloak's.

**Likely provider gap (from reading the code, not yet tested live).**
`pkg/provider/pingone` dates from 2018. It looks for an HTML login form with
`pf.username` / `pf.pass` (the PingFederate-style page used by PingOne for
Enterprise) and the PingID `ppm_request` / `authenticator.pingone.com`
redirects. Current PingOne (`auth.pingone.com/<env>/saml20/idp/startsso`)
renders sign-in with a JavaScript app driven by its flows API, so that form
is not in the HTML saml2aws fetches. Expect the `pingone` provider to fail
at "error extracting login form". The `Browser` provider (Playwright, now
runnable in this harness) is the likely working route; a native PingOne
provider would be new code.
