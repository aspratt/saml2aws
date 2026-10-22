package pingntlm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/mocks"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

func TestMakeAbsoluteURL(t *testing.T) {
	require.Equal(t, makeAbsoluteURL("/a", "https://example.com"), "https://example.com/a")
	require.Equal(t, makeAbsoluteURL("https://foo.com/a/b", "https://bar.com"), "https://foo.com/a/b")
}

var docTests = []struct {
	fn       func(*goquery.Document) bool
	file     string
	expected bool
}{
	{docIsLogin, "example/login.html", true},
	{docIsLogin, "example/login2.html", true},
	{docIsLogin, "example/otp.html", false},
	{docIsLogin, "example/swipe.html", false},
	{docIsLogin, "example/form-redirect.html", false},
	{docIsLogin, "example/webauthn.html", false},
	{docIsOTP, "example/login.html", false},
	{docIsOTP, "example/otp.html", true},
	{docIsOTP, "example/swipe.html", false},
	{docIsOTP, "example/form-redirect.html", false},
	{docIsOTP, "example/webauthn.html", false},
	{docIsSwipe, "example/login.html", false},
	{docIsSwipe, "example/otp.html", false},
	{docIsSwipe, "example/swipe.html", true},
	{docIsSwipe, "example/form-redirect.html", false},
	{docIsSwipe, "example/webauthn.html", false},
	{docIsFormRedirect, "example/login.html", false},
	{docIsFormRedirect, "example/otp.html", false},
	{docIsFormRedirect, "example/swipe.html", false},
	{docIsFormRedirect, "example/form-redirect.html", true},
	{docIsFormRedirect, "example/webauthn.html", false},
	{docIsWebAuthn, "example/login.html", false},
	{docIsWebAuthn, "example/otp.html", false},
	{docIsWebAuthn, "example/swipe.html", false},
	{docIsWebAuthn, "example/form-redirect.html", false},
	{docIsWebAuthn, "example/webauthn.html", true},
	{docIsFormSamlRequest, "example/login.html", false},
	{docIsFormSamlRequest, "example/otp.html", false},
	{docIsFormSamlRequest, "example/swipe.html", false},
	{docIsFormSamlRequest, "example/form-redirect.html", false},
	{docIsFormSamlRequest, "example/webauthn.html", false},
	{docIsFormSamlResponse, "example/login.html", false},
	{docIsFormSamlResponse, "example/otp.html", false},
	{docIsFormSamlResponse, "example/swipe.html", false},
	{docIsFormSamlResponse, "example/form-redirect.html", false},
	{docIsFormSamlResponse, "example/webauthn.html", false},
	{docIsFormResume, "example/login.html", false},
	{docIsFormResume, "example/otp.html", false},
	{docIsFormResume, "example/swipe.html", false},
	{docIsFormResume, "example/form-redirect.html", false},
	{docIsFormResume, "example/webauthn.html", false},
	{docIsFormRedirectToAWS, "example/login.html", false},
	{docIsFormRedirectToAWS, "example/otp.html", false},
	{docIsFormRedirectToAWS, "example/swipe.html", false},
	{docIsFormRedirectToAWS, "example/form-redirect.html", false},
	{docIsFormRedirectToAWS, "example/webauthn.html", false},
}

func TestDocTypes(t *testing.T) {
	for _, tt := range docTests {
		data, err := os.ReadFile(tt.file)
		require.Nil(t, err)

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
		require.Nil(t, err)

		if tt.fn(doc) != tt.expected {
			t.Errorf("expect doc check of %v to be %v", tt.file, tt.expected)
		}
	}
}

func TestHandleLogin(t *testing.T) {
	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)

	data, err := os.ReadFile("example/login.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	_, req, err := ac.handleLogin(ctx, doc)
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "pf.username=fdsa")
	require.Contains(t, s, "pf.pass=secret")
}

func TestHandleLoginNoContextValue(t *testing.T) {
	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey(""), &loginDetails)

	data, err := os.ReadFile("example/login.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	_, _, err = ac.handleLogin(ctx, doc)
	assert.ErrorContains(t, err, "no context value for 'login'")
}

func TestHandleLoginNoForm(t *testing.T) {
	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte{}))
	require.Nil(t, err)

	_, _, err = ac.handleLogin(ctx, doc)
	assert.ErrorContains(t, err, "error extracting login form")
}

func TestHandleOTP(t *testing.T) {
	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("StringRequired", "Enter passcode").Return("5309")

	data, err := os.ReadFile("example/otp.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, req, err := ac.handleOTP(context.Background(), doc)
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "otp=5309")
}

func TestHandleOTPNoForm(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte{}))
	require.Nil(t, err)

	ac := Client{}
	_, _, err = ac.handleOTP(context.Background(), doc)
	assert.ErrorContains(t, err, "error extracting OTP form")
}

func TestHandleSwipe(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pingid/ppm/auth/status":
			_, err := w.Write([]byte("{\"status\":\"OK\"}"))
			require.Nil(t, err)
		default:
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}
	}))
	defer ts.Close()

	performTest := func(data []byte) bytes.Buffer {
		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bytes.ReplaceAll(data, []byte("https://authenticator.pingone.com"), []byte(ts.URL))))
		require.Nil(t, err)

		testTransport := http.DefaultTransport.(*http.Transport).Clone()
		testTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		ac := Client{
			client: &http.Client{Transport: testTransport},
		}

		var out bytes.Buffer
		log.SetOutput(&out)
		_, req, err := ac.handleSwipe(context.Background(), doc)
		log.SetOutput(os.Stderr)
		require.Nil(t, err)

		b, err := io.ReadAll(req.Body)
		require.Nil(t, err)

		s := string(b[:])
		require.Contains(t, s, "csrfToken=abdb4264-6aab-4e1a-a830-63c9188e2395")

		return out
	}

	t.Run("Swipe", func(t *testing.T) {
		data, err := os.ReadFile("example/swipe.html")
		require.Nil(t, err)

		performTest(data)
	})
}

func TestHandleSwipeNoResponseView(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pingid/ppm/auth/status":
			_, err := w.Write([]byte("{\"status\":\"OK\"}"))
			require.Nil(t, err)
		default:
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}
	}))
	defer ts.Close()

	performTest := func(data []byte) bytes.Buffer {
		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bytes.ReplaceAll(data, []byte("https://authenticator.pingone.com"), []byte(ts.URL))))
		require.Nil(t, err)

		testTransport := http.DefaultTransport.(*http.Transport).Clone()
		testTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		ac := Client{
			client: &http.Client{Transport: testTransport},
		}

		var out bytes.Buffer
		log.SetOutput(&out)
		_, _, err = ac.handleSwipe(context.Background(), doc)
		log.SetOutput(os.Stderr)
		assert.ErrorContains(t, err, "error extracting swipe response form")

		return out
	}

	t.Run("Swipe", func(t *testing.T) {
		data, err := os.ReadFile("example/swipe-no-reponseView.html")
		require.Nil(t, err)

		performTest(data)
	})
}

func TestHandleSwipeNoForm(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte{}))
	require.Nil(t, err)

	ac := Client{}
	_, _, err = ac.handleSwipe(context.Background(), doc)
	assert.ErrorContains(t, err, "error extracting swipe status form")
}

func TestHandleFormRedirect(t *testing.T) {
	data, err := os.ReadFile("example/form-redirect.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, req, err := ac.handleFormRedirect(context.Background(), doc)
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "ppm_request=secret")
	require.Contains(t, s, "idp_account_id=some-uuid")
}

func TestHandleFormRedirectNoForm(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte{}))
	require.Nil(t, err)

	ac := Client{}
	_, _, err = ac.handleFormRedirect(context.Background(), doc)
	assert.ErrorContains(t, err, "error extracting redirect form")
}

func TestHandleWebAuthn(t *testing.T) {
	data, err := os.ReadFile("example/webauthn.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, req, err := ac.handleWebAuthn(context.Background(), doc)
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "isWebAuthnSupportedByBrowser=false")
}

func TestHandleWebAuthnNoForm(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte{}))
	require.Nil(t, err)

	ac := Client{}
	_, _, err = ac.handleWebAuthn(context.Background(), doc)
	assert.ErrorContains(t, err, "error extracting webauthn form")
}

func TestNew(t *testing.T) {
	type args struct {
		idpAccount *cfg.IDPAccount
	}
	tests := []struct {
		name    string
		args    args
		want    *Client
		wantErr bool
	}{
		{
			name: "test client",
			args: args{
				idpAccount: &cfg.IDPAccount{
					SkipVerify: false,
				},
			},
			want:    &Client{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want.idpAccount = tt.args.idpAccount
			got, err := New(tt.args.idpAccount)
			tt.want.client = got.client
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticateInvalidHost(t *testing.T) {
	idpAccount := &cfg.IDPAccount{
		Provider:   "PingNTLM",
		MFA:        "Auto",
		SkipVerify: false,
	}
	client, err := New(idpAccount)
	assert.Nil(t, err)
	loginDetails := &creds.LoginDetails{Username: "testuser", Password: "testtestlol", URL: "https://id.example.com", MFAToken: "123456"}
	_, err = client.Authenticate(loginDetails)
	assert.ErrorContains(t, err, "no such host")
}

// malformedNTLMChallenge is a type-2 (CHALLENGE) message whose TargetName
// varField has BufferOffset 0xFFFFFFF8 and Len 16. BufferOffset+Len wraps to 8
// in uint32, so the old length check passes and the slice panics. This is
// GO-2026-5543 / CVE-2026-32952 in github.com/Azure/go-ntlmssp.
func malformedNTLMChallenge() []byte {
	b := make([]byte, 0, 48)
	b = append(b, []byte("NTLMSSP\x00")...)
	b = binary.LittleEndian.AppendUint32(b, 2)          // MessageType: CHALLENGE
	b = binary.LittleEndian.AppendUint16(b, 16)         // TargetName.Len
	b = binary.LittleEndian.AppendUint16(b, 16)         // TargetName.MaxLen
	b = binary.LittleEndian.AppendUint32(b, 0xFFFFFFF8) // TargetName.BufferOffset
	b = binary.LittleEndian.AppendUint32(b, 0x00000001) // NegotiateFlags: UNICODE
	b = append(b, make([]byte, 8)...)                   // ServerChallenge
	b = append(b, make([]byte, 8)...)                   // reserved
	b = append(b, make([]byte, 8)...)                   // TargetInfo (empty)
	return b
}

// TestAuthenticateMalformedNTLMChallenge drives a server that answers the NTLM
// negotiate with a malformed challenge, through Authenticate, which uses the
// go-ntlmssp Negotiator. The old pin panics; a fixed pin must return an error.
func TestAuthenticateMalformedNTLMChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "NTLM ") {
			w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(malformedNTLMChallenge()))
		} else {
			w.Header().Set("WWW-Authenticate", "NTLM")
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client, err := New(&cfg.IDPAccount{Provider: "PingNTLM", MFA: "Auto"})
	require.NoError(t, err)

	loginDetails := &creds.LoginDetails{Username: "DOMAIN\\testuser", Password: "testtestlol", URL: srv.URL}

	var authErr error
	require.NotPanics(t, func() {
		_, authErr = client.Authenticate(loginDetails)
	})
	require.Error(t, authErr)
}

const (
	ntlmTestDomain   = "DOMAIN"
	ntlmTestUser     = "testuser"
	ntlmTestPassword = "testtestlol"
	ntlmTestRealm    = "example.com"
	ntlmTestSAMLBody = "<samlp:Response/>"
	ntlmTestSAMLForm = `<html><body><form method="POST" action="https://signin.aws.amazon.com/saml"><input type="hidden" name="SAMLResponse" value="%s"/></form></body></html>`
)

// ntlmTestServerChallenge is the nonce the mock IdP issues in its CHALLENGE.
var ntlmTestServerChallenge = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

func utf16LE(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

func fromUTF16LE(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// appendVarField appends a security buffer descriptor: Len, MaxLen and BufferOffset.
func appendVarField(b []byte, length, offset int) []byte {
	b = binary.LittleEndian.AppendUint16(b, uint16(length))
	b = binary.LittleEndian.AppendUint16(b, uint16(length))
	return binary.LittleEndian.AppendUint32(b, uint32(offset))
}

// ntlmTestChallengeMessage builds a well-formed type-2 CHALLENGE as an NTLMv2 IdP
// sends it: a target name, the server nonce and a TargetInfo block naming the domain.
func ntlmTestChallengeMessage() []byte {
	const headerLen = 48
	const flags = 0x00880205 // UNICODE|REQUEST_TARGET|NTLM|NTLM2|TARGET_INFO

	target := utf16LE(ntlmTestDomain)
	info := binary.LittleEndian.AppendUint16(nil, 2) // MsvAvNbDomainName
	info = binary.LittleEndian.AppendUint16(info, uint16(len(target)))
	info = append(info, target...)
	info = append(info, 0, 0, 0, 0) // MsvAvEOL

	b := []byte("NTLMSSP\x00")
	b = binary.LittleEndian.AppendUint32(b, 2) // MessageType: CHALLENGE
	b = appendVarField(b, len(target), headerLen)
	b = binary.LittleEndian.AppendUint32(b, flags)
	b = append(b, ntlmTestServerChallenge[:]...)
	b = append(b, make([]byte, 8)...) // reserved
	b = appendVarField(b, len(info), headerLen+len(target))
	b = append(b, target...)
	return append(b, info...)
}

// parseNTLMTestAuthenticate reads the user, domain and NT response out of a
// type-3 AUTHENTICATE message. ok is false if a field points outside the message.
func parseNTLMTestAuthenticate(msg []byte) (user, domain string, ntResponse []byte, ok bool) {
	field := func(off int) ([]byte, bool) {
		if len(msg) < off+8 {
			return nil, false
		}
		l := int(binary.LittleEndian.Uint16(msg[off:]))
		o := int(binary.LittleEndian.Uint32(msg[off+4:]))
		if o+l > len(msg) {
			return nil, false
		}
		return msg[o : o+l], true
	}
	nt, ok1 := field(20)
	dom, ok2 := field(28)
	usr, ok3 := field(36)
	if !ok1 || !ok2 || !ok3 {
		return "", "", nil, false
	}
	return fromUTF16LE(usr), fromUTF16LE(dom), nt, true
}

// TestAuthenticateNTLMHandshake runs a full NTLMv2 handshake through Authenticate
// against a mock IdP, so the v0.1.1 path is exercised end to end. The IdP offers
// Basic and NTLM on its 401, which covers the v0.1.1 default of never sending Basic
// credentials unless AllowBasicAuth is set. It also checks that the domain typed
// in the username is the one that reaches the AUTHENTICATE message.
func TestAuthenticateNTLMHandshake(t *testing.T) {
	runNTLMHandshake(t, ntlmTestDomain+"\\"+ntlmTestUser, ntlmTestUser, ntlmTestDomain)
}

// TestAuthenticateNTLMHandshakeUPN covers a UPN login (user@realm). v0.1.1 splits
// on the backslash only, so the whole UPN goes out as the user with an empty domain.
func TestAuthenticateNTLMHandshakeUPN(t *testing.T) {
	upn := ntlmTestUser + "@" + ntlmTestRealm
	runNTLMHandshake(t, upn, upn, "")
}

// runNTLMHandshake drives the handshake for username and asserts the user and
// domain fields that reach the AUTHENTICATE message.
func runNTLMHandshake(t *testing.T, username, wantUser, wantDomain string) {
	var mu sync.Mutex
	var seen []string
	record := func(step string) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, step)
	}

	samlResponse := base64.StdEncoding.EncodeToString([]byte(ntlmTestSAMLBody))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/idp/startSSO.ping" {
			http.NotFound(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Basic ") {
			record("basic")
		}

		switch {
		case strings.HasPrefix(auth, "NTLM "):
			msg, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "NTLM "))
			if err != nil || len(msg) < 12 {
				t.Errorf("malformed NTLM token: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			switch msg[8] {
			case 1: // NEGOTIATE
				record("type1")
				w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(ntlmTestChallengeMessage()))
				w.WriteHeader(http.StatusUnauthorized)
			case 3: // AUTHENTICATE
				user, domain, nt, ok := parseNTLMTestAuthenticate(msg)
				// An NTLMv2 response is a 16-byte NTProofStr followed by a blob
				// that starts with RespType and HiRespType 0x01.
				if !ok || user != wantUser || domain != wantDomain || len(nt) < 18 || nt[16] != 1 || nt[17] != 1 {
					t.Errorf("unexpected AUTHENTICATE: user=%q domain=%q ntResponseLen=%d", user, domain, len(nt))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				record("type3")
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, ntlmTestSAMLForm, samlResponse)
			default:
				t.Errorf("unexpected NTLM message type %d", msg[8])
				w.WriteHeader(http.StatusBadRequest)
			}
		default:
			// Basic first, so a client that honours it would send the password in clear text.
			w.Header().Add("WWW-Authenticate", `Basic realm="idp"`)
			w.Header().Add("WWW-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	client, err := New(&cfg.IDPAccount{Provider: "PingNTLM", MFA: "Auto"})
	require.NoError(t, err)

	loginDetails := &creds.LoginDetails{Username: username, Password: ntlmTestPassword, URL: srv.URL}

	got, err := client.Authenticate(loginDetails)
	require.NoError(t, err)
	require.Equal(t, samlResponse, got)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"type1", "type3"}, seen)
}

func TestClient_follow(t *testing.T) {
	type fields struct {
		ValidateBase provider.ValidateBase
		client       *http.Client
		idpAccount   *cfg.IDPAccount
	}
	type args struct {
		ctx context.Context
		req *http.Request
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "invalid request",
			args: args{
				ctx: context.TODO(),
				req: &http.Request{},
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &Client{
				ValidateBase: tt.fields.ValidateBase,
				client:       tt.fields.client,
				idpAccount:   tt.fields.idpAccount,
			}
			got, err := ac.follow(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.follow() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Client.follow() = %v, want %v", got, tt.want)
			}
		})
	}
}

func samlFormHandler(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, ntlmTestSAMLForm, base64.StdEncoding.EncodeToString([]byte(ntlmTestSAMLBody)))
}

// TestAuthenticateHonoursSkipVerify checks that Authenticate keeps the TLS
// verification setting from the account instead of forcing InsecureSkipVerify.
func TestAuthenticateHonoursSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(samlFormHandler))
	defer srv.Close()

	loginDetails := &creds.LoginDetails{Username: "testuser", Password: "testtestlol", URL: srv.URL}

	t.Run("verification on rejects an untrusted certificate", func(t *testing.T) {
		client, err := New(&cfg.IDPAccount{Provider: "PingNTLM", MFA: "Auto", SkipVerify: false})
		require.NoError(t, err)
		_, err = client.Authenticate(loginDetails)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate")
	})

	t.Run("skip verify accepts an untrusted certificate", func(t *testing.T) {
		client, err := New(&cfg.IDPAccount{Provider: "PingNTLM", MFA: "Auto", SkipVerify: true})
		require.NoError(t, err)
		got, err := client.Authenticate(loginDetails)
		require.NoError(t, err)
		assert.Equal(t, base64.StdEncoding.EncodeToString([]byte(ntlmTestSAMLBody)), got)
	})
}

// authRecorder records the Basic credentials on each request handed to the
// NTLM negotiator, which uses them for the handshake with that host.
type authRecorder struct {
	mu   sync.Mutex
	next http.RoundTripper
	auth map[string]bool // path -> carried Basic auth
}

func (a *authRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	_, _, ok := req.BasicAuth()
	a.mu.Lock()
	a.auth[req.URL.Host+req.URL.Path] = ok
	a.mu.Unlock()
	return a.next.RoundTrip(req)
}

// TestAuthenticateBasicAuthOnlyToOriginalHost checks that Basic credentials are
// re-sent on a same-host redirect but not to a redirect target on another host.
func TestAuthenticateBasicAuthOnlyToOriginalHost(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(samlFormHandler))
	defer other.Close()

	var origin *httptest.Server
	origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/idp/startSSO.ping":
			http.Redirect(w, r, origin.URL+"/same", http.StatusFound)
		case "/same":
			http.Redirect(w, r, other.URL+"/elsewhere", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer origin.Close()

	client, err := New(&cfg.IDPAccount{Provider: "PingNTLM", MFA: "Auto"})
	require.NoError(t, err)
	rec := &authRecorder{next: client.client.Transport, auth: map[string]bool{}}
	client.client.Transport = rec

	_, err = client.Authenticate(&creds.LoginDetails{Username: "testuser", Password: "testtestlol", URL: origin.URL})
	require.NoError(t, err)

	originHost := strings.TrimPrefix(origin.URL, "http://")
	otherHost := strings.TrimPrefix(other.URL, "http://")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Equal(t, map[string]bool{
		originHost + "/idp/startSSO.ping": true,
		originHost + "/same":              true,
		otherHost + "/elsewhere":          false,
	}, rec.auth)
}

func TestBasicAuthRedirectPolicy(t *testing.T) {
	origin, _ := url.Parse("https://idp.example.com/idp/startSSO.ping")
	policy := basicAuthRedirectPolicy(origin, "u", "p")

	cases := []struct {
		target   string
		wantAuth bool
	}{
		{"https://idp.example.com/next", true},
		{"https://IDP.example.com/next", true},
		{"http://idp.example.com/next", false},
		{"https://evil.example.com/next", false},
		{"https://idp.example.com:8443/next", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", c.target, nil)
		req.SetBasicAuth("copied", "by-net-http")
		require.NoError(t, policy(req, nil))
		u, _, ok := req.BasicAuth()
		assert.Equal(t, c.wantAuth, ok, c.target)
		if ok {
			assert.Equal(t, "u", u, c.target)
		}
	}

	req := httptest.NewRequest("GET", "https://idp.example.com/next", nil)
	assert.Error(t, policy(req, make([]*http.Request, 10)))
}
