package accessauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jwksBody(kid string, key *rsa.PublicKey) []byte {
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(bigIntBytes(key.E))
	b, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": n, "e": e, "public_cert": "ignored extension"}}})
	return b
}
func bigIntBytes(v int) []byte {
	if v == 0 {
		return []byte{0}
	}
	out := []byte{}
	for v > 0 {
		out = append([]byte{byte(v)}, out...)
		v >>= 8
	}
	return out
}

type testClaims struct {
	jwt.RegisteredClaims
	Type  string `json:"type"`
	Email string `json:"email"`
}

func sign(t *testing.T, key *rsa.PrivateKey, kid, issuer string, audiences []string, issued, expires time.Time, typ string) string {
	t.Helper()
	c := testClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Subject: "cf-subject", Audience: audiences, IssuedAt: jwt.NewNumericDate(issued), ExpiresAt: jwt.NewNumericDate(expires)}, Type: typ, Email: "alice@example.net"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["kid"] = kid
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func signMap(t *testing.T, method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	value, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestVerifyAccessAssertion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var fetches atomic.Int32
	body := jwksBody("key-a", &key.PublicKey)
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		fetches.Add(1)
		if r.URL.String() != "https://issuer.example.org/cdn-cgi/access/certs" {
			t.Errorf("unexpected JWKS URL: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), ContentLength: int64(len(body))}, nil
	}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	opts := Options{Issuer: "https://issuer.example.org", Audience: "mcp-audience", Users: map[string]string{"alice@example.net": "principal-a"}}
	v, err := NewForTesting(opts, "https://issuer.example.org/cdn-cgi/access/certs", client, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	valid := sign(t, key, "key-a", opts.Issuer, []string{"browser-aud", opts.Audience}, now.Add(-time.Minute), now.Add(time.Minute), "app")
	got, err := v.Verify(context.Background(), valid)
	if err != nil || got.Principal != "principal-a" || !got.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("valid multi-audience assertion rejected: %#v, %v", got, err)
	}
	cases := map[string]string{
		"wrong issuer":          sign(t, key, "key-a", "https://other.example.org", []string{opts.Audience}, now.Add(-time.Minute), now.Add(time.Minute), "app"),
		"browser audience only": sign(t, key, "key-a", opts.Issuer, []string{"browser-aud"}, now.Add(-time.Minute), now.Add(time.Minute), "app"),
		"wrong type":            sign(t, key, "key-a", opts.Issuer, []string{opts.Audience}, now.Add(-time.Minute), now.Add(time.Minute), "browser"),
		"expired":               sign(t, key, "key-a", opts.Issuer, []string{opts.Audience}, now.Add(-time.Minute), now.Add(-time.Minute), "app"),
		"future iat":            sign(t, key, "key-a", opts.Issuer, []string{opts.Audience}, now.Add(time.Minute), now.Add(2*time.Minute), "app"),
		"unknown identity":      sign(t, key, "key-a", opts.Issuer, []string{opts.Audience}, now.Add(-time.Minute), now.Add(time.Minute), "app"),
	}
	unknownClaims := jwt.MapClaims{"iss": opts.Issuer, "sub": "cf-subject", "aud": opts.Audience, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Minute).Unix(), "type": "app", "email": "alice@example.net"}
	withoutExp := jwt.MapClaims{}
	for k, v := range unknownClaims {
		if k != "exp" {
			withoutExp[k] = v
		}
	}
	withoutIat := jwt.MapClaims{}
	for k, v := range unknownClaims {
		if k != "iat" {
			withoutIat[k] = v
		}
	}
	withoutSub := jwt.MapClaims{}
	for k, v := range unknownClaims {
		if k != "sub" {
			withoutSub[k] = v
		}
	}
	withoutEmail := jwt.MapClaims{}
	for k, v := range unknownClaims {
		if k != "email" {
			withoutEmail[k] = v
		}
	}
	futureNbf := jwt.MapClaims{}
	for k, v := range unknownClaims {
		futureNbf[k] = v
	}
	futureNbf["nbf"] = now.Add(time.Minute).Unix()
	for name, claims := range map[string]jwt.MapClaims{"missing exp": withoutExp, "missing iat": withoutIat, "missing subject": withoutSub, "missing email": withoutEmail, "future nbf": futureNbf} {
		cases[name] = signMap(t, jwt.SigningMethodRS256, key, "key-a", claims)
	}
	cases["HS256"] = signMap(t, jwt.SigningMethodHS256, []byte("synthetic signing key"), "key-a", unknownClaims)
	cases["none"] = signMap(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, "key-a", unknownClaims)
	unknownIdentityClaims := jwt.MapClaims{}
	for k, v := range unknownClaims {
		unknownIdentityClaims[k] = v
	}
	unknownIdentityClaims["email"] = "nobody@example.net"
	cases["unknown identity"] = signMap(t, jwt.SigningMethodRS256, key, "key-a", unknownIdentityClaims)
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), token); err == nil {
				t.Fatal("invalid assertion accepted")
			}
		})
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), sign(t, other, "key-a", opts.Issuer, []string{opts.Audience}, now.Add(-time.Minute), now.Add(time.Minute), "app")); err == nil {
		t.Fatal("wrong signature accepted")
	}
	unknown := sign(t, key, "unknown-kid", opts.Issuer, []string{opts.Audience}, now.Add(-time.Minute), now.Add(time.Minute), "app")
	for i := 0; i < 4; i++ {
		if _, err := v.Verify(context.Background(), unknown); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("unknown kid caused JWKS refetch storm: %d fetches", got)
	}
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body = jwksBody("rotated-key", &rotated.PublicKey)
	now = now.Add(11 * time.Second)
	rotationToken := sign(t, rotated, "rotated-key", opts.Issuer, []string{opts.Audience}, now.Add(-time.Minute), now.Add(time.Minute), "app")
	if _, err := v.Verify(context.Background(), rotationToken); err != nil {
		t.Fatalf("key rotation did not refresh after cooldown: %v", err)
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("rotation JWKS fetch count = %d, want 2", got)
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	for _, opts := range []Options{
		{Issuer: "http://issuer.example.org", Audience: "aud", Users: map[string]string{"a@example.net": "p"}},
		{Issuer: "https://issuer.example.org/path", Audience: "aud", Users: map[string]string{"a@example.net": "p"}},
		{Issuer: "https://issuer.example.org", Audience: "", Users: map[string]string{"a@example.net": "p"}},
		{Issuer: "https://issuer.example.org", Audience: "aud", Users: map[string]string{}},
	} {
		if _, err := New(opts); err == nil {
			t.Fatalf("invalid options accepted: %#v", opts)
		}
	}
}
