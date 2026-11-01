// Package accessauth verifies Cloudflare Access application assertions for the
// gateway's independently configured admin and Managed OAuth routes.
package accessauth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	maxJWKSBytes = 1 << 20
	maxKeys      = 32
	cacheTTL     = 5 * time.Minute
)

var ErrDenied = errors.New("access assertion denied")

type Options struct {
	Issuer   string
	Audience string
	Users    map[string]string // exact email -> existing gateway principal ID
}

type Identity struct {
	Principal string
	Subject   string
	Email     string
	ExpiresAt time.Time
}

type Verifier struct {
	issuer, audience, jwksURL string
	users                     map[string]string
	client                    *http.Client
	now                       func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	loaded    time.Time
	lastFetch time.Time
	fetching  chan struct{}
}

func New(opts Options) (*Verifier, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	return newWithJWKS(opts, strings.TrimSuffix(opts.Issuer, "/")+"/cdn-cgi/access/certs", &http.Client{
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{Proxy: nil, ResponseHeaderTimeout: 2 * time.Second, TLSHandshakeTimeout: 2 * time.Second},
	})
}

// NewForTesting permits a local HTTPS test server while retaining all JWT
// validation. It is intentionally not exposed through environment settings.
func NewForTesting(opts Options, jwksURL string, client *http.Client, now func() time.Time) (*Verifier, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	u, err := url.Parse(jwksURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrDenied
	}
	if client == nil {
		return nil, ErrDenied
	}
	if client.CheckRedirect == nil {
		return nil, errors.New("test client must reject redirects")
	}
	v, err := newWithJWKS(opts, jwksURL, client)
	if err == nil && now != nil {
		v.now = now
	}
	return v, err
}

func newWithJWKS(opts Options, endpoint string, client *http.Client) (*Verifier, error) {
	copyUsers := make(map[string]string, len(opts.Users))
	for email, principal := range opts.Users {
		copyUsers[email] = principal
	}
	return &Verifier{issuer: opts.Issuer, audience: opts.Audience, jwksURL: endpoint, users: copyUsers, client: client, now: time.Now, keys: map[string]*rsa.PublicKey{}}, nil
}

func (v *Verifier) PrincipalIDs() []string {
	ids := make([]string, 0, len(v.users))
	for _, id := range v.users {
		ids = append(ids, id)
	}
	return ids
}

func validateOptions(o Options) error {
	u, err := url.Parse(o.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || o.Issuer != "https://"+u.Host || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.HasSuffix(o.Issuer, "/") || o.Audience == "" || strings.TrimSpace(o.Audience) != o.Audience || len(o.Audience) > 512 || len(o.Users) == 0 {
		return ErrDenied
	}
	for email, principal := range o.Users {
		if email == "" || strings.TrimSpace(email) != email || strings.ContainsAny(email, "\r\n\x00") || principal == "" || strings.TrimSpace(principal) != principal || len(principal) > 128 {
			return ErrDenied
		}
	}
	return nil
}

type claims struct {
	jwt.RegisteredClaims
	Type  string `json:"type"`
	Email string `json:"email"`
}

func (v *Verifier) Verify(ctx context.Context, assertion string) (Identity, error) {
	if len(assertion) < 20 || len(assertion) > 16<<10 || strings.ContainsAny(assertion, " \t\r\n") {
		return Identity{}, ErrDenied
	}
	var parsed *jwt.Token
	var c claims
	keyfunc := func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodRS256 {
			return nil, ErrDenied
		}
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" || len(kid) > 256 {
			return nil, ErrDenied
		}
		key, err := v.key(ctx, kid)
		if err != nil {
			return nil, ErrDenied
		}
		return key, nil
	}
	var err error
	parsed, err = jwt.ParseWithClaims(assertion, &c, keyfunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(v.issuer), jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(),
		jwt.WithTimeFunc(v.now),
	)
	if err != nil || parsed == nil || !parsed.Valid || c.Type != "app" || c.Subject == "" || c.Email == "" || c.ExpiresAt == nil || c.IssuedAt == nil {
		return Identity{}, ErrDenied
	}
	principal, ok := v.users[c.Email]
	if !ok || principal == "" {
		return Identity{}, ErrDenied
	}
	return Identity{Principal: principal, Subject: c.Subject, Email: c.Email, ExpiresAt: c.ExpiresAt.Time}, nil
}

func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	for {
		v.mu.Lock()
		if v.now().Before(v.loaded) && v.keys[kid] != nil {
			k := v.keys[kid]
			v.mu.Unlock()
			return k, nil
		}
		if v.fetching != nil {
			done := v.fetching
			v.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ErrDenied
			}
		}
		if !v.lastFetch.IsZero() && v.now().Sub(v.lastFetch) < 10*time.Second {
			v.mu.Unlock()
			return nil, ErrDenied
		}
		v.lastFetch = v.now()
		v.fetching = make(chan struct{})
		done := v.fetching
		v.mu.Unlock()
		keys, err := v.fetch(ctx)
		v.mu.Lock()
		if err == nil {
			v.keys, v.loaded = keys, v.now().Add(cacheTTL)
		}
		close(done)
		v.fetching = nil
		k := v.keys[kid]
		v.mu.Unlock()
		if err != nil || k == nil {
			return nil, ErrDenied
		}
		return k, nil
	}
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, ErrDenied
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, ErrDenied
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > maxJWKSBytes {
		return nil, ErrDenied
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err == nil && len(b) > maxJWKSBytes {
		err = ErrDenied
	}
	if err != nil {
		return nil, ErrDenied
	}
	var doc struct {
		Keys []struct{ Kty, Kid, Use, Alg, N, E string } `json:"keys"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if dec.Decode(&doc) != nil || dec.Decode(new(any)) != io.EOF || len(doc.Keys) == 0 || len(doc.Keys) > maxKeys {
		return nil, ErrDenied
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") || k.Kid == "" || len(k.Kid) > 256 || keys[k.Kid] != nil {
			return nil, ErrDenied
		}
		n, e1 := base64.RawURLEncoding.DecodeString(k.N)
		e, e2 := base64.RawURLEncoding.DecodeString(k.E)
		if e1 != nil || e2 != nil || len(n) < 256 || len(n) > 1024 || len(e) > 4 {
			return nil, ErrDenied
		}
		exp := new(big.Int).SetBytes(e)
		if !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > 1<<31-1 {
			return nil, ErrDenied
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}
		if pub.N.BitLen() < 2048 {
			return nil, ErrDenied
		}
		if _, err := x509.MarshalPKIXPublicKey(pub); err != nil {
			return nil, ErrDenied
		}
		keys[k.Kid] = pub
	}
	return keys, nil
}
