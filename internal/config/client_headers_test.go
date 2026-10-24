package config

import (
	"net/http"
	"testing"
)

func TestClientCredentialHeaders(t *testing.T) {
	token := "synthetic-client-token-123456"
	t.Setenv("HEADER_CLIENT_TOKEN", token)
	c := &Config{RegistryVersion: 2,
		Principals: map[string]Principal{"env": {ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
			TokenEnv: "HEADER_CLIENT_TOKEN"}}}
	for _, hashed := range []bool{false, true} {
		if hashed {
			c.Principals["env"] = Principal{ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
				TokenHash: TokenDigest(token)}
		}
		for _, headers := range []http.Header{
			{"Authorization": {"Bearer " + token}},
			{"authorization": {"Bearer " + token}},
			{"X-API-Key": {token}},
			{"x-api-key": {token}},
		} {
			if id, err := c.AuthenticateHeaders(headers); err != nil || id != "env" {
				t.Fatal("valid credential rejected", err)
			}
		}
		for _, headers := range []http.Header{
			nil, {}, {"Authorization": {}}, {"X-API-Key": {}},
			{"Authorization": {""}}, {"X-API-Key": {""}},
			{"Authorization": {"Bearer wrong"}}, {"X-API-Key": {"wrong"}},
			{"Authorization": {"Bearer " + token}, "X-API-Key": {token}},
			{"Authorization": {"Bearer wrong"}, "X-API-Key": {token}},
			{"Authorization": {""}, "X-API-Key": {token}},
			{"Authorization": {"Bearer " + token, "Bearer " + token}},
			{"X-API-Key": {token, token}},
			{"X-API-Key": {token}, "x-api-key": {token}},
			{"Authorization": {"Bearer " + token}, "authorization": {"Bearer " + token}},
			{"X-API-Key": {token + " "}}, {"X-API-Key": {token + "\n"}},
			{"X-API-Key": {token + "," + token}},
		} {
			if _, err := c.AuthenticateHeaders(headers); err == nil {
				t.Fatal("invalid or ambiguous credential accepted")
			}
		}
	}
}
