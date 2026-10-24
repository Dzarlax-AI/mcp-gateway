package config

import "encoding/json"

// UpgradeAgentACLDocument is maintenance-only. Runtime Decode never calls it.
// The legacy input cannot contain any v2 fields or managed-key legacy grants.
func UpgradeAgentACLDocument(raw []byte) ([]byte, bool, error) {
	obj, err := DecodeObject(raw)
	if err != nil {
		return nil, false, err
	}
	if _, ok := obj["registry_version"]; ok {
		if _, err = Decode(raw); err != nil {
			return nil, false, err
		}
		return append([]byte(nil), raw...), false, nil
	}
	ps, ok := obj["principals"].(map[string]any)
	if !ok || len(ps) == 0 {
		return nil, false, ErrConfig
	}
	for _, value := range ps {
		p, ok := value.(map[string]any)
		if !ok {
			return nil, false, ErrConfig
		}
		for _, k := range []string{"access_policy", "tool_allowlist"} {
			if _, ok := p[k]; ok {
				return nil, false, ErrConfig
			}
		}
		if hash, ok := p["token_hash"].(string); ok && hash != "" {
			if gs, ok := p["grants"].(map[string]any); ok && len(gs) > 0 {
				return nil, false, ErrConfig
			}
		}
		p["access_policy"] = LegacyShared
		p["tool_allowlist"] = map[string]any{}
	}
	obj["registry_version"] = RegistryVersion
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, false, ErrConfig
	}
	if _, err = Decode(b); err != nil {
		return nil, false, err
	}
	return b, true, nil
}
