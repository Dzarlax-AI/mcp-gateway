// Package policy applies explicit server, tool and argument authorization.
package policy

import (
	"encoding/json"
	"errors"
	"math/big"
	"reflect"

	"mcp-gateway/internal/config"
)

var ErrDenied = errors.New("access denied")

func Grant(c *config.Config, p, s, t string) (config.Grant, error) {
	if _, ok := c.Principals[p]; !ok {
		return config.Grant{}, ErrDenied
	}
	srv, ok := c.Servers[s]
	if !ok || !srv.Enabled || !srv.Tools[t].Enabled {
		return config.Grant{}, ErrDenied
	}
	if srv.Tools[t].AccessMode == "shared" {
		return config.Grant{SchemaOnly: true}, nil
	}
	g, ok := c.Principals[p].Grants[s][t]
	if !ok {
		return g, ErrDenied
	}
	return g, nil
}
func Visible(c *config.Config, p, s string) bool {
	for t := range c.Servers[s].Tools {
		if _, e := Grant(c, p, s, t); e == nil {
			return true
		}
	}
	return false
}
func Arguments(g config.Grant, a map[string]any) error {
	if a == nil {
		return ErrDenied
	}
	if g.SchemaOnly {
		return nil
	}
	allowed := map[string]bool{}
	for _, k := range g.AllowedArguments {
		allowed[k] = true
	}
	for k := range a {
		if !allowed[k] {
			return ErrDenied
		}
	}
	for _, k := range g.RequiredArguments {
		if _, ok := a[k]; !ok {
			return ErrDenied
		}
	}
	for k, v := range g.ArgumentEquals {
		x, ok := a[k]
		if !ok || !equal(x, v) {
			return ErrDenied
		}
	}
	return nil
}
func equal(a, b any) bool {
	switch x := a.(type) {
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		r, ok := new(big.Rat).SetString(string(x))
		q, ok2 := new(big.Rat).SetString(string(y))
		return ok && ok2 && r.Cmp(q) == 0
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !equal(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equal(x[i], y[i]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}
