package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"mcp-gateway/internal/admin"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/store"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"mcp-gateway/internal/gateway"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if healthCheck() != nil {
			os.Exit(1)
		}
		return
	}
	if e := run(); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
func run() error {
	addr := os.Getenv("GATEWAY_LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	origin := os.Getenv("GATEWAY_PUBLIC_ORIGIN")
	if e := validateListen(addr, origin); e != nil {
		return e
	}
	path := os.Getenv("GATEWAY_CONFIG")
	if path == "" {
		path = "config/local.json"
	}
	registry, e := openRegistry()
	if e != nil {
		return e
	}
	if registry != nil {
		defer registry.Close()
	}
	if os.Getenv("GATEWAY_ADMIN_ADDR") != "" && registry == nil {
		return errors.New("admin requires sqlite or postgres storage")
	}
	var catalogs *catalog.Provider
	if raw := os.Getenv("GATEWAY_TOOL_SEARCH_ENABLED"); raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err != nil {
			return errors.New("GATEWAY_TOOL_SEARCH_ENABLED must be a boolean")
		}
		if enabled {
			catalogs = catalog.New()
			defer catalogs.Close()
		}
	}
	h, e := (&gateway.Gateway{Path: path, Store: registry, Catalog: catalogs, Timeout: 10 * time.Second, PublicOrigin: origin}).Handler()
	if e != nil {
		return e
	}
	listeners := []net.Listener{}
	servers := []*http.Server{}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	add := func(address string, handler http.Handler) error {
		l, e := net.Listen("tcp", address)
		if e != nil {
			return errors.New("cannot open listener")
		}
		listeners = append(listeners, l)
		servers = append(servers, &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second})
		return nil
	}
	if e = add(addr, h); e != nil {
		return e
	}
	if adminAddr := os.Getenv("GATEWAY_ADMIN_ADDR"); adminAddr != "" {
		adminOrigin := os.Getenv("GATEWAY_ADMIN_ORIGIN")
		if adminOrigin == "" {
			adminOrigin = "http://" + adminAddr
		}
		if e = validateAdminListen(adminAddr, adminOrigin); e != nil {
			return e
		}
		opts := adminOptions(adminOrigin)
		opts.Catalog = catalogs
		opts.MCPEndpoint = connectionEndpoint(addr, origin)
		a, e := admin.New(registry, opts)
		if e != nil {
			return e
		}
		if e = add(adminAddr, a); e != nil {
			return e
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, len(servers))
	for i, s := range servers {
		go func() { log.Print("gateway listening on ", listeners[i].Addr()); done <- s.Serve(listeners[i]) }()
	}
	select {
	case <-ctx.Done():
	case e = <-done:
	}
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(c)
	}
	if e == nil || errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return errors.New("HTTP server stopped unexpectedly")
}

func connectionEndpoint(addr, publicOrigin string) string {
	if endpoint := os.Getenv("GATEWAY_MCP_EXTERNAL_URL"); endpoint != "" {
		return endpoint
	}
	if publicOrigin == "" {
		return "http://" + addr + "/mcp"
	}
	return ""
}

func openRegistry() (store.Store, error) {
	kind := os.Getenv("GATEWAY_STORAGE")
	if kind == "" || kind == "file" {
		return nil, nil
	}
	location := os.Getenv("GATEWAY_DATABASE_URL")
	if kind == "sqlite" {
		location = os.Getenv("GATEWAY_SQLITE_PATH")
		if location == "" {
			location = "/var/lib/gateway/gateway.db"
		}
	}
	key, e := base64.StdEncoding.DecodeString(os.Getenv("GATEWAY_SECRET_KEY"))
	if e != nil || len(key) != 32 {
		return nil, errors.New("GATEWAY_SECRET_KEY requires base64-encoded 32 bytes")
	}
	return store.Open(kind, location, key)
}
func validateAdminListen(addr, origin string) error {
	u, e := url.Parse(origin)
	if e != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return errors.New("invalid admin origin")
	}
	host, port, e := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	p, pe := strconv.Atoi(port)
	if e != nil || ip == nil || pe != nil || p < 1 || p > 65535 {
		return errors.New("admin requires literal IP and port")
	}
	if u.Scheme == "https" {
		return gateway.ValidatePublicOrigin(origin)
	}
	if u.Scheme != "http" || !ip.IsLoopback() || u.Host != addr {
		return errors.New("non-loopback admin requires HTTPS origin")
	}
	return nil
}

func validateListen(addr, origin string) error {
	if e := gateway.ValidatePublicOrigin(origin); e != nil {
		return e
	}
	host, port, e := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	p, pe := strconv.Atoi(port)
	if e != nil || ip == nil || pe != nil || p < 1 || p > 65535 || (!ip.IsLoopback() && origin == "") {
		return errors.New("listen address requires a literal IP and port; non-loopback requires public HTTPS origin")
	}
	return nil
}

func adminOptions(origin string) admin.Options {
	list := func(name string) []string {
		if raw := os.Getenv(name); raw != "" {
			return strings.Split(raw, ",")
		}
		return nil
	}
	return admin.Options{Token: os.Getenv("GATEWAY_ADMIN_TOKEN"), Origin: origin, BasePath: os.Getenv("GATEWAY_ADMIN_BASE_PATH"), AuthMode: os.Getenv("GATEWAY_ADMIN_AUTH_MODE"), TrustedProxyCIDRs: list("GATEWAY_ADMIN_TRUSTED_PROXY_CIDRS"), AllowedUsers: list("GATEWAY_ADMIN_ALLOWED_USERS"), AllowedGroups: list("GATEWAY_ADMIN_ALLOWED_GROUPS")}
}
