package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func healthCheck() error {
	addr := os.Getenv("GATEWAY_LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	host, port, err := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil {
		return errors.New("invalid healthcheck address")
	}
	if ip.IsUnspecified() {
		host = "127.0.0.1"
		if ip.To4() == nil {
			host = "::1"
		}
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	res, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return errors.New("healthcheck failed")
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 4))
	if err != nil || res.StatusCode != 200 || string(b) != "ok\n" {
		return errors.New("healthcheck failed")
	}
	return nil
}
