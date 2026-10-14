package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestRotationPrivateInputsAndSafeErrors(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	path := filepath.Join(root, "key")
	if e := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := readKey(path); e != nil {
		t.Fatal("valid private key", e)
	}
	alias := filepath.Join(root, "alias")
	os.Symlink(path, alias)
	if _, e := readKey(alias); e == nil {
		t.Fatal("symlink allowed")
	}
	os.Chmod(path, 0644)
	if _, e := readKey(path); e == nil {
		t.Fatal("world readable key allowed")
	}
	os.Chmod(path, 0600)
	marker := "synthetic-sensitive-argument"
	for _, args := range [][]string{{"--unexpected", marker}, {"--storage", "postgres", "--expected-revision", "1", "--old-key-file", "/" + marker}, {"--storage", marker}} {
		e := runRotation(args)
		if e == nil || bytes.Contains([]byte(e.Error()), []byte(marker)) {
			t.Fatal("unsafe operator error")
		}
	}
}
func TestRecoveryEnvelopeAndCorruption(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	input := filepath.Join(root, "archive")
	key := filepath.Join(root, "recovery.key")
	sealed := filepath.Join(root, "sealed")
	output := filepath.Join(root, "restored")
	plain := []byte("synthetic-old-key-password-and-database-dump")
	os.WriteFile(input, plain, 0600)
	os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))), 0600)
	args := []string{"--key-file", key, "--input-file", input, "--output-file", sealed}
	if e := runRecovery(args); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(sealed)
	if bytes.Contains(b, plain) {
		t.Fatal("archive plaintext")
	}
	if e := runRecovery([]string{"--open", "--key-file", key, "--input-file", sealed, "--output-file", output}); e != nil {
		t.Fatal(e)
	}
	restored, _ := os.ReadFile(output)
	if !bytes.Equal(restored, plain) {
		t.Fatal("archive lost")
	}
	if e := runRecovery(args); e == nil {
		t.Fatal("existing recovery overwritten")
	}
	b[len(b)-1] ^= 1
	os.WriteFile(sealed, b, 0600)
	target := filepath.Join(root, "bad-output")
	if e := runRecovery([]string{"--open", "--key-file", key, "--input-file", sealed, "--output-file", target}); e == nil {
		t.Fatal("corrupt archive accepted")
	}
	if _, e := os.Stat(target); !os.IsNotExist(e) {
		t.Fatal("partial recovery output")
	}
}
