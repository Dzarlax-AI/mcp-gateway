package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"mcp-gateway/internal/store"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var errRotationInput = errors.New("rotation input unavailable or invalid")

func readPrivate(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errRotationInput
	}
	parent, e := os.Lstat(filepath.Dir(path))
	if e != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return nil, errRotationInput
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, errRotationInput
	}
	f := os.NewFile(uintptr(fd), "private input")
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > limit {
		return nil, errRotationInput
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errRotationInput
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errRotationInput
	}
	return b, nil
}
func readKey(path string) ([]byte, error) {
	b, e := readPrivate(path, 128)
	if e != nil {
		return nil, e
	}
	defer clear(b)
	k, e := base64.StdEncoding.DecodeString(string(b))
	if e != nil || len(k) != 32 {
		return nil, errRotationInput
	}
	return k, nil
}
func runRotation(args []string) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("rotation failed; inspect state before recovery")
		}
	}()
	fs := flag.NewFlagSet("rotate-secret-key", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	kind := fs.String("storage", "", "explicit sqlite or postgres")
	location := fs.String("database-url-file", "", "private database location file")
	oldPath := fs.String("old-key-file", "", "private old key file")
	newPath := fs.String("new-key-file", "", "private new key file")
	passwordPath := fs.String("new-password-file", "", "optional private new password file")
	role := fs.String("role", "", "optional exact DB role")
	revision := fs.Int64("expected-revision", 0, "required CAS revision")
	verify := fs.Bool("verify-only", false, "validate without writes")
	if fs.Parse(args) != nil || fs.NArg() != 0 || (*kind != "sqlite" && *kind != "postgres") || *revision < 1 {
		return errRotationInput
	}
	old, e := readKey(*oldPath)
	if e != nil {
		return e
	}
	defer clear(old)
	next, e := readKey(*newPath)
	if e != nil {
		return e
	}
	defer clear(next)
	if bytes.Equal(old, next) {
		return errRotationInput
	}
	loc, e := readPrivate(*location, 8192)
	if e != nil {
		return e
	}
	defer clear(loc)
	var password []byte
	if *passwordPath != "" {
		password, e = readPrivate(*passwordPath, 256)
		if e != nil {
			return e
		}
		defer clear(password)
	}
	raw, e := store.Open(*kind, string(loc), old)
	if e != nil {
		return errors.New("rotation storage unavailable")
	}
	defer raw.Close()
	db, ok := raw.(*store.DB)
	if !ok {
		return errRotationInput
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, e := db.RotateSecretKey(ctx, store.RotationOptions{ExpectedRevision: *revision, NewKey: next, VerifyOnly: *verify, Role: *role, Password: password})
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}

// Recovery envelopes protect historical material independently of the exposed old key.
func runRecovery(args []string) (err error) {
	defer func() {
		if recover() != nil {
			err = errRotationInput
		}
	}()
	fs := flag.NewFlagSet("seal-recovery", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	keyPath := fs.String("key-file", "", "private independent key")
	input := fs.String("input-file", "", "private archive")
	output := fs.String("output-file", "", "new private envelope")
	open := fs.Bool("open", false, "verify/restore envelope to a new private file")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errRotationInput
	}
	key, e := readKey(*keyPath)
	if e != nil {
		return e
	}
	defer clear(key)
	b, e := readPrivate(*input, 256<<20)
	if e != nil {
		return e
	}
	defer clear(b)
	block, e := aes.NewCipher(key)
	if e != nil {
		return errRotationInput
	}
	ae, e := cipher.NewGCM(block)
	if e != nil {
		return errRotationInput
	}
	aad := []byte("mcp-gateway-recovery-v1")
	var result []byte
	if *open {
		if len(b) < ae.NonceSize()+ae.Overhead() {
			return errRotationInput
		}
		result, e = ae.Open(nil, b[:ae.NonceSize()], b[ae.NonceSize():], aad)
		if e != nil {
			return errRotationInput
		}
	} else {
		nonce := make([]byte, ae.NonceSize())
		if _, e = rand.Read(nonce); e != nil {
			return errRotationInput
		}
		result = ae.Seal(nonce, nonce, b, aad)
	}
	defer clear(result)
	// Validate the output directory, refuse existing files and fsync before reporting success.
	st, e := os.Lstat(filepath.Dir(*output))
	if e != nil || !filepath.IsAbs(*output) || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errRotationInput
	}
	f, e := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errRotationInput
	}
	good := false
	defer func() {
		f.Close()
		if !good {
			os.Remove(*output)
		}
	}()
	if _, e = f.Write(result); e != nil {
		return errRotationInput
	}
	if f.Sync() != nil {
		return errRotationInput
	}
	if f.Close() != nil {
		return errRotationInput
	}
	directory, e := os.Open(filepath.Dir(*output))
	if e != nil {
		return errRotationInput
	}
	e = directory.Sync()
	directory.Close()
	if e != nil {
		return errRotationInput
	}
	good = true
	return nil
}
