//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSudoAuthorize(t *testing.T) {
	dir := t.TempDir()
	zenity := filepath.Join(dir, "zenity")
	if err := os.WriteFile(zenity, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	sudo := filepath.Join(dir, "sudo")
	if err := os.WriteFile(sudo, []byte("#!/bin/sh\nprintf '%s' \"$SUDO_ASKPASS\" > \"$OUT\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	t.Setenv("PATH", dir)
	t.Setenv("OUT", out)
	t.Setenv("DISPLAY", ":0")
	if err := sudoAuthorize(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	askpass := strings.TrimSpace(string(b))
	script, err := os.ReadFile(askpass)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), strconv.Quote(zenity)+" --password") {
		t.Fatalf("askpass: %q", script)
	}
	st, err := os.Stat(askpass)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("права askpass: %v %v", st.Mode(), err)
	}
}

func TestSudoAuthorizeNoZenity(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("DISPLAY", ":0")
	if err := sudoAuthorize(); !errors.Is(err, errSystemAuth) {
		t.Fatalf("без zenity: %v", err)
	}
}
