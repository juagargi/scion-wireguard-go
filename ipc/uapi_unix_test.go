//go:build linux || darwin || freebsd || openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"net"
	"path/filepath"
	"testing"
)

func TestSocketDirDefault(t *testing.T) {
	t.Setenv(EnvUAPIDir, "")
	if got := sockPath("wg0"); got != socketDirectory+"/wg0.sock" {
		t.Errorf("sockPath = %q", got)
	}
}

func TestUAPIOpenInEnvDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "uapi") // created by UAPIOpen
	t.Setenv(EnvUAPIDir, dir)
	f, err := UAPIOpen("wgx-test")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	path := filepath.Join(dir, "wgx-test.sock")
	if got := sockPath("wgx-test"); got != path {
		t.Errorf("sockPath = %q, want %q", got, path)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("no socket at %s: %v", path, err)
	}
	conn.Close()
}
