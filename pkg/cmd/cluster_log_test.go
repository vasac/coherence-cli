/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * https://oss.oracle.com/licenses/upl.
 */

package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogFileRejectsTraversal(t *testing.T) {
	previous := logsDirectory
	logsDirectory = t.TempDir()
	t.Cleanup(func() { logsDirectory = previous })
	for _, name := range []string{"", ".", "..", "../outside", "a/b", `a\b`, "/absolute"} {
		for _, components := range [][2]string{{name, "member"}, {"cluster", name}} {
			if path, err := getLogFile(components[0], components[1]); err == nil || path != "" {
				t.Fatalf("unsafe components %q: path=%q error=%v", components, path, err)
			}
		}
	}
	entries, err := os.ReadDir(logsDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejected names must not create directories: entries=%v error=%v", entries, err)
	}
	path, err := getLogFile("local-cluster", "storage-0")
	if want := filepath.Join(logsDirectory, "local-cluster", "storage-0.log"); err != nil || path != want {
		t.Fatalf("valid log path=%q error=%v, want %q", path, err, want)
	}
}
