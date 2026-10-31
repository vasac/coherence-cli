//go:build linux || darwin

/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * https://oss.oracle.com/licenses/upl.
 */

package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestClassifyMonitoringBundleFIFO(t *testing.T) {
	for _, name := range []string{generatedDockerComposeYAML, monitoringEnvFile, grafanaPasswordFile} {
		t.Run(name, func(t *testing.T) {
			directory := monitoringValidationFixture(t)
			if err := syscall.Mkfifo(filepath.Join(directory, name), 0600); err != nil {
				if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOSYS) {
					t.Skipf("FIFO creation unavailable: %v", err)
				}
				t.Fatal(err)
			}
			mode, err := classifyMonitoringBundle(directory)
			if mode != monitoringBundleInvalid {
				t.Errorf("expected invalid mode, got %v", mode)
			}
			assertInvalidMonitoringArtifact(t, err, name)
		})
	}
}

func TestClassifyMonitoringBundleInspectionFailure(t *testing.T) {
	// ENOTDIR remains an inspection failure even when running as root.
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0600); err != nil {
		t.Fatal(err)
	}
	mode, err := classifyMonitoringBundle(blocked)
	var pathError *os.PathError
	if mode != monitoringBundleInvalid || !errors.Is(err, syscall.ENOTDIR) || !errors.As(err, &pathError) {
		t.Fatalf("expected wrapped inspection failure, got mode=%v error=%v", mode, err)
	}
}
