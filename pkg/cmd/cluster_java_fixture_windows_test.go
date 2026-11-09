// Copyright (c) 2026 Oracle and/or its affiliates.
// Licensed under the Universal Permissive License v 1.0 as shown at
// https://oss.oracle.com/licenses/upl.

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const windowsJavaVersion17 = "17.0.21"
const windowsEndpointLaunchKey = "COHCTL_ENDPOINT_TEST_LAUNCH"

type windowsJavaFixture struct {
	Version   string
	RawOutput bool
	Query     bool
	Exit      int
	Sleep     bool
	Marker    string
	Cleanup   bool
}

// Native translations of the closed set of existing shell fixtures. Unknown
// scripts fail rather than silently losing assertions. No cmd.exe or shell.
func installWindowsJavaFixture(t *testing.T, script string) {
	t.Helper()
	writeWindowsJavaFixture(t, script, t.TempDir())
}

func writeWindowsJavaFixture(t *testing.T, script, dir string) {
	t.Helper()
	version17 := `echo 'openjdk version "17.0.21"' >&2`
	query17 := `if [ "$1" = "-version" ]; then echo 'openjdk version "17.0.21"' >&2; exit 0; fi` + "\n"
	modes := map[string]windowsJavaFixture{
		version17:                                {Version: windowsJavaVersion17},
		version17 + "; exit 1":                   {Version: windowsJavaVersion17, Exit: 1},
		`echo 'openjdk version "11.0.32.1"' >&2`: {Version: "11.0.32.1"},
		`echo unknown`:                           {Version: strings.TrimPrefix("echo unknown", "echo "), RawOutput: true},
		"exec /bin/sleep 30":                     {Sleep: true},
		query17 + "exec /bin/sleep 30":           {Version: windowsJavaVersion17, Query: true, Sleep: true},
		query17 + `echo launched > "$COHCTL_RESTART_MARKER"`:                                  {Version: windowsJavaVersion17, Query: true, Marker: "COHCTL_RESTART_MARKER"},
		query17 + `printf launched > "$COHCTL_STOP_TEST_LAUNCH"`:                              {Version: windowsJavaVersion17, Query: true, Marker: "COHCTL_STOP_TEST_LAUNCH"},
		query17 + `printf launched > "$COHCTL_ENDPOINT_TEST_LAUNCH"`:                          {Version: windowsJavaVersion17, Query: true, Marker: windowsEndpointLaunchKey},
		query17 + `printf launched > "$COHCTL_ENDPOINT_TEST_LAUNCH"` + "\nexec /bin/sleep 30": {Version: windowsJavaVersion17, Query: true, Marker: windowsEndpointLaunchKey, Sleep: true},
		query17 + `exec "$COHCTL_CLEANUP_EXE" -test.run=^TestManagementCleanupChild$`:         {Version: windowsJavaVersion17, Query: true, Cleanup: true},
	}
	mode, ok := modes[script]
	if !ok {
		t.Fatalf("no reviewed native Windows translation for fixture %q", script)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := directory.Close(); err != nil {
			t.Errorf("close private fixture directory: %v", err)
		}
	}()
	if err := directory.WriteFile("java.exe", data, 0600); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(mode)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("COHCTL_NATIVE_JAVA_FIXTURE", string(encoded))
	t.Setenv("PATH", dir)
}

func TestMain(m *testing.M) {
	name := filepath.Base(os.Args[0])
	if (!strings.EqualFold(name, "java") && !strings.EqualFold(name, "java.exe")) || os.Getenv("COHCTL_NATIVE_JAVA_FIXTURE") == "" {
		os.Exit(m.Run())
	}
	var mode windowsJavaFixture
	if err := json.Unmarshal([]byte(os.Getenv("COHCTL_NATIVE_JAVA_FIXTURE")), &mode); err != nil {
		panic(err)
	}
	query := len(os.Args) == 2 && os.Args[1] == "-version"
	if query || !mode.Query {
		if mode.RawOutput {
			fmt.Fprintln(os.Stderr, mode.Version)
		} else if mode.Version != "" {
			fmt.Fprintf(os.Stderr, "openjdk version %q\n", mode.Version)
		}
		if mode.Query || mode.Version != "" {
			os.Exit(mode.Exit)
		}
	}
	if mode.Marker != "" {
		switch mode.Marker {
		case "COHCTL_RESTART_MARKER", "COHCTL_STOP_TEST_LAUNCH", windowsEndpointLaunchKey:
			// Guarded native fixture; parent tests own these private marker paths.
			marker := os.Getenv(mode.Marker)
			name := filepath.Base(marker)
			if name != "launch" && name != "launched" {
				panic("invalid private fixture marker name")
			}
			directory, err := os.OpenRoot(filepath.Dir(marker))
			if err != nil {
				panic(err)
			}
			if err := directory.WriteFile(name, []byte("launched"), 0600); err != nil {
				_ = directory.Close()
				panic(err)
			}
			if err := directory.Close(); err != nil {
				panic(err)
			}
		default:
			panic("unrecognized native fixture marker")
		}
	}
	if mode.Cleanup {
		TestManagementCleanupChild(nil) // Same direct child, no wrapper/grandchild or second Wait.
	}
	if mode.Sleep {
		time.Sleep(30 * time.Second)
	}
	os.Exit(mode.Exit)
}

// Run the actual producers with PATH-resolved and absolute spellings. A wrong
// TestMain dispatch can enter only this bounded canary, never the whole suite.
func TestManagementWindowsJavaFixtureDispatch(t *testing.T) {
	if os.Getenv("COHCTL_JAVA_DISPATCH_CHILD") == "1" {
		t.Fatal("Java fixture entered the package test runner")
	}
	for _, absolute := range []bool{false, true} {
		for _, name := range []string{"java", "java.exe", "JaVa", "JaVa.ExE"} {
			for _, query := range []bool{false, true} {
				t.Run(fmt.Sprintf("%t/%s/query-%t", absolute, name, query), func(t *testing.T) {
					dir := t.TempDir()
					writeWindowsJavaFixture(t, `if [ "$1" = "-version" ]; then echo 'openjdk version "17.0.21"' >&2; exit 0; fi
printf launched > "$COHCTL_ENDPOINT_TEST_LAUNCH"`, dir)
					marker := filepath.Join(t.TempDir(), "launch")
					t.Setenv(windowsEndpointLaunchKey, marker)
					t.Setenv("COHCTL_JAVA_DISPATCH_CHILD", "1")
					command := name
					if absolute {
						command = filepath.Join(dir, name)
					}
					args := []string{"-test.run=^TestManagementWindowsJavaFixtureDispatch$"}
					if query {
						args = []string{"-version"}
					}
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					child := exec.CommandContext(ctx, command, args...)
					output, err := child.CombinedOutput() // Sole Wait owner.
					if err != nil || ctx.Err() != nil {
						t.Fatalf("fixture failed or required rescue: argv=%q path=%q error=%v context=%v output=%s", child.Args, child.Path, err, ctx.Err(), output)
					}
					if query {
						if string(output) != "openjdk version \"17.0.21\"\n" {
							t.Fatalf("unexpected version output: %q", output)
						}
						if _, err := os.Stat(marker); !os.IsNotExist(err) {
							t.Fatalf("version query entered launch branch: %v", err)
						}
					} else {
						body, err := os.ReadFile(marker)
						if err != nil || string(body) != "launched" || len(output) != 0 {
							t.Fatalf("launch branch: marker=%q error=%v output=%q", body, err, output)
						}
					}
					t.Logf("native producer argv=%q resolved=%q", child.Args, child.Path)
				})
			}
		}
	}
}
