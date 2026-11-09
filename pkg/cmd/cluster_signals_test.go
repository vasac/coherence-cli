/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * https://oss.oracle.com/licenses/upl.
 */

package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type managedCancelWriter struct {
	cancel context.CancelFunc
	text   string
}

func (w managedCancelWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.text) {
		w.cancel()
	}
	return len(p), nil
}

type managedCancelReader struct {
	cancel context.CancelFunc
	reader *strings.Reader
}

func (r managedCancelReader) Read(p []byte) (int, error) { r.cancel(); return r.reader.Read(p) }

func assertManagedChildAlive(t *testing.T, p *managedProcess) {
	t.Helper()
	select {
	case <-p.done:
		t.Fatalf("pre-existing/accepted PID %d was stopped", p.command.Process.Pid)
	default:
	}
}

func TestManagementCancellationBeforeSideEffects(t *testing.T) {
	for _, operation := range []string{stopClusterCommand, restartClusterCommand, startClusterCommand, scaleClusterCommand} {
		t.Run(operation, func(t *testing.T) {
			managedTestState(t)
			child := stopTestChild(t)
			connection := stopTestConnection(t, []int{child.command.Process.Pid}, nil)
			before, _ := os.ReadFile(viper.ConfigFileUsed())
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			cmd := managementTestCommand(t)
			cmd.SetContext(ctx)
			if err := runClusterOperation(cmd, connection.Name, operation); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			assertManagedChildAlive(t, child)
			after, _ := os.ReadFile(viper.ConfigFileUsed())
			if !bytes.Equal(before, after) || !reflect.DeepEqual(connection, Config.Clusters[0]) {
				t.Fatal("cancel changed config")
			}
		})
	}
}

func TestManagementCancellationAtStopBoundary(t *testing.T) {
	for _, operation := range []string{stopClusterCommand, restartClusterCommand} {
		t.Run(operation, func(t *testing.T) {
			managedTestState(t)
			if operation == restartClusterCommand {
				fakeJava(t, `echo 'openjdk version "17.0.21"' >&2`)
			}
			child := stopTestChild(t)
			connection := stopTestConnection(t, []int{child.command.Process.Pid}, nil)
			before, _ := os.ReadFile(viper.ConfigFileUsed())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cmd := managementTestCommand(t)
			cmd.SetContext(ctx)
			cmd.SetIn(managedCancelReader{cancel, strings.NewReader("y\n")})
			if err := runClusterOperation(cmd, connection.Name, operation); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			assertManagedChildAlive(t, child)
			if cmd.Context() != ctx {
				t.Fatal("caller context not restored")
			}
			after, _ := os.ReadFile(viper.ConfigFileUsed())
			if !bytes.Equal(before, after) || !reflect.DeepEqual(connection, Config.Clusters[0]) {
				t.Fatal("cancel at stop changed config")
			}
		})
	}
}

func TestManagementCancellationBeforeEachLaunch(t *testing.T) {
	for _, at := range []string{"before-first", "before-second"} {
		t.Run(at, func(t *testing.T) {
			managedTestState(t)
			old := stopTestChild(t)
			fakeJava(t, "exec /bin/sleep 30")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cmd := managementTestCommand(t)
			cmd.SetContext(ctx)
			if at == "before-first" {
				cancel()
			} else {
				cmd.SetOut(managedCancelWriter{cancel, "Starting cluster member storage-2"})
			}
			conn := ClusterConnection{Name: "scale-cancel", ManagementPort: 30000, ClusterVersion: defaultCoherenceVersion}
			children, err := startCluster(cmd, conn, 2, 1, ClusterManagement{RESTAddress: localHost})
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			want := 0
			if at == "before-second" {
				want = 1
			}
			if len(children) != want {
				t.Fatalf("launched %d, want %d", len(children), want)
			}
			for _, p := range children {
				waitStopTestChild(t, p)
			}
			assertManagedChildAlive(t, old)
		})
	}
}

func TestManagementRestartCancellationFinishesStopPass(t *testing.T) {
	managedTestState(t)
	stopTestSeams(t)
	fakeJava(t, `echo 'openjdk version "17.0.21"' >&2`)
	children := []*managedProcess{stopTestChild(t), stopTestChild(t), stopTestChild(t)}
	var pids []int
	for _, p := range children {
		pids = append(pids, p.command.Process.Pid)
	}
	conn := stopTestConnection(t, pids, nil)
	before, _ := os.ReadFile(viper.ConfigFileUsed())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts, writes, readiness := 0, 0, 0
	killProcessForStop = func(p *os.Process) error { attempts++; cancel(); return p.Kill() }
	writeManagedConfig = func() error { writes++; return nil }
	awaitManagedStartup = func(_ *cobra.Command, _ ClusterConnection, _ []*managedProcess) error { readiness++; return nil }
	automaticallyConfirm = true
	cmd := managementTestCommand(t)
	cmd.SetContext(ctx)
	err := runClusterOperation(cmd, conn.Name, restartClusterCommand)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "cannot be restored automatically") {
		t.Fatal(err)
	}
	if attempts != 3 || writes != 0 || readiness != 0 {
		t.Fatalf("attempts=%d writes=%d readiness=%d", attempts, writes, readiness)
	}
	for _, p := range children {
		waitStopTestChild(t, p)
	}
	after, _ := os.ReadFile(viper.ConfigFileUsed())
	if !bytes.Equal(before, after) || !reflect.DeepEqual(conn, Config.Clusters[0]) {
		t.Fatal("cancel changed config")
	}
}

func TestManagementCancellationCompletionBoundary(t *testing.T) {
	for _, at := range []string{managementTestReadiness, managementTestBeforeWrite, managementTestDuringWrite, "scale-success"} {
		t.Run(at, func(t *testing.T) {
			managedTestState(t)
			fakeJava(t, "exec /bin/sleep 30")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cmd := managementTestCommand(t)
			cmd.SetContext(ctx)
			restore := managedOperationSignals(cmd)
			defer restore()
			conn := ClusterConnection{Name: "complete", ClusterName: "complete", ManuallyCreated: true, ManagementPort: 30000, ClusterVersion: defaultCoherenceVersion}
			Config.Clusters = []ClusterConnection{conn}
			viper.Set(clusterKey, Config.Clusters)
			viper.SetConfigFile(filepath.Join(t.TempDir(), "cohctl.yaml"))
			if err := writeManagedConfigAtomically(); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(viper.ConfigFileUsed())
			awaitManagedStartup = func(_ *cobra.Command, _ ClusterConnection, _ []*managedProcess) error {
				if at == managementTestReadiness {
					cancel()
				}
				return nil
			}
			children, err := startCluster(cmd, conn, 1, 0, ClusterManagement{RESTAddress: localHost})
			t.Cleanup(func() {
				if err := cleanupManagedProcesses(children); err != nil {
					t.Errorf("completion fixture cleanup: %v", err)
				}
			})
			if at == managementTestReadiness {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				waitStopTestChild(t, children[0])
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			writes := 0
			writeManagedConfig = func() error {
				writes++
				if at == managementTestDuringWrite {
					cancel()
				}
				return writeManagedConfigAtomically()
			}
			if at == managementTestBeforeWrite {
				cancel()
			}
			updated := managedConnection(conn, ClusterManagement{RESTAddress: localHost})
			err = completeManagedStartup(cmd, updated, children, false, at != "scale-success")
			restore()
			if cmd.Context() != ctx {
				t.Fatal("caller context not restored")
			}
			if at == managementTestBeforeWrite {
				if !errors.Is(err, context.Canceled) || writes != 0 {
					t.Fatalf("err=%v writes=%d", err, writes)
				}
				waitStopTestChild(t, children[0])
				after, _ := os.ReadFile(viper.ConfigFileUsed())
				if !bytes.Equal(before, after) {
					t.Fatal("cancel changed bytes")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				assertManagedChildAlive(t, children[0])
				if at == managementTestDuringWrite && !reflect.DeepEqual(updated, Config.Clusters[0]) {
					t.Fatal("accepted write did not persist")
				}
			}
		})
	}
}

// Cancellation during the successor process-exit barrier must retain the old
// configuration and return promptly without another REST request or launch.
func TestManagementRestartCancellationDuringShutdownBarrier(t *testing.T) {
	managedTestState(t)
	stopTestSeams(t)
	restartTestSeams(t)
	fakeJava(t, `echo 'openjdk version "17.0.21"' >&2`)
	child := stopTestChild(t)
	conn := stopTestConnection(t, []int{child.command.Process.Pid}, nil)
	before, _ := os.ReadFile(viper.ConfigFileUsed())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := 0
	var canceledAt time.Time
	observeProcessForRestart = func(*os.Process) (processExitObserver, error) {
		return &restartTestObserver{check: func() (bool, error) {
			if canceledAt.IsZero() {
				canceledAt = time.Now()
			}
			cancel()
			return false, nil
		}, closed: &closed}, nil
	}
	attempts, writes, readiness := 0, 0, 0
	killProcessForStop = func(*os.Process) error { attempts++; return nil } // modeled delayed exit
	writeManagedConfig = func() error { writes++; return nil }
	awaitManagedStartup = func(*cobra.Command, ClusterConnection, []*managedProcess) error { readiness++; return nil }
	automaticallyConfirm = true
	cmd := managementTestCommand(t)
	cmd.SetContext(ctx)
	started := time.Now()
	err := runClusterOperation(cmd, conn.Name, restartClusterCommand)
	// Measure prompt return from the actual injected cancellation. Native Java
	// preflight runs before that event and must not consume this assertion's budget.
	elapsed := time.Since(canceledAt)
	if canceledAt.IsZero() || !errors.Is(err, context.Canceled) || elapsed > time.Second || closed != 1 || attempts != 1 || writes != 0 || readiness != 0 {
		t.Fatalf("err=%v after-cancel=%s total=%s closed=%d attempts=%d writes=%d readiness=%d", err, elapsed, time.Since(started), closed, attempts, writes, readiness)
	}
	assertManagedChildAlive(t, child)
	after, _ := os.ReadFile(viper.ConfigFileUsed())
	if !bytes.Equal(before, after) || !reflect.DeepEqual(conn, Config.Clusters[0]) || !reflect.DeepEqual(viper.Get(clusterKey), Config.Clusters) {
		t.Fatal("cancel changed prior state")
	}
}
