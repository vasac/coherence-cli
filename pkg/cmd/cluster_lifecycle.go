/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * https://oss.oracle.com/licenses/upl.
 */

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oracle/coherence-cli/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type managedProcess struct {
	command *exec.Cmd
	done    chan struct{}
	logFile string
	// Written by the sole Wait goroutine; read only after done closes.
	waitErr error
}

// openManagedProcessLog confines the truncating open itself, including when
// backup is disabled or a link changes after an earlier path/backup check.
func openManagedProcessLog(clusterName, processName string) (*os.File, error) {
	if err := validateClusterLogName(processName); err != nil {
		return nil, err
	}
	root, err := openClusterLogs(clusterName)
	if err != nil {
		return nil, err
	}
	file, openErr := root.OpenFile(processName+".log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	closeErr := root.Close()
	if openErr != nil {
		return nil, errors.Join(openErr, closeErr)
	}
	if closeErr != nil {
		return nil, errors.Join(closeErr, file.Close())
	}
	return file, nil
}

func launchManagedProcess(clusterName, processName string, args []string) (*managedProcess, error) {
	f, err := openManagedProcessLog(clusterName, processName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	command := exec.Command(javaExec, args...)
	command.Stdout, command.Stderr = f, f
	setForkProcess(command)
	if err = command.Start(); err != nil {
		return nil, err
	}
	p := &managedProcess{command: command, done: make(chan struct{}), logFile: filepath.Join(logsDirectory, clusterName, processName+".log")}
	go func() { p.waitErr = command.Wait(); close(p.done) }()
	return p, nil
}

// Cleanup is independent of operation cancellation and uses the original owned
// handles. Never reuse the stop-phase seam or re-find/re-signal numeric PIDs.
var killManagedProcess = (*os.Process).Kill
var managedCleanupTimeout = 5 * time.Second

func cleanupManagedProcesses(processes []*managedProcess) error {
	deadline := time.NewTimer(managedCleanupTimeout)
	defer deadline.Stop()
	var failures []error
	killErrors := make([]error, len(processes))
	// A failed kill or delayed completion must not prevent later attempts.
	for i, p := range processes {
		select {
		case <-p.done:
			continue
		default:
		}
		process := p.command.Process
		if err := killManagedProcess(process); err != nil && !processAlreadyExited(process.Pid, process, err) {
			killErrors[i] = err
		}
	}
	// All requests precede every wait. A single timer covers the collection;
	// the existing Wait goroutines keep reaping after a bounded return.
wait:
	for _, p := range processes {
		select {
		case <-p.done:
			continue
		default:
		}
		select {
		case <-p.done:
		case <-deadline.C:
			break wait
		}
	}
	completed := 0
	for i, p := range processes {
		completedWait := false
		select {
		case <-p.done:
			// Nonzero/signal exits still establish termination. In particular,
			// ProcessState.Exited alone would reject expected signal kills.
			var exitErr *exec.ExitError
			if p.waitErr == nil || errors.As(p.waitErr, &exitErr) && exitErr.ProcessState != nil {
				completed++
				completedWait = true
			} else {
				failures = append(failures, fmt.Errorf("wait for owned child PID %d (log %q); exit unresolved: %w", p.command.Process.Pid, p.logFile, p.waitErr))
			}
		default:
			failures = append(failures, fmt.Errorf("wait for owned child PID %d (log %q); completion unresolved after shared cleanup budget %s: %w", p.command.Process.Pid, p.logFile, managedCleanupTimeout, context.DeadlineExceeded))
		}
		// Windows Wait can release the owned handle between the request and
		// Kill. Only a trustworthy result from this child's sole Wait can
		// resolve that specific released-handle error. Other kill failures
		// survive completion; no numeric PID is reopened or signalled.
		if err := killErrors[i]; err != nil && (!completedWait || !processKillAfterWait(err)) {
			failures = append(failures, fmt.Errorf("kill owned child PID %d (log %q): %w", p.command.Process.Pid, p.logFile, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("owned-child cleanup reported errors (%d of %d children completed): %w", completed, len(processes), errors.Join(failures...))
	}
	return nil
}

var awaitManagedStartup = waitManagedReady

var managedReadinessTimeout = 90 * time.Second

// Readiness proves the expected cluster and every child PID are visible through
// the proposed REST endpoint. exec.Start alone is not a successful startup.
func waitManagedReady(cmd *cobra.Command, connection ClusterConnection, processes []*managedProcess) error {
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: time.Second, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	readJSON := func(url string, value interface{}) error {
		request, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP status %d", response.StatusCode)
		}
		return json.NewDecoder(response.Body).Decode(value)
	}
	deadline := time.Now().Add(managedReadinessTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := cmd.Context().Err(); err != nil {
			return err
		}
		for _, p := range processes {
			select {
			case <-p.done:
				return fmt.Errorf("member PID %d exited during startup; inspect its cluster log", p.command.Process.Pid)
			default:
			}
		}
		var cluster config.Cluster
		var members config.Members
		lastErr = readJSON(connection.ConnectionURL, &cluster)
		if lastErr == nil && cluster.ClusterName != connection.ClusterName {
			return fmt.Errorf("management endpoint belongs to cluster %s, expected %s", cluster.ClusterName, connection.ClusterName)
		}
		if lastErr == nil {
			lastErr = readJSON(connection.ConnectionURL+"/members", &members)
		}
		if lastErr == nil {
			visible := map[string]bool{}
			for _, member := range members.Members {
				visible[member.ProcessName] = true
			}
			ready := true
			for _, p := range processes {
				if !visible[strconv.Itoa(p.command.Process.Pid)] {
					ready = false
				}
			}
			if ready {
				return nil
			}
			lastErr = fmt.Errorf("waiting for launched member PIDs to join")
		}
		select {
		case <-cmd.Context().Done():
			return cmd.Context().Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("cluster startup/readiness failed at %s: %v; inspect cluster logs and check for occupied ports", connection.ConnectionURL, lastErr)
}

type managedConfigFile interface {
	io.Writer
	Name() string
	Sync() error
	Close() error
}

// File-operation seams keep persistence failure tests isolated from user files.
var createManagedConfigTemp = func(dir, pattern string) (managedConfigFile, error) {
	return os.CreateTemp(dir, pattern)
}

var renameManagedConfig = os.Rename

// Write a complete replacement beside the destination and rename only after success.
// A failed serialization/write must leave the prior on-disk settings intact.
func writeManagedConfigAtomically() error {
	filename := viper.ConfigFileUsed()
	if filename == "" {
		return fmt.Errorf("no configuration file selected")
	}
	destination := filename
	info, err := os.Lstat(filename)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		destination, err = filepath.EvalSymlinks(filename)
		if err != nil {
			return fmt.Errorf("unable to resolve configuration symlink %s: %w", filename, err)
		}
	}
	f, err := createManagedConfigTemp(filepath.Dir(destination), ".cohctl-management-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	// Viper uses the selected config type (or selected file's extension), just
	// as ReadInConfig does. WriteConfigAs would select the temporary extension.
	if err = viper.WriteConfigTo(f); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return renameManagedConfig(name, destination)
}

var writeManagedConfig = writeManagedConfigAtomically

func persistManagedConnection(connection ClusterConnection, create bool) error {
	oldClusters, oldContext := Config.Clusters, viper.Get(currentContextKey)
	oldViperClusters := viper.Get(clusterKey)
	updated := append([]ClusterConnection(nil), oldClusters...)
	if create {
		updated = append(updated, connection)
	} else {
		found := false
		for i := range updated {
			if updated[i].Name == connection.Name {
				updated[i] = connection
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unable to persist unknown cluster %s", connection.Name)
		}
	}
	// Use Viper's configuration field names for every codec. In particular,
	// ClusterConnection's public JSON output tags (url, clusterVersionParam)
	// differ from the field names used by Viper's configuration decoder.
	settings, err := configurationClusters(updated)
	if err != nil {
		return fmt.Errorf("unable to encode management settings: %w", err)
	}
	viper.Set(clusterKey, settings)
	if create {
		viper.Set(currentContextKey, connection.Name)
	}
	if err := writeManagedConfig(); err != nil {
		viper.Set(clusterKey, oldViperClusters)
		viper.Set(currentContextKey, oldContext)
		return fmt.Errorf("unable to save management settings; previous configuration retained: %w", err)
	}
	Config.Clusters = updated
	if create {
		Config.CurrentContext = connection.Name
	}
	return nil
}

func managedConnection(connection ClusterConnection, m ClusterManagement) ClusterConnection {
	args, _ := serverBaseOptions(connection) // preflight has already validated these
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.ContainsAny(arg, " \t\r\n'\"") {
			quoted = append(quoted, "'"+strings.ReplaceAll(arg, "'", "'\"'\"'")+"'")
		} else {
			quoted = append(quoted, arg)
		}
	}
	connection.Arguments = strings.Join(quoted, " ")
	connection.Management = &m
	connection.ConnectionURL = managementURL(m, connection.ManagementPort)
	return connection
}

func showManagedSettings(cmd *cobra.Command, connection ClusterConnection, m ClusterManagement) {
	cmd.Printf("Management REST: %s (bind %s)\n", managementURL(m, connection.ManagementPort), m.RESTAddress)
	if m.JMXPort == 0 {
		cmd.Println("JMX remote connector: disabled")
	} else {
		cmd.Printf("JMX registry/RMI: %s:%d (advertised %s)\n", m.JMXAddress, m.JMXPort, m.JMXHost)
	}
	cmd.Println("These endpoint settings will be saved after successful startup/readiness and configuration write.")
	if connection.Management == nil && connection.BaseClasspath != "" && m.JMXPort == 0 {
		cmd.Println("Legacy configuration: JMX was not saved by older CLI versions; use --jmx-port to re-enable it. The selected REST bind is shown above.")
	}
}

// The last cancellation check is the completion boundary. For create/start/
// restart, entering the synchronous persistence transaction accepts completion:
// a successful write transfers ownership to the user even if a signal arrives
// during that write. A failed write still cleans the children. Scale has no
// write; passing this check transfers ownership. Deferred context/signal cleanup
// must never kill successfully detached members.
func completeManagedStartup(cmd *cobra.Command, connection ClusterConnection, processes []*managedProcess, create, persist bool) error {
	err := cmd.Context().Err()
	if err == nil && persist {
		err = persistManagedConnection(connection, create)
	}
	if err != nil {
		if cleanupErr := cleanupManagedProcesses(processes); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("completion failure cleanup: %w", cleanupErr))
		}
	}
	return err
}
