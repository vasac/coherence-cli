/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * https://oss.oracle.com/licenses/upl.
 */

package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func TestGenerateGrafanaPassword(t *testing.T) {
	original := monitoringRandomReader
	monitoringRandomReader = bytes.NewReader(bytes.Repeat([]byte{0xa5}, 32))
	t.Cleanup(func() { monitoringRandomReader = original })

	password, err := generateGrafanaPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 43 {
		t.Fatalf("expected 43-character unpadded base64url password, got %d", len(password))
	}
	if strings.ContainsAny(password, "+/=") {
		t.Fatalf("password is not unpadded base64url: %q", password)
	}

	directory := t.TempDir()
	if err = writeGrafanaPassword(directory, password); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(directory, grafanaPasswordFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != password {
		t.Fatalf("password file contains unexpected data %q", contents)
	}
	if err = validateMonitoringSecretFile(filepath.Join(directory, grafanaPasswordFile)); err != nil {
		t.Fatalf("new password file did not pass validation: %v", err)
	}
}

func TestGenerateGrafanaPasswordEntropyFailure(t *testing.T) {
	original := monitoringRandomReader
	monitoringRandomReader = &failingReader{}
	t.Cleanup(func() { monitoringRandomReader = original })
	if password, err := generateGrafanaPassword(); err == nil || password != "" {
		t.Fatalf("expected entropy failure without a password, got %q, %v", password, err)
	}
}

type failingReader struct{}

func (*failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestMonitoringConfigBaseURL(t *testing.T) {
	tests := []struct {
		version string
		want    string
		valid   bool
	}{
		{"1.10.11", "https://raw.githubusercontent.com/oracle/coherence-cli/refs/tags/1.10.11/monitoring", true},
		{"1.11.0-RC1", "https://raw.githubusercontent.com/oracle/coherence-cli/refs/tags/1.11.0-RC1/monitoring", true},
		{" 1.10.11 ", "https://raw.githubusercontent.com/oracle/coherence-cli/refs/tags/1.10.11/monitoring", true},
		{"", "", false},
		{"v1.10.11", "", false},
		{"../heads/main", "", false},
		{"1.10", "", false},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			actual, err := monitoringConfigBaseURL(test.version)
			if test.valid {
				if err != nil {
					t.Fatal(err)
				}
				if actual != test.want {
					t.Fatalf("expected %q, got %q", test.want, actual)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected version %q to be rejected, got %q", test.version, actual)
			}
		})
	}
}

func TestValidateMonitoringSecretPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are not meaningful on Windows")
	}
	file := filepath.Join(t.TempDir(), grafanaPasswordFile)
	validPassword := bytes.Repeat([]byte("a"), 43)
	if err := os.WriteFile(file, validPassword, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if err := validateMonitoringSecretFile(file); err == nil || !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("expected insecure permission failure, got %v", err)
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateMonitoringSecretFile(file); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "password-link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := validateMonitoringSecretFile(link); err == nil || !strings.Contains(err.Error(), "non-symbolic-link") {
		t.Fatalf("expected symlink failure, got %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty-password")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateMonitoringSecretFile(empty); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty password failure, got %v", err)
	}
}

func TestMonitoringBindAddress(t *testing.T) {
	tests := []struct {
		input       string
		want        string
		wantWarning string
		wantURL     string
	}{
		{"127.0.0.1", "127.0.0.1", "", "http://127.0.0.1:3000/api/health"},
		{"::1", "::1", "", "http://[::1]:3000/api/health"},
		{"192.0.2.15", "192.0.2.15", "non-loopback", "http://192.0.2.15:3000/api/health"},
		{"0.0.0.0", "0.0.0.0", "every network interface", "http://127.0.0.1:3000/api/health"},
		{"::", "::", "every network interface", "http://[::1]:3000/api/health"},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			address, err := parseMonitoringBindAddress(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if address != test.want {
				t.Fatalf("got address %q, want %q", address, test.want)
			}
			warning := monitoringExposureWarning(address)
			if !strings.Contains(warning, test.wantWarning) {
				t.Fatalf("got warning %q, want it to contain %q", warning, test.wantWarning)
			}
			if url := monitoringURL(address, 3000, "/api/health"); url != test.wantURL {
				t.Fatalf("got URL %q, want %q", url, test.wantURL)
			}
		})
	}
	if _, err := parseMonitoringBindAddress("localhost"); err == nil {
		t.Fatal("expected hostname to be rejected")
	}
	if _, err := parseMonitoringBindAddress(""); err == nil {
		t.Fatal("expected an explicitly empty address to be rejected")
	}
	t.Setenv(monitoringBindAddressEnv, "")
	if _, err := monitoringBindAddressFromEnvironment(); err == nil {
		t.Fatal("expected an explicitly empty environment value to be rejected")
	}
	if err := os.Unsetenv(monitoringBindAddressEnv); err != nil {
		t.Fatal(err)
	}
	if address, err := monitoringBindAddressFromEnvironment(); err != nil || address != defaultMonitoringAddress {
		t.Fatalf("expected unset environment to default to loopback, got %q, %v", address, err)
	}
}

func TestLegacyPortWarningsUseEffectiveBindAddress(t *testing.T) {
	t.Setenv(monitoringBindAddressEnv, "")
	tracked := trackedCompose(t)
	if warnings := legacyPortWarnings(tracked); len(warnings) != 0 {
		t.Fatalf("tracked loopback defaults unexpectedly warned: %v", warnings)
	}
	t.Setenv(monitoringBindAddressEnv, "0.0.0.0")
	if warnings := legacyPortWarnings(tracked); len(warnings) != 2 {
		t.Fatalf("expected warnings for both inherited wildcard listeners, got %v", warnings)
	}
	shortPorts := []byte(`services:
  grafana:
    ports: ["3000:3000"]
  prometheus:
    ports: ["127.0.0.1:9090:9090"]
`)
	if warnings := legacyPortWarnings(shortPorts); len(warnings) != 1 || !strings.Contains(warnings[0], "grafana") {
		t.Fatalf("expected only Grafana wildcard warning, got %v", warnings)
	}
}

func TestMonitoringBindAddressPersistence(t *testing.T) {
	directory := t.TempDir()
	if err := writeMonitoringEnv(directory, "2001:db8::10"); err != nil {
		t.Fatal(err)
	}
	address, err := readMonitoringEnv(directory)
	if err != nil || address != "2001:db8::10" {
		t.Fatalf("persisted address = %q, %v", address, err)
	}
	if err = os.WriteFile(filepath.Join(directory, monitoringEnvFile), []byte(monitoringBindAddressEnv+"=\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readMonitoringEnv(directory); err == nil {
		t.Fatal("expected empty persisted address to fail")
	}
	duplicate := monitoringBindAddressEnv + "=127.0.0.1\n" + monitoringBindAddressEnv + "=0.0.0.0\n"
	if err = os.WriteFile(filepath.Join(directory, monitoringEnvFile), []byte(duplicate), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readMonitoringEnv(directory); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("expected duplicate persisted address to fail, got %v", err)
	}
}

func TestSanitizeGrafanaINI(t *testing.T) {
	input := []byte(`[server]
http_port = 3000
admin_password = misplaced-secret

[security]
admin_user = attacker
admin_password = admin
admin_password = another-secret
cookie_secure = true

[users]
allow_sign_up = false
`)
	result := string(sanitizeGrafanaINI(input))
	if strings.Contains(result, "admin_password") || strings.Contains(result, "attacker") {
		t.Fatalf("credentials were not removed from INI:\n%s", result)
	}
	if strings.Count(result, "admin_user = admin") != 1 {
		t.Fatalf("expected exactly one fixed admin user:\n%s", result)
	}
	if !strings.Contains(result, "cookie_secure = true") || !strings.Contains(result, "allow_sign_up = false") {
		t.Fatalf("unrelated settings were lost:\n%s", result)
	}
}

func TestGenerateSecureComposeSanitizesHostileInputs(t *testing.T) {
	input := []byte(`services:
  grafana:
    image: grafana/grafana:12.0.0
    networks:
      coherence:
    environment:
      - GF_SECURITY_ADMIN_USER=attacker
      - GF_SECURITY_ADMIN_PASSWORD=leaked-direct-password
      - GF_SECURITY_ADMIN_PASSWORD__FILE=/tmp/attacker-password
      - KEEP_ME=yes
    ports:
      - 0.0.0.0:3000:3000
      - 3001:3000
    secrets:
      - attacker_secret
    volumes:
      - ./grafana-admin-password:/tmp/attacker-password
      - ./grafana.ini:/etc/grafana/grafana.ini
      - ./datasources.yaml:/etc/grafana/provisioning/datasources/datasources.yaml
      - ./dashboards.yaml:/etc/grafana/provisioning/dashboards/dashboards.yaml
      - ./dashboards:/etc/grafana/provisioning/dashboards/dashboards
  prometheus:
    image: prom/prometheus:v3.4.1
    networks:
      coherence:
    command:
      - --config.file=/etc/prometheus/prometheus.yaml
    volumes:
      - ./prometheus.yaml:/etc/prometheus/prometheus.yaml
    ports:
      - 9090:9090
      - 9091:9090
    secrets:
      - attacker_secret
secrets:
  grafana_admin_password:
    file: ./attacker-password
  unrelated_secret:
    file: ./unrelated
networks:
  coherence:
`)
	generated, err := generateSecureCompose(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(generated), "leaked-direct-password") || strings.Contains(string(generated), "/tmp/attacker-password") {
		t.Fatalf("generated compose retains attacker-controlled credentials:\n%s", generated)
	}

	var document map[string]any
	if err = yaml.Unmarshal(generated, &document); err != nil {
		t.Fatal(err)
	}
	services, _ := stringMap(document["services"])
	grafana, _ := stringMap(services["grafana"])
	prometheus, _ := stringMap(services["prometheus"])
	assertOneSecurePort(t, grafana, grafanaPort)
	assertOneSecurePort(t, prometheus, prometheusPort)

	environment, _ := stringMap(grafana["environment"])
	if environment["GF_SECURITY_ADMIN_USER"] != grafanaAdminUser || environment["GF_SECURITY_ADMIN_PASSWORD__FILE"] != grafanaAdminFileTarget {
		t.Fatalf("Grafana secure environment is incorrect: %#v", environment)
	}
	if _, exists := environment["GF_SECURITY_ADMIN_PASSWORD"]; exists {
		t.Fatalf("direct password remains in environment: %#v", environment)
	}
	if environment["KEEP_ME"] != "yes" {
		t.Fatalf("unrelated environment was lost: %#v", environment)
	}
	if _, exists := prometheus["secrets"]; exists {
		t.Fatalf("Prometheus unexpectedly received secrets: %#v", prometheus["secrets"])
	}
	grafanaSecrets, ok := grafana["secrets"].([]any)
	if !ok || len(grafanaSecrets) != 1 {
		t.Fatalf("Grafana must receive exactly one secret: %#v", grafana["secrets"])
	}
	grant, _ := stringMap(grafanaSecrets[0])
	if grant["source"] != grafanaPasswordSecret || grant["target"] != grafanaPasswordSecret {
		t.Fatalf("unexpected Grafana secret grant: %#v", grant)
	}
	secrets, _ := stringMap(document["secrets"])
	passwordSecret, _ := stringMap(secrets[grafanaPasswordSecret])
	if passwordSecret["file"] != "./"+grafanaPasswordFile {
		t.Fatalf("unexpected password secret source: %#v", passwordSecret)
	}
}

func TestGenerateSecureComposeRejectsUnapprovedServiceFields(t *testing.T) {
	compose := trackedCompose(t)
	compose = bytes.Replace(compose, []byte("    image: grafana/grafana:"), []byte("    privileged: true\n    image: grafana/grafana:"), 1)
	if _, err := generateSecureCompose(compose); err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("expected unsupported field rejection, got %v", err)
	}
}

func TestGenerateSecureComposeNormalizesMapEnvironment(t *testing.T) {
	compose := trackedCompose(t)
	compose = bytes.Replace(compose, []byte("    image: grafana/grafana:"), []byte(`    environment:
      GF_SECURITY_ADMIN_USER: attacker
      GF_SECURITY_ADMIN_PASSWORD: direct-secret
      GF_SECURITY_ADMIN_PASSWORD__FILE: /tmp/alternate
      KEEP_ME: preserved
    image: grafana/grafana:`), 1)
	generated, err := generateSecureCompose(compose)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = yaml.Unmarshal(generated, &document); err != nil {
		t.Fatal(err)
	}
	services, _ := stringMap(document["services"])
	grafana, _ := stringMap(services["grafana"])
	environment, _ := stringMap(grafana["environment"])
	if len(environment) != 3 || environment["GF_SECURITY_ADMIN_USER"] != grafanaAdminUser ||
		environment["GF_SECURITY_ADMIN_PASSWORD__FILE"] != grafanaAdminFileTarget || environment["KEEP_ME"] != "preserved" {
		t.Fatalf("map environment was not normalized: %#v", environment)
	}
}

func assertOneSecurePort(t *testing.T, service map[string]any, port int) {
	t.Helper()
	ports, ok := service["ports"].([]any)
	if !ok || len(ports) != 1 {
		t.Fatalf("expected one authoritative port, got %#v", service["ports"])
	}
	mapping, _ := stringMap(ports[0])
	if mapping["target"] != port || mapping["published"] != strconv.Itoa(port) {
		t.Fatalf("unexpected port mapping: %#v", mapping)
	}
	if mapping["host_ip"] != "${COHCTL_MONITORING_BIND_ADDRESS:?monitoring bind address is required}" {
		t.Fatalf("unexpected host IP mapping: %#v", mapping)
	}
}

func TestClassifyMonitoringBundle(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, dockerComposeYAML), []byte("services: {}"), 0600); err != nil {
		t.Fatal(err)
	}
	mode, err := classifyMonitoringBundle(directory)
	if err != nil || mode != monitoringBundleLegacy {
		t.Fatalf("expected legacy mode, got %v, %v", mode, err)
	}
	if err = os.WriteFile(filepath.Join(directory, generatedDockerComposeYAML), []byte("services: {}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = classifyMonitoringBundle(directory); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("expected incomplete bundle error, got %v", err)
	}
	if err = os.WriteFile(filepath.Join(directory, monitoringEnvFile), []byte("COHCTL_MONITORING_BIND_ADDRESS=127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, grafanaPasswordFile), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	mode, err = classifyMonitoringBundle(directory)
	if err != nil || mode != monitoringBundleGenerated {
		t.Fatalf("expected generated mode, got %v, %v", mode, err)
	}
}

func TestComposeForStopSelection(t *testing.T) {
	tests := []struct {
		name          string
		generated     []byte
		legacy        []byte
		wantBase      string
		wantGenerated bool
		wantError     bool
	}{
		{"generated only", secureCompose(t), nil, generatedDockerComposeYAML, true, false},
		{"legacy only", nil, minimalLegacyCompose(), dockerComposeYAML, false, false},
		{"mixed prefers generated", secureCompose(t), minimalLegacyCompose(), generatedDockerComposeYAML, true, false},
		{"corrupt generated falls back", []byte("not: [yaml"), minimalLegacyCompose(), dockerComposeYAML, false, false},
		{"no usable model", []byte("not: [yaml"), []byte("services: {}"), "", false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			if test.generated != nil {
				if err := os.WriteFile(filepath.Join(directory, generatedDockerComposeYAML), test.generated, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if test.legacy != nil {
				if err := os.WriteFile(filepath.Join(directory, dockerComposeYAML), test.legacy, 0600); err != nil {
					t.Fatal(err)
				}
			}
			mon := newMonitoringAt(&cobra.Command{}, directory)
			file, address, generated, err := mon.composeForStop()
			if test.wantError {
				if err == nil {
					t.Fatal("expected stop selection to fail")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if filepath.Base(file) != test.wantBase || generated != test.wantGenerated || address != defaultMonitoringAddress {
				t.Fatalf("unexpected selection file=%s generated=%v address=%s", file, generated, address)
			}
		})
	}
}

func TestInstallStagedDirectoryReplacesCompleteDirectory(t *testing.T) {
	parent := t.TempDir()
	active := filepath.Join(parent, "monitoring")
	staged := filepath.Join(parent, "staged")
	if err := os.Mkdir(active, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(active, "old"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(staged, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "new"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	mon := newMonitoringAt(&cobra.Command{}, active)
	if err := mon.installStagedDirectory(staged); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(active, "new")); err != nil {
		t.Fatalf("new directory was not installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(active, "old")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old directory was not replaced: %v", err)
	}
}

func secureCompose(t *testing.T) []byte {
	t.Helper()
	generated, err := generateSecureCompose(trackedCompose(t))
	if err != nil {
		t.Fatal(err)
	}
	return generated
}

func trackedCompose(t *testing.T) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "monitoring", dockerComposeYAML))
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func minimalLegacyCompose() []byte {
	return []byte("services:\n  grafana:\n    image: grafana/grafana:1\n  prometheus:\n    image: prom/prometheus:1\n")
}

func TestParseComposeMajorVersion(t *testing.T) {
	for input, expected := range map[string]int{
		"2.38.2\n":                       2,
		"Docker Compose version v2.24.1": 2,
		"docker-compose version 1.29.2":  1,
	} {
		major, err := parseComposeMajorVersion(input)
		if err != nil || major != expected {
			t.Fatalf("parseComposeMajorVersion(%q) = %d, %v; want %d", input, major, err, expected)
		}
	}
	if _, err := parseComposeMajorVersion("unknown"); err == nil {
		t.Fatal("expected unknown Compose version to fail")
	}
}

func TestWithEnvironmentReplacesInheritedBindAddress(t *testing.T) {
	t.Setenv(monitoringBindAddressEnv, "0.0.0.0")
	environment := withEnvironment([]string{monitoringBindAddressEnv + "=127.0.0.1"})
	count := 0
	for _, entry := range environment {
		if strings.HasPrefix(entry, monitoringBindAddressEnv+"=") {
			count++
			if entry != monitoringBindAddressEnv+"=127.0.0.1" {
				t.Fatalf("inherited bind address survived: %q", entry)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one bind-address environment entry, got %d", count)
	}
}

func TestTrackedMonitoringTemplatesAreSafeByDefault(t *testing.T) {
	ini, err := os.ReadFile(filepath.Join("..", "..", "monitoring", "grafana.ini"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(ini)), "admin_password") {
		t.Fatalf("tracked grafana.ini contains an administrator password:\n%s", ini)
	}
	compose, err := os.ReadFile(filepath.Join("..", "..", "monitoring", dockerComposeYAML))
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(compose), "${COHCTL_MONITORING_BIND_ADDRESS:-127.0.0.1}"); count != 2 {
		t.Fatalf("expected both tracked ports to default to loopback, got %d:\n%s", count, compose)
	}
}
