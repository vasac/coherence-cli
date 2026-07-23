/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * https://oss.oracle.com/licenses/upl.
 */

package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	generatedDockerComposeYAML = "docker-compose.cohctl.yaml"
	monitoringEnvFile          = "monitoring.env"
	grafanaPasswordFile        = "grafana-admin-password"
	monitoringBindAddressEnv   = "COHCTL_MONITORING_BIND_ADDRESS"
	grafanaPasswordSecret      = "grafana_admin_password"
	grafanaAdminFileTarget     = "/run/secrets/grafana_admin_password"
	grafanaAdminUser           = "admin"
	defaultMonitoringAddress   = "127.0.0.1"
)

var monitoringRandomReader = io.Reader(rand.Reader)

type monitoringBundleMode int

const (
	monitoringBundleInvalid monitoringBundleMode = iota
	monitoringBundleGenerated
	monitoringBundleLegacy
)

func parseMonitoringBindAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s must not be empty", monitoringBindAddressEnv)
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", fmt.Errorf("%s must be an IPv4 or IPv6 address, got %q", monitoringBindAddressEnv, value)
	}
	return ip.String(), nil
}

func monitoringBindAddressFromEnvironment() (string, error) {
	value, exists := os.LookupEnv(monitoringBindAddressEnv)
	if !exists {
		return defaultMonitoringAddress, nil
	}
	return parseMonitoringBindAddress(value)
}

func monitoringConnectAddress(bindAddress string) string {
	ip := net.ParseIP(bindAddress)
	if ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			return "127.0.0.1"
		}
		return "::1"
	}
	return bindAddress
}

func monitoringURL(bindAddress string, port int, suffix string) string {
	return "http://" + net.JoinHostPort(monitoringConnectAddress(bindAddress), strconv.Itoa(port)) + suffix
}

func monitoringExposureWarning(bindAddress string) string {
	ip := net.ParseIP(bindAddress)
	if ip == nil || ip.IsLoopback() {
		return ""
	}
	if ip.IsUnspecified() {
		return fmt.Sprintf("WARNING: %s=%s exposes Grafana and Prometheus on every network interface.", monitoringBindAddressEnv, bindAddress)
	}
	return fmt.Sprintf("WARNING: %s=%s exposes Grafana and Prometheus on a non-loopback interface.", monitoringBindAddressEnv, bindAddress)
}

func legacyPortWarnings(contents []byte) []string {
	var document map[string]any
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return []string{"WARNING: unable to inspect legacy monitoring ports; they may be exposed on every network interface."}
	}
	services, ok := stringMap(document["services"])
	if !ok {
		return []string{"WARNING: unable to inspect legacy monitoring services; their ports may be exposed."}
	}
	warnings := make([]string, 0, 2)
	for _, name := range []string{"grafana", "prometheus"} {
		service, serviceOK := stringMap(services[name])
		if !serviceOK || legacyPortsMayBeExposed(service["ports"]) {
			warnings = append(warnings, fmt.Sprintf("WARNING: the legacy %s port may be exposed on a non-loopback or wildcard interface.", name))
		}
	}
	return warnings
}

func legacyPortsMayBeExposed(value any) bool {
	ports, ok := value.([]any)
	if !ok || len(ports) == 0 {
		return false
	}
	for _, item := range ports {
		address := ""
		if mapping, mapOK := stringMap(item); mapOK {
			address = fmt.Sprint(mapping["host_ip"])
			if _, exists := mapping["host_ip"]; !exists {
				return true
			}
		} else {
			published := strings.TrimSuffix(fmt.Sprint(item), "/tcp")
			if strings.HasPrefix(published, "[") {
				closing := strings.Index(published, "]")
				if closing < 0 {
					return true
				}
				address = published[1:closing]
			} else {
				parts := strings.Split(published, ":")
				if len(parts) == 2 {
					return true
				}
				if len(parts) != 3 {
					return true
				}
				address = parts[0]
			}
		}
		address = resolveLegacyBindExpression(address)
		ip := net.ParseIP(address)
		if ip == nil || !ip.IsLoopback() {
			return true
		}
	}
	return false
}

func resolveLegacyBindExpression(value string) string {
	defaultExpression := "${" + monitoringBindAddressEnv + ":-" + defaultMonitoringAddress + "}"
	if value == defaultExpression {
		if inherited := strings.TrimSpace(os.Getenv(monitoringBindAddressEnv)); inherited != "" {
			return inherited
		}
		return defaultMonitoringAddress
	}
	plainExpression := "${" + monitoringBindAddressEnv + "}"
	if value == plainExpression {
		return strings.TrimSpace(os.Getenv(monitoringBindAddressEnv))
	}
	return value
}

func generateGrafanaPassword() (string, error) {
	random := make([]byte, 32)
	if _, err := io.ReadFull(monitoringRandomReader, random); err != nil {
		return "", fmt.Errorf("unable to generate Grafana administrator password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

func validateGrafanaPasswordContents(contents []byte) error {
	if len(contents) == 0 {
		return errors.New("password is empty")
	}
	if len(contents) != 43 || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).Match(contents) {
		return errors.New("password is not a 32-byte unpadded base64url value")
	}
	return nil
}

func writeGrafanaPassword(directory, password string) error {
	file := filepath.Join(directory, grafanaPasswordFile)
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("unable to create Grafana password file %s: %w", file, err)
	}
	if _, err = io.WriteString(f, password); err != nil {
		_ = f.Close()
		return fmt.Errorf("unable to write Grafana password file %s: %w", file, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("unable to close Grafana password file %s: %w", file, err)
	}
	return nil
}

func writeMonitoringEnv(directory, bindAddress string) error {
	content := []byte(monitoringBindAddressEnv + "=" + bindAddress + "\n")
	return writeFileContents(directory, monitoringEnvFile, content)
}

func readMonitoringEnv(directory string) (string, error) {
	file := filepath.Join(directory, monitoringEnvFile)
	contents, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("unable to read %s: %w", file, err)
	}
	address := ""
	for _, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != monitoringBindAddressEnv {
			return "", fmt.Errorf("%s contains an unsupported entry %q", file, line)
		}
		if address != "" {
			return "", fmt.Errorf("%s defines %s more than once", file, monitoringBindAddressEnv)
		}
		address, err = parseMonitoringBindAddress(value)
		if err != nil {
			return "", err
		}
	}
	if address == "" {
		return "", fmt.Errorf("%s does not define %s", file, monitoringBindAddressEnv)
	}
	return address, nil
}

func classifyMonitoringBundle(directory string) (monitoringBundleMode, error) {
	generatedFiles := []string{generatedDockerComposeYAML, monitoringEnvFile, grafanaPasswordFile}
	found := make([]string, 0, len(generatedFiles))
	missing := make([]string, 0, len(generatedFiles))
	for _, name := range generatedFiles {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err == nil && info.Mode().IsRegular() {
			found = append(found, name)
			continue
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return monitoringBundleInvalid, fmt.Errorf("unable to inspect monitoring bundle file %s: %w", name, err)
		}
		missing = append(missing, name)
	}
	if len(found) == len(generatedFiles) {
		return monitoringBundleGenerated, nil
	}
	if len(found) == 0 {
		if info, err := os.Lstat(filepath.Join(directory, dockerComposeYAML)); err == nil && info.Mode().IsRegular() {
			return monitoringBundleLegacy, nil
		}
		return monitoringBundleInvalid, monitoringNotValid("no usable generated or legacy compose configuration exists")
	}
	sort.Strings(found)
	sort.Strings(missing)
	return monitoringBundleInvalid, fmt.Errorf("monitoring installation is incomplete: found %s but missing %s; rerun 'cohctl init monitoring'", strings.Join(found, ", "), strings.Join(missing, ", "))
}

func sanitizeGrafanaINI(contents []byte) []byte {
	lines := strings.Split(strings.ReplaceAll(string(contents), "\r\n", "\n"), "\n")
	result := make([]string, 0, len(lines)+2)
	inSecurity := false
	foundSecurity := false
	foundAdminUser := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if key, _, found := strings.Cut(trimmed, "="); found && strings.EqualFold(strings.TrimSpace(key), "admin_password") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if inSecurity && !foundAdminUser {
				result = append(result, "admin_user = "+grafanaAdminUser)
				foundAdminUser = true
			}
			inSecurity = strings.EqualFold(strings.TrimSpace(trimmed[1:len(trimmed)-1]), "security")
			if inSecurity {
				foundSecurity = true
				foundAdminUser = false
			}
			result = append(result, line)
			continue
		}
		if inSecurity {
			key, _, found := strings.Cut(trimmed, "=")
			if found {
				switch strings.ToLower(strings.TrimSpace(key)) {
				case "admin_user":
					if !foundAdminUser {
						result = append(result, "admin_user = "+grafanaAdminUser)
						foundAdminUser = true
					}
					continue
				}
			}
		}
		result = append(result, line)
	}
	if inSecurity && !foundAdminUser {
		result = append(result, "admin_user = "+grafanaAdminUser)
	}
	if !foundSecurity {
		if len(result) > 0 && result[len(result)-1] != "" {
			result = append(result, "")
		}
		result = append(result, "[security]", "admin_user = "+grafanaAdminUser)
	}
	return []byte(strings.TrimRight(strings.Join(result, "\n"), "\n") + "\n")
}

func generateSecureCompose(contents []byte) ([]byte, error) {
	var document map[string]any
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return nil, fmt.Errorf("unable to parse downloaded docker compose configuration: %w", err)
	}
	services, ok := stringMap(document["services"])
	if !ok {
		return nil, errors.New("downloaded docker compose configuration does not define services")
	}
	grafana, ok := stringMap(services["grafana"])
	if !ok {
		return nil, errors.New("downloaded docker compose configuration does not define the grafana service")
	}
	prometheus, ok := stringMap(services["prometheus"])
	if !ok {
		return nil, errors.New("downloaded docker compose configuration does not define the prometheus service")
	}
	if !strings.HasPrefix(fmt.Sprint(grafana["image"]), "grafana/grafana:") {
		return nil, errors.New("downloaded docker compose configuration has an unexpected Grafana image")
	}
	if !strings.HasPrefix(fmt.Sprint(prometheus["image"]), "prom/prometheus:") {
		return nil, errors.New("downloaded docker compose configuration has an unexpected Prometheus image")
	}
	if err := validateDownloadedComposeModel(document, services, grafana, prometheus); err != nil {
		return nil, err
	}

	grafana["environment"] = secureGrafanaEnvironment(grafana["environment"])
	grafana["ports"] = secureServicePort(grafanaPort)
	grafana["secrets"] = []any{map[string]any{"source": grafanaPasswordSecret, "target": grafanaPasswordSecret}}
	grafana["volumes"] = removeSecretVolumeMounts(grafana["volumes"])
	prometheus["ports"] = secureServicePort(prometheusPort)
	delete(prometheus, "secrets")
	prometheus["volumes"] = removeSecretVolumeMounts(prometheus["volumes"])

	services["grafana"] = grafana
	services["prometheus"] = prometheus
	document["services"] = services
	secrets := map[string]any{}
	secrets[grafanaPasswordSecret] = map[string]any{"file": "./" + grafanaPasswordFile}
	document["secrets"] = secrets

	result, err := yaml.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("unable to create secure docker compose configuration: %w", err)
	}
	if err = validateSecureComposeDocument(document); err != nil {
		return nil, fmt.Errorf("generated docker compose configuration failed validation: %w", err)
	}
	return result, nil
}

func validateDownloadedComposeModel(document, services, grafana, prometheus map[string]any) error {
	for key := range document {
		if key != "services" && key != "networks" && key != "secrets" {
			return fmt.Errorf("downloaded docker compose configuration contains unsupported top-level field %q", key)
		}
	}
	for name := range services {
		if name != "grafana" && name != "prometheus" {
			return fmt.Errorf("downloaded docker compose configuration contains unexpected service %q", name)
		}
	}
	allowedGrafana := map[string]bool{"image": true, "networks": true, "volumes": true, "ports": true, "environment": true, "secrets": true}
	allowedPrometheus := map[string]bool{"image": true, "networks": true, "volumes": true, "ports": true, "command": true, "environment": true, "secrets": true}
	if err := rejectUnsupportedServiceFields("grafana", grafana, allowedGrafana); err != nil {
		return err
	}
	if err := rejectUnsupportedServiceFields("prometheus", prometheus, allowedPrometheus); err != nil {
		return err
	}
	if !serviceUsesNetwork(grafana, "coherence") || !serviceUsesNetwork(prometheus, "coherence") {
		return errors.New("downloaded docker compose configuration must attach Grafana and Prometheus to the coherence network")
	}
	networks, ok := stringMap(document["networks"])
	if !ok || len(networks) != 1 || networks["coherence"] == nil {
		// An empty YAML mapping is decoded as nil, so membership is checked separately.
		if _, exists := networks["coherence"]; !ok || len(networks) != 1 || !exists {
			return errors.New("downloaded docker compose configuration must define only the coherence network")
		}
	}
	if !containsConfigurationReference(prometheus["command"], "--config.file=/etc/prometheus/prometheus.yaml") {
		return errors.New("downloaded Prometheus service does not use the expected configuration command")
	}
	if err := validateVolumeReferences("Prometheus", prometheus["volumes"], []string{
		"./prometheus.yaml:/etc/prometheus/prometheus.yaml",
	}); err != nil {
		return err
	}
	if err := validateVolumeReferences("Grafana", grafana["volumes"], []string{
		"./grafana.ini:/etc/grafana/grafana.ini",
		"./datasources.yaml:/etc/grafana/provisioning/datasources/datasources.yaml",
		"./dashboards.yaml:/etc/grafana/provisioning/dashboards/dashboards.yaml",
		"./dashboards:/etc/grafana/provisioning/dashboards/dashboards",
	}); err != nil {
		return err
	}
	return nil
}

func rejectUnsupportedServiceFields(service string, model map[string]any, allowed map[string]bool) error {
	for key := range model {
		if !allowed[key] {
			return fmt.Errorf("downloaded %s service contains unsupported field %q", service, key)
		}
	}
	return nil
}

func serviceUsesNetwork(service map[string]any, expected string) bool {
	if networks, ok := stringMap(service["networks"]); ok {
		_, exists := networks[expected]
		return len(networks) == 1 && exists
	}
	if networks, ok := service["networks"].([]any); ok {
		return len(networks) == 1 && fmt.Sprint(networks[0]) == expected
	}
	return false
}

func containsConfigurationReference(value any, expected string) bool {
	if fmt.Sprint(value) == expected {
		return true
	}
	if list, ok := value.([]any); ok {
		for _, item := range list {
			if fmt.Sprint(item) == expected {
				return true
			}
		}
	}
	return false
}

func validateVolumeReferences(service string, value any, required []string) error {
	volumes, ok := value.([]any)
	if !ok {
		return fmt.Errorf("downloaded %s service does not define the expected volumes", service)
	}
	found := make(map[string]bool, len(required))
	for _, item := range volumes {
		volume := fmt.Sprint(item)
		matched := false
		for _, expected := range required {
			if volume == expected {
				found[expected] = true
				matched = true
				break
			}
		}
		if !matched && !isPasswordSecretReference(volume) {
			return fmt.Errorf("downloaded %s service contains unsupported volume %q", service, volume)
		}
	}
	for _, expected := range required {
		if !found[expected] {
			return fmt.Errorf("downloaded %s service is missing required volume %q", service, expected)
		}
	}
	return nil
}

func isPasswordSecretReference(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, strings.ToLower(grafanaPasswordFile)) ||
		strings.Contains(value, strings.ToLower(grafanaPasswordSecret)) ||
		strings.Contains(value, strings.ToLower(grafanaAdminFileTarget))
}

func validateSecureComposeDocument(document map[string]any) error {
	services, ok := stringMap(document["services"])
	if !ok || len(services) != 2 {
		return errors.New("expected exactly the Grafana and Prometheus services")
	}
	grafana, grafanaOK := stringMap(services["grafana"])
	prometheus, prometheusOK := stringMap(services["prometheus"])
	if !grafanaOK || !prometheusOK {
		return errors.New("expected Grafana and Prometheus services")
	}
	if err := validateSecurePortList("Grafana", grafana["ports"], grafanaPort); err != nil {
		return err
	}
	if err := validateSecurePortList("Prometheus", prometheus["ports"], prometheusPort); err != nil {
		return err
	}
	environment, ok := stringMap(grafana["environment"])
	if !ok || environment["GF_SECURITY_ADMIN_USER"] != grafanaAdminUser || environment["GF_SECURITY_ADMIN_PASSWORD__FILE"] != grafanaAdminFileTarget {
		return errors.New("Grafana administrator environment is not authoritative")
	}
	for key := range environment {
		if strings.HasPrefix(key, "GF_SECURITY_ADMIN_PASSWORD") && key != "GF_SECURITY_ADMIN_PASSWORD__FILE" {
			return fmt.Errorf("Grafana contains competing administrator password setting %s", key)
		}
	}
	grants, ok := grafana["secrets"].([]any)
	if !ok || len(grants) != 1 {
		return errors.New("Grafana must receive exactly one password secret")
	}
	grant, ok := stringMap(grants[0])
	if !ok || grant["source"] != grafanaPasswordSecret || grant["target"] != grafanaPasswordSecret {
		return errors.New("Grafana password secret grant is invalid")
	}
	if _, exists := prometheus["secrets"]; exists {
		return errors.New("Prometheus must not receive the Grafana password secret")
	}
	secrets, ok := stringMap(document["secrets"])
	if !ok || len(secrets) != 1 {
		return errors.New("generated model must define exactly one secret")
	}
	secret, ok := stringMap(secrets[grafanaPasswordSecret])
	if !ok || secret["file"] != "./"+grafanaPasswordFile {
		return errors.New("Grafana password secret source is invalid")
	}
	return nil
}

func validateSecurePortList(service string, value any, port int) error {
	ports, ok := value.([]any)
	if !ok || len(ports) != 1 {
		return fmt.Errorf("%s must publish exactly one port", service)
	}
	mapping, ok := stringMap(ports[0])
	if !ok || mapping["target"] != port || fmt.Sprint(mapping["published"]) != strconv.Itoa(port) ||
		mapping["host_ip"] != "${"+monitoringBindAddressEnv+":?monitoring bind address is required}" {
		return fmt.Errorf("%s published port is not authoritative", service)
	}
	return nil
}

func stringMap(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return typed, true
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[fmt.Sprint(key)] = item
		}
		return result, true
	default:
		return nil, false
	}
}

func secureGrafanaEnvironment(value any) map[string]any {
	environment := map[string]any{}
	if existing, ok := stringMap(value); ok {
		for key, item := range existing {
			environment[key] = item
		}
	} else if list, ok := value.([]any); ok {
		for _, item := range list {
			key, val, found := strings.Cut(fmt.Sprint(item), "=")
			if found {
				environment[key] = val
			}
		}
	}
	for key := range environment {
		if strings.HasPrefix(key, "GF_SECURITY_ADMIN_PASSWORD") {
			delete(environment, key)
		}
	}
	delete(environment, "GF_SECURITY_ADMIN_USER")
	environment["GF_SECURITY_ADMIN_USER"] = grafanaAdminUser
	environment["GF_SECURITY_ADMIN_PASSWORD__FILE"] = grafanaAdminFileTarget
	return environment
}

func secureServicePort(port int) []any {
	return []any{map[string]any{
		"target":    port,
		"published": strconv.Itoa(port),
		"host_ip":   "${" + monitoringBindAddressEnv + ":?monitoring bind address is required}",
	}}
}

func removeSecretVolumeMounts(value any) any {
	list, ok := value.([]any)
	if !ok {
		return value
	}
	filtered := make([]any, 0, len(list))
	for _, item := range list {
		if isPasswordSecretReference(fmt.Sprint(item)) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func parseComposeMajorVersion(output string) (int, error) {
	match := regexp.MustCompile(`(?i)(?:^|[^0-9])v?([0-9]+)\.[0-9]+`).FindStringSubmatch(output)
	if len(match) != 2 {
		return 0, fmt.Errorf("unable to determine Docker Compose version from %q", strings.TrimSpace(output))
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, fmt.Errorf("unable to parse Docker Compose version %q: %w", match[1], err)
	}
	return major, nil
}
