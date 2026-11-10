/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * https://oss.oracle.com/licenses/upl.
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/oracle/coherence-cli/pkg/utils"
	"github.com/spf13/cobra"
)

// ClusterManagement contains endpoint settings, never permission for remote access.
// Explicit tags match both Viper's struct write and mapstructure read paths.
type ClusterManagement struct {
	RESTAddress string `json:"restAddress" yaml:"restaddress" mapstructure:"restaddress"`
	JMXPort     int32  `json:"jmxPort" yaml:"jmxport" mapstructure:"jmxport"`
	JMXAddress  string `json:"jmxAddress" yaml:"jmxaddress" mapstructure:"jmxaddress"`
	JMXHost     string `json:"jmxHost" yaml:"jmxhost" mapstructure:"jmxhost"`
}

const (
	loopbackHostname = "localhost"
	wildcardIPv4     = "0.0.0.0"
)

func managementFlags(cmd *cobra.Command) {
	cmd.Flags().String("management-address", localHost, "Management REST IPv4 bind address (saved after successful startup)")
	cmd.Flags().String("jmx-address", localHost, "JMX IPv4 bind address (requires --jmx-port)")
	cmd.Flags().Bool("allow-insecure-remote-management", false, "acknowledge unauthenticated, unencrypted remote management for this invocation only")
}

func savedManagement(connection ClusterConnection) ClusterManagement {
	m := ClusterManagement{RESTAddress: localHost}
	if connection.Management != nil {
		m = *connection.Management
		if m.RESTAddress == "" {
			m.RESTAddress = localHost
		}
	}
	return m
}

func resolveManagement(cmd *cobra.Command, connection ClusterConnection) (ClusterManagement, error) {
	m := savedManagement(connection)
	if cmd.Flags().Changed("management-address") {
		m.RESTAddress, _ = cmd.Flags().GetString("management-address")
	}
	if cmd.Flags().Changed(jmxPortArg) {
		m.JMXPort, _ = cmd.Flags().GetInt32(jmxPortArg)
	}
	if cmd.Flags().Changed("jmx-address") {
		m.JMXAddress, _ = cmd.Flags().GetString("jmx-address")
	}
	if cmd.Flags().Changed(jmxHostArg) {
		m.JMXHost, _ = cmd.Flags().GetString(jmxHostArg)
	}
	var err error
	if m.RESTAddress, err = managementBind(m.RESTAddress); err != nil {
		return m, fmt.Errorf("--management-address: %w", err)
	}
	if m.JMXPort < 0 {
		return m, fmt.Errorf("--jmx-port must be zero (disabled) or 1024..65535")
	}
	if m.JMXPort == 0 {
		if cmd.Flags().Changed("jmx-address") || cmd.Flags().Changed(jmxHostArg) {
			return m, fmt.Errorf("--jmx-address and --jmx-host require a positive --jmx-port")
		}
		m.JMXAddress, m.JMXHost = "", ""
		return m, nil
	}
	if err = utils.ValidatePort(m.JMXPort); err != nil {
		return m, fmt.Errorf("--jmx-port: %w", err)
	}
	if m.JMXAddress == "" {
		m.JMXAddress = localHost
	}
	if m.JMXAddress, err = managementBind(m.JMXAddress); err != nil {
		return m, fmt.Errorf("--jmx-address: %w", err)
	}
	// An explicit bind change without an explicit host uses the new concrete bind.
	if cmd.Flags().Changed("jmx-address") && !cmd.Flags().Changed(jmxHostArg) && m.JMXAddress != savedManagement(connection).JMXAddress {
		m.JMXHost = ""
	}
	if m.JMXHost == loopbackHostname {
		m.JMXHost = localHost
	}
	if m.JMXHost == "" {
		m.JMXHost = m.JMXAddress
	}
	if !validJMXHost(m.JMXHost) {
		return m, fmt.Errorf("--jmx-host must be a concrete IPv4 address or DNS hostname; wildcard JMX binds require an explicit advertised host")
	}
	if isLoopback(m.JMXAddress) && !isLoopback(m.JMXHost) {
		return m, fmt.Errorf("non-loopback --jmx-host cannot make a loopback listener remote; select --jmx-address and acknowledge --allow-insecure-remote-management")
	}
	return m, nil
}

func managementBind(value string) (string, error) {
	if value == loopbackHostname {
		value = localHost
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil || strings.Contains(value, ":") || ip.IsMulticast() || value == "255.255.255.255" {
		return "", fmt.Errorf("use an IPv4 literal or localhost; DNS, IPv6, multicast and broadcast binds are unsupported")
	}
	return ip.To4().String(), nil
}

func isLoopback(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }

var dnsLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func validJMXHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4() != nil && !strings.Contains(host, ":") && !ip.IsUnspecified() && !ip.IsMulticast() && host != "255.255.255.255"
	}
	if len(host) > 253 || host == "" {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// The asymmetric scale selection is intentional compatibility with existing CLI behavior.
func memberHTTPPort(connection ClusterConnection, addedIndex, existingCount int32, dynamic bool) int32 {
	if addedIndex == 0 {
		if existingCount > 0 {
			return -1
		}
		return connection.ManagementPort
	}
	if dynamic {
		return 0
	}
	return -1
}

func authorizeManagement(cmd *cobra.Command, m ClusterManagement, rest, jmx bool, restPort int32) error {
	var endpoints []string
	if rest && !isLoopback(m.RESTAddress) {
		endpoints = append(endpoints, fmt.Sprintf("Management REST bind %s:%d (dynamic listeners use ephemeral ports)", m.RESTAddress, restPort))
	}
	if jmx && m.JMXPort > 0 && (!isLoopback(m.JMXAddress) || !isLoopback(m.JMXHost)) {
		endpoints = append(endpoints, fmt.Sprintf("JMX bind %s:%d, advertised %s", m.JMXAddress, m.JMXPort, m.JMXHost))
	}
	if len(endpoints) == 0 {
		return nil
	}
	cmd.Printf("WARNING: %s exposes management without authentication or encryption. Other reachable users can control the JVM/cluster.\n", strings.Join(endpoints, "; "))
	allow, _ := cmd.Flags().GetBool("allow-insecure-remote-management")
	if !allow {
		return fmt.Errorf("remote management requires --allow-insecure-remote-management on each invocation, including --yes")
	}
	return nil
}

func managementURL(m ClusterManagement, port int32) string {
	host := m.RESTAddress
	if host == wildcardIPv4 {
		host = localHost
	}
	return fmt.Sprintf("http://%s:%d/management/coherence/cluster", host, port)
}

var listenManagementEndpoint = net.Listen

// The saved URL identifies the reachable REST address for legacy/wildcard
// records. It does not establish that every address overlapping a wildcard is
// occupied by this cluster. Do not resolve arbitrary DNS names for exemptions.
func existingRESTAddress(connection ClusterConnection) string {
	old := savedManagement(connection)
	if connection.Management != nil && old.RESTAddress != wildcardIPv4 {
		return old.RESTAddress
	}
	u, err := url.Parse(connection.ConnectionURL)
	if err != nil || u.Port() != strconv.Itoa(int(connection.ManagementPort)) {
		return ""
	}
	address, err := managementBind(u.Hostname())
	if err != nil || address == wildcardIPv4 {
		return ""
	}
	return address
}

// Probe addresses and fixed endpoints without reserving them; startup must
// still handle races. Only an expected old endpoint's address-in-use error is
// tolerated during restart, after independently checking local bind usability.
func checkManagementPorts(connection ClusterConnection, m ClusterManagement, replacing bool) error {
	return checkManagementPortsContext(context.Background(), connection, m, replacing)
}

func checkManagementPortsContext(ctx context.Context, connection ClusterConnection, m ClusterManagement, replacing bool) error {
	old := savedManagement(connection)
	endpoints := []struct {
		address  string
		port     int32
		name     string
		existing bool
	}{{m.RESTAddress, connection.ManagementPort, "Management REST", m.RESTAddress == existingRESTAddress(connection) ||
		connection.Management != nil && m.RESTAddress == old.RESTAddress}}
	if m.JMXPort > 0 {
		endpoints = append(endpoints, struct {
			address  string
			port     int32
			name     string
			existing bool
		}{m.JMXAddress, m.JMXPort, "JMX", m.JMXPort == old.JMXPort && m.JMXAddress == old.JMXAddress})
	}
	for _, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			return err
		}
		// A fixed port may legitimately be busy, but its address must still be
		// usable locally before any existing member is stopped.
		probe, err := listenManagementEndpoint("tcp4", net.JoinHostPort(endpoint.address, "0"))
		if err != nil {
			return fmt.Errorf("%s bind address %s is unavailable; choose an available local address: %w", endpoint.name, endpoint.address, err)
		}
		if err := probe.Close(); err != nil {
			return fmt.Errorf("close %s bind probe at %s: %w", endpoint.name, endpoint.address, err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		address := net.JoinHostPort(endpoint.address, strconv.Itoa(int(endpoint.port)))
		listener, err := listenManagementEndpoint("tcp4", address)
		if err != nil {
			if replacing && endpoint.existing && errors.Is(err, errManagementAddressInUse) {
				continue
			}
			return fmt.Errorf("%s endpoint %s is unavailable; choose an available local address/port: %w", endpoint.name, address, err)
		}
		if err := listener.Close(); err != nil {
			return fmt.Errorf("close %s endpoint probe at %s: %w", endpoint.name, address, err)
		}
	}
	return ctx.Err()
}

// splitJVMOptions handles quoted whitespace without shell expansion or execution.
func splitJVMOptions(value string) ([]string, error) {
	var result []string
	var b strings.Builder
	var quote rune
	active := false
	for _, c := range value {
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				b.WriteRune(c)
			}
		} else if c == '\'' || c == '"' {
			quote = c
			active = true
		} else if unicode.IsSpace(c) {
			if active {
				result = append(result, b.String())
				b.Reset()
				active = false
			}
		} else {
			b.WriteRune(c)
			active = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in JVM options")
	}
	if active {
		result = append(result, b.String())
	}
	return result, nil
}

// savedJVMOptions preserves the literal space-delimited format of legacy
// records. managedConnection writes quoted arguments and Management together;
// only those records use the quoted format. Reading never migrates a record.
func savedJVMOptions(connection ClusterConnection) ([]string, error) {
	if connection.Management == nil {
		return strings.Split(connection.Arguments, " "), nil
	}
	return splitJVMOptions(connection.Arguments)
}

func controlledManagementProperty(arg string) bool {
	key, _, _ := strings.Cut(strings.TrimPrefix(arg, "-D"), "=")
	if strings.HasPrefix(key, "tangosol.coherence.") {
		key = strings.TrimPrefix(key, "tangosol.")
	} else if strings.HasPrefix(key, "tangosol.management.") {
		key = "coherence." + strings.TrimPrefix(key, "tangosol.")
	}
	return key == "com.sun.management.jmxremote" || strings.HasPrefix(key, "com.sun.management.jmxremote.") ||
		key == "com.sun.management.config.file" || key == "com.sun.management.agent.class" || key == "java.rmi.server.hostname" ||
		key == "coherence.management.http" || key == "coherence.management.http.address" || key == "coherence.management.http.port" ||
		// Retained pending supported-release consumer evidence; do not infer a file loader.
		key == "coherence.management.config"
}

// Only the exact hostname generated by the old create command is migrated, only
// on legacy server records. Console/CohQL and unrelated properties are untouched.
func serverBaseOptions(connection ClusterConnection) ([]string, error) {
	args, err := savedJVMOptions(connection)
	if err != nil {
		return nil, err
	}
	wka := ""
	for _, arg := range args {
		if strings.HasPrefix(arg, "-Dcoherence.wka=") {
			wka = strings.TrimPrefix(arg, "-Dcoherence.wka=")
		}
	}
	var result []string
	migrated := false
	for _, arg := range args {
		// Empty legacy separators are not JVM options. Clients retain the exact
		// old token sequence; managed server validation operates on options.
		if arg == "" && connection.Management == nil {
			continue
		}
		if !migrated && connection.Management == nil && connection.ManuallyCreated && wka != "" && arg == "-Djava.rmi.server.hostname="+wka {
			migrated = true
			continue
		}
		result = append(result, arg)
	}
	return result, nil
}

const (
	jvmAddOpensOption     = "--add-opens"
	jvmAddExportsOption   = "--add-exports"
	jvmAddReadsOption     = "--add-reads"
	jvmAddModulesOption   = "--add-modules"
	jvmLimitModulesOption = "--limit-modules"
)

// Environment options use ASCII whitespace and matching quotes in the qualified
// JDKs. Backslashes and non-ASCII bytes are literal; there is no shell expansion.
// Saved/profile parsing deliberately retains splitJVMOptions semantics.
func splitJVMEnvironmentOptions(value string) ([]string, error) {
	var result []string
	var b strings.Builder
	var quote byte
	active := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				b.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote, active = c, true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			if active {
				result = append(result, b.String())
				b.Reset()
				active = false
			}
		default:
			b.WriteByte(c)
			active = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in JVM environment options")
	}
	if active {
		result = append(result, b.String())
	}
	return result, nil
}

// This finite table describes launcher consumption, not module/path validity.
// Long attached values are VM inputs; only split forms need a launcher version.
func managedLauncherOperand(option string) (minimum int, emptyAllowed bool) {
	switch option {
	case "-cp", "-classpath":
		return 1, true
	case "--class-path":
		return 9, true
	case jvmAddOpensOption, jvmAddExportsOption, jvmAddReadsOption, jvmAddModulesOption, jvmLimitModulesOption,
		"-p", "--module-path", "--upgrade-module-path", "--patch-module", "-d", "--describe-module":
		return 9, false
	case "--enable-native-access":
		return 17, false
	default:
		return 0, false
	}
}

func indirectManagementOption(arg string) bool {
	flag := strings.TrimPrefix(arg, "-XX:")
	if strings.HasPrefix(flag, "+") || strings.HasPrefix(flag, "-") {
		flag = flag[1:]
	}
	flag, _, _ = strings.Cut(flag, "=")
	return strings.HasPrefix(arg, "@") || strings.HasPrefix(arg, "-XX:VMOptionsFile=") || strings.HasPrefix(arg, "-XX:Flags=") ||
		strings.HasPrefix(arg, "-XX:") && flag == "ManagementServer" ||
		arg == "-Xmanagement" || strings.HasPrefix(arg, "-Xmanagement:") || strings.HasPrefix(arg, "-Xoptionsfile=")
}

// Server option validation controls stock management and the launch boundary.
// User code, agents, replacement resources and installed runtimes are trusted,
// not sandboxed here.
func validateServerOptions(source string, args []string, launcher bool) (int, error) {
	// Inspect raw tokens before consuming operands. In particular, a malformed
	// VM-only split option must not hide the next reserved property or @file.
	for _, arg := range args {
		if strings.ContainsRune(arg, 0) {
			return 0, fmt.Errorf("%s contains NUL in JVM options", source)
		}
		if strings.HasPrefix(arg, "-D") && controlledManagementProperty(arg) {
			key, _, _ := strings.Cut(arg, "=")
			return 0, fmt.Errorf("%s contains reserved management property %s; use --management-address/--jmx-port/--jmx-address/--jmx-host instead", source, key)
		}
		if indirectManagementOption(arg) {
			return 0, fmt.Errorf("%s contains a direct management switch or uninspected JVM option source; use endpoint flags and explicit options", source)
		}
		if arg == "-jar" || arg == "-m" || arg == "--module" || strings.HasPrefix(arg, "--module=") ||
			arg == "--source" || strings.HasPrefix(arg, "--source=") || strings.HasPrefix(arg, "--source") && strings.Contains(arg, " ") {
			return 0, fmt.Errorf("%s contains a launch target override; the CLI must select the server main class", source)
		}
	}
	requiredMajor := 0
	remaining := args
	for len(remaining) > 0 {
		arg := remaining[0]
		remaining = remaining[1:]
		if !strings.HasPrefix(arg, "-") {
			return 0, fmt.Errorf("%s contains an unclaimed JVM operand at token %d; unknown split options are unsupported, use an attached spelling if the JVM supports it", source, len(args)-len(remaining))
		}
		option, operand, attached := strings.Cut(arg, "=")
		minimum, emptyAllowed := managedLauncherOperand(option)
		if minimum == 0 || attached && !strings.HasPrefix(option, "--") {
			continue
		}
		if !attached {
			if !launcher {
				return 0, fmt.Errorf("%s: %s requires an attached value; this variable supplies VM options, not launcher operands", source, option)
			}
			if len(remaining) == 0 {
				return 0, fmt.Errorf("%s: %s requires a separate operand", source, option)
			}
			operand = remaining[0]
			remaining = remaining[1:]
			if strings.HasPrefix(operand, "-") {
				return 0, fmt.Errorf("%s: %s requires an operand that does not start with '-'", source, option)
			}
			if minimum > 1 {
				requiredMajor = max(requiredMajor, minimum)
			}
		}
		if operand == "" && !emptyAllowed {
			return 0, fmt.Errorf("%s: %s requires a nonempty operand", source, option)
		}
	}
	return requiredMajor, nil
}

func validateManagedOptions(connection ClusterConnection) (int, error) {
	args, err := serverBaseOptions(connection)
	if err != nil {
		return 0, err
	}
	requiredMajor, err := validateServerOptions("saved server arguments", args, true)
	if err != nil {
		return 0, err
	}
	profile, err := splitJVMOptions(getProfileValue(profileValueParam))
	if err != nil {
		return 0, err
	}
	profileMajor, err := validateServerOptions("startup profile", profile, true)
	if err != nil {
		return 0, err
	}
	requiredMajor = max(requiredMajor, profileMajor)
	for _, name := range []string{"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"} {
		options, err := splitJVMEnvironmentOptions(os.Getenv(name))
		if err != nil {
			return 0, fmt.Errorf("%s: %w", name, err)
		}
		major, err := validateServerOptions(name, options, name == "JDK_JAVA_OPTIONS")
		if err != nil {
			return 0, err
		}
		requiredMajor = max(requiredMajor, major)
	}
	return requiredMajor, nil
}

func preflightManagedStartup(cmd *cobra.Command, connection ClusterConnection, count, existing int32, scale bool) (ClusterManagement, error) {
	m, err := resolveManagement(cmd, connection)
	if err != nil {
		return m, err
	}
	if scale && m != savedManagement(connection) {
		return m, fmt.Errorf("scale cannot change management endpoints; use restart cluster")
	}
	if count < 1 {
		return m, fmt.Errorf("replica count must be 1 or more")
	}
	if err = utils.ValidatePort(connection.ManagementPort); err != nil {
		return m, err
	}
	if err = validateLogLevel(logLevelParam); err != nil {
		return m, err
	}
	if err = utils.ValidateStartClass(serverStartClassParam); err != nil {
		return m, err
	}
	if err = validateProfile(); err != nil {
		return m, err
	}
	if _, err = utils.GetStartupDelayInMillis(startupDelayParam); err != nil {
		return m, err
	}
	requiredMajor, err := validateManagedOptions(connection)
	if err != nil {
		return m, err
	}
	ports := map[int32]string{}
	reserve := func(port int32, label string) error {
		if err := utils.ValidatePort(port); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if prior, found := ports[port]; found {
			return fmt.Errorf("port %d conflicts between %s and %s", port, prior, label)
		}
		ports[port] = label
		return nil
	}
	baseOptions, _ := serverBaseOptions(connection) // validated above
	for _, option := range baseOptions {
		if strings.HasPrefix(option, "-Dcoherence.clusterport=") {
			port, parseErr := strconv.ParseInt(strings.TrimPrefix(option, "-Dcoherence.clusterport="), 10, 32)
			if parseErr != nil {
				return m, fmt.Errorf("invalid saved cluster port: %w", parseErr)
			}
			if err = reserve(int32(port), "cluster discovery"); err != nil {
				return m, err
			}
		}
	}
	if existing == 0 {
		if err = reserve(connection.ManagementPort, "Management REST"); err != nil {
			return m, err
		}
		if m.JMXPort > 0 {
			if err = reserve(m.JMXPort, "JMX"); err != nil {
				return m, err
			}
		}
	} else {
		// Existing fixed listeners must not collide with new metrics/health ports.
		ports[connection.ManagementPort] = "existing Management REST"
		if m.JMXPort > 0 {
			ports[m.JMXPort] = "existing JMX"
		}
	}
	for i := int32(0); i < count; i++ {
		for _, p := range []struct {
			start int32
			name  string
		}{{metricsStartPortParam, "metrics"}, {healthStartPortParam, healthPanelData}} {
			if p.start < 0 {
				return m, fmt.Errorf("%s port cannot be negative", p.name)
			}
			if p.start > 0 {
				port := int64(p.start) + int64(i)
				if port > 65535 {
					return m, fmt.Errorf("%s port range exceeds 65535", p.name)
				}
				if err = reserve(int32(port), p.name+" member "+strconv.Itoa(int(i))); err != nil {
					return m, err
				}
			}
		}
	}
	if err = authorizeManagement(cmd, m, existing == 0 || dynamicHTTPParam && count > 1, existing == 0, connection.ManagementPort); err != nil {
		return m, err
	}
	if err = checkManagedRuntime(connection.ClusterVersion, requiredMajor); err != nil {
		return m, err
	}
	return m, nil
}
