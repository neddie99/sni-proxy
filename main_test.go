package main

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseHTTPAuthorityUsesHostHeader(t *testing.T) {
	initial := []byte("GET / HTTP/1.1\r\nHost: Example.COM:8080\r\nUser-Agent: test\r\n\r\n")

	authority, err := parseHTTPAuthority(initial)
	if err != nil {
		t.Fatalf("parseHTTPAuthority returned an error: %v", err)
	}
	if authority != "Example.COM:8080" {
		t.Fatalf("authority = %q, want %q", authority, "Example.COM:8080")
	}

	target, serverName, err := buildTargetAddress(authority, defaultHTTPPort)
	if err != nil {
		t.Fatalf("buildTargetAddress returned an error: %v", err)
	}
	if target != "example.com:8080" {
		t.Fatalf("target = %q, want %q", target, "example.com:8080")
	}
	if serverName != "example.com" {
		t.Fatalf("serverName = %q, want %q", serverName, "example.com")
	}
}

func TestParseHTTPAuthorityUsesAbsoluteURL(t *testing.T) {
	initial := []byte("GET http://example.org/path HTTP/1.0\r\nUser-Agent: test\r\n\r\n")

	authority, err := parseHTTPAuthority(initial)
	if err != nil {
		t.Fatalf("parseHTTPAuthority returned an error: %v", err)
	}
	if authority != "example.org" {
		t.Fatalf("authority = %q, want %q", authority, "example.org")
	}
}

func TestReadTLSClientHelloExtractsSNI(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan error, 1)
	go func() {
		tlsClient := tls.Client(clientConn, &tls.Config{
			ServerName:         "Example.COM",
			InsecureSkipVerify: true,
		})
		done <- tlsClient.Handshake()
	}()

	if err := serverConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline returned an error: %v", err)
	}

	serverName, initial, err := readTLSClientHello(serverConn, maxTLSHelloSize)
	if err != nil {
		t.Fatalf("readTLSClientHello returned an error: %v", err)
	}
	if serverName != "example.com" {
		t.Fatalf("serverName = %q, want %q", serverName, "example.com")
	}
	if len(initial) == 0 {
		t.Fatal("initial bytes are empty")
	}

	_ = serverConn.Close()
	<-done
}

func TestParseYAMLConfigReadsLogLevelAndHosts(t *testing.T) {
	cfg, err := parseYAMLConfig([]byte("# Test configuration\nlog_level: \"debug\" # request logs\nhosts:\n  Example.COM.: 203.0.113.10\n  ipv6.example.com: \"2001:db8::10\"\nip_family:\n  Example.COM.: ipv4\n  ipv6.example.com: ipv6\n"))
	if err != nil {
		t.Fatalf("parseYAMLConfig returned an error: %v", err)
	}
	if cfg.LogLevel != levelDebug {
		t.Fatalf("LogLevel = %v, want %v", cfg.LogLevel, levelDebug)
	}
	if cfg.Hosts["example.com"] != "203.0.113.10" {
		t.Fatalf("Hosts[example.com] = %q, want %q", cfg.Hosts["example.com"], "203.0.113.10")
	}
	if cfg.Hosts["ipv6.example.com"] != "2001:db8::10" {
		t.Fatalf("Hosts[ipv6.example.com] = %q, want %q", cfg.Hosts["ipv6.example.com"], "2001:db8::10")
	}
	if cfg.IPFamilies["example.com"] != familyIPv4 {
		t.Fatalf("IPFamilies[example.com] = %v, want %v", cfg.IPFamilies["example.com"], familyIPv4)
	}
	if cfg.IPFamilies["ipv6.example.com"] != familyIPv6 {
		t.Fatalf("IPFamilies[ipv6.example.com] = %v, want %v", cfg.IPFamilies["ipv6.example.com"], familyIPv6)
	}
}

func TestParseYAMLConfigRejectsUnsupportedKeys(t *testing.T) {
	_, err := parseYAMLConfig([]byte("log_level: info\nlisten: :8080\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "unsupported configuration key") {
		t.Fatalf("error = %q, want unsupported key error", err.Error())
	}
}

func TestParseYAMLConfigRejectsNonIPHostsValue(t *testing.T) {
	_, err := parseYAMLConfig([]byte("hosts:\n  example.com: upstream.example.net\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "must be an IP address") {
		t.Fatalf("error = %q, want IP address error", err.Error())
	}
}

func TestParseYAMLConfigRejectsInvalidIPFamily(t *testing.T) {
	_, err := parseYAMLConfig([]byte("ip_family:\n  example.com: auto\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "supported values are ipv4 and ipv6") {
		t.Fatalf("error = %q, want supported values error", err.Error())
	}
}

func TestParseYAMLConfigRejectsHostsAndIPFamilyMismatch(t *testing.T) {
	_, err := parseYAMLConfig([]byte("hosts:\n  example.com: 203.0.113.10\nip_family:\n  example.com: ipv6\n"))
	if err == nil {
		t.Fatal("parseYAMLConfig returned nil error")
	}
	if !strings.Contains(err.Error(), "conflicts with ip_family") {
		t.Fatalf("error = %q, want conflict error", err.Error())
	}
}

func TestResolveRouteTargetUsesHostOverride(t *testing.T) {
	route, err := resolveRouteTarget(
		"example.com:8443",
		"example.com",
		config{
			Hosts:      map[string]string{"example.com": "203.0.113.10"},
			IPFamilies: map[string]ipFamily{},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if !route.HostsOverridden {
		t.Fatal("HostsOverridden = false, want true")
	}
	if route.DialTarget != "203.0.113.10:8443" {
		t.Fatalf("DialTarget = %q, want %q", route.DialTarget, "203.0.113.10:8443")
	}
	if route.Network != "tcp" {
		t.Fatalf("Network = %q, want %q", route.Network, "tcp")
	}
}

func TestResolveRouteTargetSupportsIPv6HostOverride(t *testing.T) {
	route, err := resolveRouteTarget(
		"ipv6.example.com:443",
		"ipv6.example.com",
		config{
			Hosts:      map[string]string{"ipv6.example.com": "2001:db8::10"},
			IPFamilies: map[string]ipFamily{},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if !route.HostsOverridden {
		t.Fatal("HostsOverridden = false, want true")
	}
	if route.DialTarget != "[2001:db8::10]:443" {
		t.Fatalf("DialTarget = %q, want %q", route.DialTarget, "[2001:db8::10]:443")
	}
}

func TestResolveRouteTargetKeepsOriginalWhenHostIsMissing(t *testing.T) {
	route, err := resolveRouteTarget(
		"example.com:443",
		"example.com",
		config{
			Hosts:      map[string]string{"other.example.com": "203.0.113.10"},
			IPFamilies: map[string]ipFamily{},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if route.HostsOverridden {
		t.Fatal("HostsOverridden = true, want false")
	}
	if route.DialTarget != "example.com:443" {
		t.Fatalf("DialTarget = %q, want %q", route.DialTarget, "example.com:443")
	}
}

func TestResolveRouteTargetUsesForcedIPv4(t *testing.T) {
	route, err := resolveRouteTarget(
		"example.com:443",
		"Example.COM.",
		config{
			Hosts:      map[string]string{},
			IPFamilies: map[string]ipFamily{"example.com": familyIPv4},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if route.Network != "tcp4" {
		t.Fatalf("Network = %q, want %q", route.Network, "tcp4")
	}
	if route.DialTarget != "example.com:443" {
		t.Fatalf("DialTarget = %q, want %q", route.DialTarget, "example.com:443")
	}
}

func TestResolveRouteTargetUsesForcedIPv6WithHostOverride(t *testing.T) {
	route, err := resolveRouteTarget(
		"ipv6.example.com:443",
		"ipv6.example.com",
		config{
			Hosts:      map[string]string{"ipv6.example.com": "2001:db8::10"},
			IPFamilies: map[string]ipFamily{"ipv6.example.com": familyIPv6},
		},
	)
	if err != nil {
		t.Fatalf("resolveRouteTarget returned an error: %v", err)
	}
	if route.Network != "tcp6" {
		t.Fatalf("Network = %q, want %q", route.Network, "tcp6")
	}
	if route.DialTarget != "[2001:db8::10]:443" {
		t.Fatalf("DialTarget = %q, want %q", route.DialTarget, "[2001:db8::10]:443")
	}
}
