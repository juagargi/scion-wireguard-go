/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	humm "github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/hummingbird/bwencoding"
	"github.com/scionproto/scion/private/path/pathpol"
)

const (
	DefaultSCIONDaemonAddr = "127.0.0.1:30255"
)

func GetScionAddress() string {
	cmd := exec.Command("scion", "address")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// LoadScionConfigFromEnv loads SCION configuration from environment variables
func LoadScionConfigFromEnv() (*ScionConfig, error) {
	config := &ScionConfig{
		DaemonAddr: DefaultSCIONDaemonAddr,
		PathPolicy: PathPolicyShortest,
	}

	// Load daemon address from environment
	if addr := os.Getenv(EnvSCIONDaemonAddr); addr != "" {
		config.DaemonAddr = addr
	}

	// Load path policy from environment
	if policy := os.Getenv(EnvSCIONPathPolicy); policy != "" {
		config.PathPolicy = ParsePathPolicy(policy)
	}

	if raw := os.Getenv(EnvSCIONPathAPIAddress); raw != "" {
		if err := ParseAPIAddress(raw); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", EnvSCIONPathAPIAddress, err)
		}
		config.APIAddress = raw
	}

	// Try to get SCION address from scion command first, then fallback to environment
	scionAddress := GetScionAddress()
	if scionAddress == "" {
		scionAddress = os.Getenv(EnvSCIONLocalIA)
	}

	if scionAddress == "" {
		return nil, fmt.Errorf("SCION configuration not found: neither scion command nor %s environment variable available", EnvSCIONLocalIA)
	}

	// Parse SCION address into IA and IP
	parts := strings.Split(scionAddress, ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid SCION address format %q: expected ISD-AS,IP", scionAddress)
	}

	// Parse ISD-AS
	ia, err := addr.ParseIA(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid ISD-AS in SCION address %q: %w", scionAddress, err)
	}

	// Parse IP address
	localIP := net.ParseIP(parts[1])
	if localIP == nil {
		return nil, fmt.Errorf("invalid IP address in SCION address %q", scionAddress)
	}

	config.LocalIP = localIP
	config.LocalIA = ia

	humm, err := LoadHummingbirdConfigFromEnv()
	if err != nil {
		return nil, err
	}
	config.Hummingbird = humm

	return config, nil
}

// Environment variables configuring the Hummingbird reservations.
const (
	EnvMarketplaceJWT              = "SCION_MARKETPLACE_JWT"
	EnvMarketplaceInsecure         = "HUMMINGBIRD_MARKETPLACE_INSECURE"
	EnvMarketplaceMaxPrice         = "HUMMINGBIRD_MAX_PRICE"
	EnvHummingbirdBandwidth        = "HUMMINGBIRD_BANDWIDTH"
	EnvHummingbirdReverseBandwidth = "HUMMINGBIRD_REVERSE_BANDWIDTH"
	EnvHummingbirdDuration         = "HUMMINGBIRD_DURATION"
	EnvHummingbirdRenewalAhead     = "HUMMINGBIRD_RENEWAL_AHEAD"
	EnvHummingbirdOverlap          = "HUMMINGBIRD_RESERVATION_OVERLAP"
	EnvHummingbirdStartOffset      = "HUMMINGBIRD_START_OFFSET"

	EnvHummingbirdPathToMarketplaceFilter = "HUMMINGBIRD_PATH_TO_MARKETPLACE_FILTER"
	EnvHummingbirdPartial                 = "HUMMINGBIRD_PARTIAL"

	// EnvHummingbirdMarketplaceAddress is the SCION API address of the marketplace every
	// reservation is bought from, e.g. [71-2:0:5c,127.0.0.1]:31888. The Notes of the path are
	// then not consulted.
	EnvHummingbirdMarketplaceAddress = "HUMMINGBIRD_MARKETPLACE_ADDRESS"
)

// ParseMarketplaceAddress validates the address of a marketplace: either a SCION address
// [ISD-AS,host]:port, or an http:// or https:// URL, which is reached over TCP.
// A bare host:port is rejected: the marketplace client needs the scheme to reach it.
func ParseMarketplaceAddress(raw string) error {
	if strings.ContainsAny(raw, " \t\r\n") {
		return fmt.Errorf("address %q contains whitespace", raw)
	}
	hostPort := raw
	if scheme, rest, ok := strings.Cut(raw, "://"); ok {
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("unsupported scheme %q in %q", scheme, raw)
		}
		hostPort, _, _ = strings.Cut(rest, "/")
	} else if !strings.HasPrefix(raw, "[") {
		return fmt.Errorf("address %q is neither a SCION address [ISD-AS,host]:port nor "+
			"an http(s):// URL", raw)
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return err
	}
	if p, err := strconv.ParseUint(port, 10, 16); err != nil || p == 0 {
		return fmt.Errorf("invalid port %q", port)
	}
	if host == "" {
		return fmt.Errorf("missing host in %q", raw)
	}
	if ia, ip, ok := strings.Cut(host, ","); ok {
		if _, err := addr.ParseIA(ia); err != nil {
			return fmt.Errorf("invalid ISD-AS in %q: %w", raw, err)
		}
		if ip == "" {
			return fmt.Errorf("missing host in SCION address %q", raw)
		}
	} else if !strings.Contains(raw, "://") {
		return fmt.Errorf("SCION address %q lacks the ISD-AS: expected [ISD-AS,host]:port", raw)
	}
	return nil
}

// LoadHummingbirdConfigFromEnv reads the Hummingbird configuration from the environment.
// Bandwidths carry a unit (kbps, mbps or gbps),
// and the durations are Go duration strings such as "60s".
func LoadHummingbirdConfigFromEnv() (HummingbirdConfig, error) {
	cfg := DefaultHummingbirdConfig()

	// Hummingbird is requested by giving a forward bandwidth.
	// Otherwise the tunnel travels on best-effort SCION paths and no marketplace is ever contacted.
	rawBandwidth := os.Getenv(EnvHummingbirdBandwidth)
	if rawBandwidth == "" {
		if os.Getenv(EnvHummingbirdMarketplaceAddress) != "" {
			log.Printf("Warning: %s is ignored, Hummingbird is disabled because %s is unset",
				EnvHummingbirdMarketplaceAddress, EnvHummingbirdBandwidth)
		}
		return cfg, nil
	}
	cfg.Enabled = true

	bw, err := bwencoding.ParseBandwidth(rawBandwidth, true)
	if err != nil {
		return cfg, fmt.Errorf("parsing %s: %w", EnvHummingbirdBandwidth, err)
	}
	cfg.BandwidthKbps = bw

	cfg.JWT = os.Getenv(EnvMarketplaceJWT)
	cfg.Insecure = boolEnv(EnvMarketplaceInsecure, cfg.Insecure)

	if raw := os.Getenv(EnvHummingbirdPartial); raw != "" {
		partial, err := humm.ParseASFilter(raw)
		if err != nil {
			return cfg, fmt.Errorf("parsing %s: %w", EnvHummingbirdPartial, err)
		}
		cfg.Partial = partial
	}

	if raw := os.Getenv(EnvHummingbirdPathToMarketplaceFilter); raw != "" {
		sequence, err := pathpol.NewSequence(raw)
		if err != nil {
			return cfg, fmt.Errorf("parsing %s: %w", EnvHummingbirdPathToMarketplaceFilter, err)
		}
		cfg.PathToMarketplace = sequence
	}

	if raw := os.Getenv(EnvHummingbirdMarketplaceAddress); raw != "" {
		if err := ParseMarketplaceAddress(raw); err != nil {
			return cfg, fmt.Errorf("parsing %s: %w", EnvHummingbirdMarketplaceAddress, err)
		}
		cfg.MarketplaceAddress = raw
	}

	if raw := os.Getenv(EnvMarketplaceMaxPrice); raw != "" {
		price, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return cfg, fmt.Errorf("parsing %s: %w", EnvMarketplaceMaxPrice, err)
		}
		cfg.MaxPrice = price
	}

	// The reverse direction is reserved only when a reverse bandwidth is given;
	// by default the reservation is unidirectional.
	if raw := os.Getenv(EnvHummingbirdReverseBandwidth); raw != "" {
		bw, err := bwencoding.ParseBandwidth(raw, true)
		if err != nil {
			return cfg, fmt.Errorf("parsing %s: %w", EnvHummingbirdReverseBandwidth, err)
		}
		cfg.ReverseBandwidthKbps = bw
	}

	// The reservation duration has no default: it must be given explicitly.
	if os.Getenv(EnvHummingbirdDuration) == "" {
		return cfg, fmt.Errorf("hummingbird requested but no %s provided", EnvHummingbirdDuration)
	}

	durations := []struct {
		env    string
		target *time.Duration
	}{
		{EnvHummingbirdDuration, &cfg.Duration},
		{EnvHummingbirdRenewalAhead, &cfg.RenewalAhead},
		{EnvHummingbirdOverlap, &cfg.ReservationOverlap},
		{EnvHummingbirdStartOffset, &cfg.StartOffset},
	}
	for _, d := range durations {
		raw := os.Getenv(d.env)
		if raw == "" {
			continue
		}
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return cfg, fmt.Errorf("parsing %s: %w", d.env, err)
		}
		*d.target = parsed
	}

	return cfg, cfg.Validate()
}

// DefaultHummingbirdConfig returns the disabled Hummingbird configuration.
func DefaultHummingbirdConfig() HummingbirdConfig {
	return HummingbirdConfig{
		MaxPrice:           math.MaxUint64,
		RenewalAhead:       defaultRenewalAhead,
		ReservationOverlap: defaultReservationOverlap,
		StartOffset:        defaultStartOffset,
	}
}

// boolEnv reads a boolean environment variable, falling back to def when unset or wrong.
func boolEnv(name string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

// ValidateConfig validates the SCION configuration
func (c *ScionConfig) ValidateConfig() error {
	if c.LocalIA.IsZero() {
		return fmt.Errorf("LocalIA cannot be zero")
	}

	if c.DaemonAddr == "" {
		return fmt.Errorf("DaemonAddr cannot be empty")
	}

	return c.Hummingbird.Validate()
}

// String returns a string representation of the configuration
func (c *ScionConfig) String() string {
	return fmt.Sprintf("ScionConfig{LocalIA: %s, DaemonAddr: %s, PathPolicy: %s}",
		c.LocalIA, c.DaemonAddr, c.PathPolicy)
}

// DefaultScionConfig returns a default SCION configuration
func DefaultScionConfig() *ScionConfig {
	return &ScionConfig{
		DaemonAddr:  DefaultSCIONDaemonAddr,
		PathPolicy:  PathPolicyFirst,
		Hummingbird: DefaultHummingbirdConfig(),
	}
}

// ParseIA parses an IA string in the format "ISD-AS"
func ParseIA(s string) (addr.IA, error) {
	return addr.ParseIA(s)
}

// FormatIA formats an IA to string
func FormatIA(ia addr.IA) string {
	return ia.String()
}

// Environment variable names for SCION configuration
const (
	EnvSCIONDaemonAddr = "SCION_DAEMON_ADDRESS"
	EnvSCIONLocalIA    = "SCION_LOCAL_IA"
	EnvSCIONTopology   = "SCION_TOPOLOGY_FILE"
	EnvSCIONPathPolicy = "SCION_PATH_POLICY"

	// EnvSCIONPathAPIAddress is the host:port the path manager API listens on, e.g. 127.0.0.1:28016.
	// Unset, the API listens on :28015 or, if taken, on 28016 or 28017.
	EnvSCIONPathAPIAddress = "SCION_PATH_API_ADDRESS"
)

// ParseAPIAddress validates a host:port as net.Listen takes it. The host may be empty.
func ParseAPIAddress(raw string) error {
	_, port, err := net.SplitHostPort(raw)
	if err != nil {
		return err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

// GetConfigSummary returns a summary of current SCION configuration
func GetConfigSummary() string {
	var parts []string

	if addr := os.Getenv(EnvSCIONDaemonAddr); addr != "" {
		parts = append(parts, fmt.Sprintf("DaemonAddr=%s", addr))
	}

	if ia := os.Getenv(EnvSCIONLocalIA); ia != "" {
		parts = append(parts, fmt.Sprintf("LocalIA=%s", ia))
	}

	if policy := os.Getenv(EnvSCIONPathPolicy); policy != "" {
		parts = append(parts, fmt.Sprintf("PathPolicy=%s", policy))
	}

	if len(parts) == 0 {
		return "No SCION configuration found"
	}

	return strings.Join(parts, ", ")
}
