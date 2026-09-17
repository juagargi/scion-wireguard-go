/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird/bwencoding"
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
	EnvHummingbirdEnabled          = "USE_HUMMINGBIRD"
	EnvMarketplaceJWT              = "SCION_MARKETPLACE_JWT"
	EnvMarketplaceInsecure         = "HUMMINGBIRD_MARKETPLACE_INSECURE"
	EnvMarketplaceMaxPrice         = "HUMMINGBIRD_MAX_PRICE"
	EnvHummingbirdBandwidth        = "HUMMINGBIRD_BANDWIDTH"
	EnvHummingbirdReverseBandwidth = "HUMMINGBIRD_REVERSE_BANDWIDTH"
	EnvHummingbirdBidirectional    = "HUMMINGBIRD_BIDIRECTIONAL"
	EnvHummingbirdDuration         = "HUMMINGBIRD_DURATION"
	EnvHummingbirdRenewalAhead     = "HUMMINGBIRD_RENEWAL_AHEAD"
	EnvHummingbirdOverlap          = "HUMMINGBIRD_RESERVATION_OVERLAP"
	EnvHummingbirdStartOffset      = "HUMMINGBIRD_START_OFFSET"
)

// LoadHummingbirdConfigFromEnv reads the Hummingbird configuration from the environment.
// Bandwidths carry a unit (kbps, mbps or gbps),
// and the durations are Go duration strings such as "60s".
func LoadHummingbirdConfigFromEnv() (HummingbirdConfig, error) {
	cfg := DefaultHummingbirdConfig()
	cfg.Enabled = boolEnv(EnvHummingbirdEnabled, false)
	if !cfg.Enabled {
		return cfg, nil
	}

	cfg.JWT = os.Getenv(EnvMarketplaceJWT)
	cfg.Insecure = boolEnv(EnvMarketplaceInsecure, cfg.Insecure)

	if raw := os.Getenv(EnvMarketplaceMaxPrice); raw != "" {
		price, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return cfg, fmt.Errorf("parsing %s: %w", EnvMarketplaceMaxPrice, err)
		}
		cfg.MaxPrice = price
	}

	if raw := os.Getenv(EnvHummingbirdBandwidth); raw != "" {
		bw, err := bwencoding.ParseBandwidth(raw, true)
		if err != nil {
			return cfg, fmt.Errorf("parsing %s: %w", EnvHummingbirdBandwidth, err)
		}
		cfg.BandwidthKbps = bw
	}

	// A reservation is bidirectional unless it is turned off or the reverse
	// bandwidth is given explicitly; by default it mirrors the forward one.
	cfg.ReverseBandwidthKbps = cfg.BandwidthKbps
	if !boolEnv(EnvHummingbirdBidirectional, true) {
		cfg.ReverseBandwidthKbps = 0
	}
	if raw := os.Getenv(EnvHummingbirdReverseBandwidth); raw != "" {
		bw, err := bwencoding.ParseBandwidth(raw, true)
		if err != nil {
			return cfg, fmt.Errorf("parsing %s: %w", EnvHummingbirdReverseBandwidth, err)
		}
		cfg.ReverseBandwidthKbps = bw
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
		// The marketplaces of a local topology serve a self-signed certificate,
		// which no verification can accept.
		Insecure:             true,
		MaxPrice:             math.MaxUint64,
		BandwidthKbps:        defaultBandwidthKbps,
		ReverseBandwidthKbps: defaultBandwidthKbps,
		Duration:             defaultReservationDuration,
		RenewalAhead:         defaultRenewalAhead,
		ReservationOverlap:   defaultReservationOverlap,
		StartOffset:          defaultStartOffset,
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
)

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
