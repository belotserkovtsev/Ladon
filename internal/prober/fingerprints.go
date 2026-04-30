package prober

import (
	utls "github.com/refraction-networking/utls"
)

// Fingerprint identifies which browser ClientHello uTLS should mimic. The
// engine speaks names; lookupHelloID maps them to uTLS preset IDs at probe
// time. Names rather than utls.ClientHelloID values let the config schema
// stay stable across utls version bumps that rename presets.
type Fingerprint string

const (
	// FingerprintChrome120 is the production default. Mimics Chrome 120's
	// ClientHello byte-for-byte (cipher suites order, extensions order,
	// GREASE values, ALPN, key share groups, padding extension). Effective
	// against RU-DPI Chrome-fingerprint blacklists, which is the dominant
	// targeting class as of 2026.
	FingerprintChrome120 Fingerprint = "chrome_120"

	// FingerprintFirefox120 — for deployments where Chrome FP is somehow
	// already-burned by a specific DPI flavour. Less common.
	FingerprintFirefox120 Fingerprint = "firefox_120"

	// FingerprintIOS14 — exact match for iPhone Safari. Use when the
	// operator's traffic mix is dominated by Apple devices and they want
	// the probe to see exactly what those devices see.
	FingerprintIOS14 Fingerprint = "ios_14"

	// FingerprintGoDefault — Go stdlib's tls.Dial fingerprint. The pre-rc5
	// behaviour; kept as an escape hatch for debugging or for hosts where
	// uTLS itself is the problem.
	FingerprintGoDefault Fingerprint = "go_default"
)

// DefaultFingerprint is the value used when probe.tls_fingerprint is not
// set in config. See FingerprintChrome120 for rationale.
const DefaultFingerprint = FingerprintChrome120

// fingerprintMap holds the uTLS preset for each named fingerprint. Add
// new entries when bumping the supported list — config validation refuses
// unknown names against this map.
var fingerprintMap = map[Fingerprint]utls.ClientHelloID{
	FingerprintChrome120:  utls.HelloChrome_120,
	FingerprintFirefox120: utls.HelloFirefox_120,
	FingerprintIOS14:      utls.HelloIOS_14,
	FingerprintGoDefault:  utls.HelloGolang,
}

// lookupHelloID returns the uTLS preset for a given fingerprint name.
// Unknown names fall back to the default — config validation should have
// rejected them at load time, so this fallback is a defence-in-depth net,
// not the expected path.
func lookupHelloID(fp Fingerprint) utls.ClientHelloID {
	if id, ok := fingerprintMap[fp]; ok {
		return id
	}
	return fingerprintMap[DefaultFingerprint]
}

// IsKnownFingerprint reports whether the given name is a recognised
// fingerprint. Used by config.Load to validate probe.tls_fingerprint.
func IsKnownFingerprint(fp Fingerprint) bool {
	_, ok := fingerprintMap[fp]
	return ok
}
