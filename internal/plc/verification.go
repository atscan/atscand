package plc

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"
)

// CacheMetadata contains verification information for cached data
type CacheMetadata struct {
	FetchedAt        time.Time         `json:"fetched_at"`
	SourceURL        string            `json:"source_url"`
	TLSVerified      bool              `json:"tls_verified"`
	TLSVersion       string            `json:"tls_version"`
	CipherSuite      string            `json:"cipher_suite"`
	ServerName       string            `json:"server_name"`
	PeerCertificates []CertificateInfo `json:"peer_certificates"`
	DataHash         string            `json:"data_hash"` // SHA256 of the raw response
	OperationCount   int               `json:"operation_count"`
	FirstOperation   string            `json:"first_operation_cid"`
	LastOperation    string            `json:"last_operation_cid"`
}

// CertificateInfo contains relevant certificate details
type CertificateInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	DNSNames     []string  `json:"dns_names"`
	Fingerprint  string    `json:"fingerprint"` // SHA256 fingerprint
	SerialNumber string    `json:"serial_number"`
}

// VerificationResult contains the result of verifying cached data
type VerificationResult struct {
	Valid            bool
	Errors           []string
	Warnings         []string
	TLSCertsValid    bool
	DataHashMatches  bool
	OperationCountOK bool
}

// extractTLSInfo extracts TLS connection information
func extractTLSInfo(connState *tls.ConnectionState, serverName string) *CacheMetadata {
	if connState == nil {
		return nil
	}

	metadata := &CacheMetadata{
		FetchedAt:   time.Now(),
		TLSVerified: true,
		TLSVersion:  tlsVersionString(connState.Version),
		CipherSuite: tls.CipherSuiteName(connState.CipherSuite),
		ServerName:  serverName,
	}

	// Extract peer certificates
	for _, cert := range connState.PeerCertificates {
		certInfo := CertificateInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			DNSNames:     cert.DNSNames,
			SerialNumber: cert.SerialNumber.String(),
			Fingerprint:  certFingerprint(cert),
		}
		metadata.PeerCertificates = append(metadata.PeerCertificates, certInfo)
	}

	return metadata
}

// certFingerprint calculates SHA256 fingerprint of certificate
func certFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// tlsVersionString converts TLS version to string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// calculateDataHash creates SHA256 hash of the data
func calculateDataHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Verify checks if cached data is valid and genuine
func (m *CacheMetadata) Verify(operations []PLCOperation) *VerificationResult {
	result := &VerificationResult{
		Valid: true,
	}

	// Check certificate validity dates
	now := time.Now()
	for _, cert := range m.PeerCertificates {
		if now.Before(cert.NotBefore) {
			result.Errors = append(result.Errors,
				fmt.Sprintf("Certificate not yet valid: %s", cert.Subject))
			result.Valid = false
		}
		if now.After(cert.NotAfter) {
			result.Errors = append(result.Errors,
				fmt.Sprintf("Certificate expired: %s (expired %s)", cert.Subject, cert.NotAfter))
			result.Valid = false
		}
	}
	result.TLSCertsValid = len(result.Errors) == 0

	// Verify operation count
	if m.OperationCount != len(operations) {
		result.Errors = append(result.Errors,
			fmt.Sprintf("Operation count mismatch: expected %d, got %d", m.OperationCount, len(operations)))
		result.Valid = false
	} else {
		result.OperationCountOK = true
	}

	// Verify first and last operation CIDs
	if len(operations) > 0 {
		if operations[0].CID != m.FirstOperation {
			result.Errors = append(result.Errors, "First operation CID mismatch")
			result.Valid = false
		}
		if operations[len(operations)-1].CID != m.LastOperation {
			result.Errors = append(result.Errors, "Last operation CID mismatch")
			result.Valid = false
		}
	}

	// Check server name
	if m.ServerName != "plc.directory" {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Unexpected server name: %s", m.ServerName))
	}

	// Check TLS version
	if m.TLSVersion != "TLS 1.2" && m.TLSVersion != "TLS 1.3" {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Old TLS version: %s", m.TLSVersion))
	}

	return result
}
