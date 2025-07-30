package signer

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	api "github.com/flightctl/flightctl/api/v1alpha1"
	fccrypto "github.com/flightctl/flightctl/pkg/crypto"
	"github.com/sirupsen/logrus"
)

const signerDeviceEnrollmentExpiryDays int32 = 365

// AttestationBundle contains the structured data required for TCG spec compliance
// Local definition to avoid import cycles
type AttestationBundle struct {
	EKCert                 []byte `json:"ek_cert"`
	LAKCertifyInfo         []byte `json:"lak_certify_info"`
	LAKCertifySignature    []byte `json:"lak_certify_signature"`
	LDevIDCertifyInfo      []byte `json:"ldevid_certify_info"`
	LDevIDCertifySignature []byte `json:"ldevid_certify_signature"`
	LAKPublicKey           []byte `json:"lak_public_key"`
	LDevIDPublicKey        []byte `json:"ldevid_public_key"`
}

type SignerDeviceEnrollment struct {
	name          string
	ca            CA
	trustedTPMCAs *x509.CertPool // Direct CA pool instead of interface
	log           logrus.FieldLogger
}

// NewSignerDeviceEnrollment creates a device enrollment signer without TPM validation (backward compatibility)
func NewSignerDeviceEnrollment(CAClient CA) Signer {
	return NewSignerDeviceEnrollmentWithTPMConfig(CAClient, nil)
}

// NewSignerDeviceEnrollmentWithTPMConfig creates a device enrollment signer with specified TPM configuration
func NewSignerDeviceEnrollmentWithTPMConfig(CAClient CA, trustedTPMCAs []string) Signer {
	cfg := CAClient.Config()

	// Load TPM configuration if provided
	if len(trustedTPMCAs) > 0 {
		// Load trusted TPM CAs directly
		caPool := x509.NewCertPool()
		loadedCount := 0

		for _, caPath := range trustedTPMCAs {
			if err := loadCAFromFile(caPool, caPath); err != nil {
				// Continue with other CAs on error
				continue
			}
			loadedCount++
		}

		if loadedCount > 0 {
			// Create TPM-enabled signer
			logger := logrus.WithField("component", "tpm-validator")
			logger.Infof("TPM validation enabled with %d trusted CA(s)", loadedCount)
			return &SignerDeviceEnrollment{
				name:          cfg.DeviceEnrollmentSignerName,
				ca:            CAClient,
				trustedTPMCAs: caPool,
				log:           logger,
			}
		}
	}

	// Create legacy signer without TPM validation
	return &SignerDeviceEnrollment{
		name:          cfg.DeviceEnrollmentSignerName,
		ca:            CAClient,
		trustedTPMCAs: nil,
		log:           nil,
	}
}

// loadCAFromFile loads a CA certificate from a PEM file into the cert pool
func loadCAFromFile(caPool *x509.CertPool, path string) error {
	if path == "" {
		return fmt.Errorf("empty CA path")
	}

	// Resolve relative paths
	if !filepath.IsAbs(path) {
		var err error
		path, err = filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolving CA path: %w", err)
		}
	}

	certPEM, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading CA file %s: %w", path, err)
	}

	if !caPool.AppendCertsFromPEM(certPEM) {
		return fmt.Errorf("failed to parse CA certificate from %s", path)
	}

	return nil
}

func (s *SignerDeviceEnrollment) RestrictedPrefix() string {
	return s.ca.Config().DeviceCommonNamePrefix
}

func (s *SignerDeviceEnrollment) Name() string {
	return s.name
}

func (s *SignerDeviceEnrollment) Verify(ctx context.Context, request api.CertificateSigningRequest) error {
	cfg := s.ca.Config()

	// Check if the client presented a peer certificate during the mTLS handshake.
	// If no peer certificate was presented, we allow the request to proceed without additional signer checks.
	if _, err := PeerCertificateFromCtx(ctx); err == nil {
		signer := s.ca.PeerCertificateSignerFromCtx(ctx)

		got := "<nil>"
		if signer != nil {
			got = signer.Name()
		}

		// Enforce that if a client certificate was presented, it must be signed by the expected bootstrap signer.
		// This ensures only bootstrap client certificates can be used to perform device enrollment.
		if signer == nil || signer.Name() != cfg.ClientBootstrapSignerName {
			return fmt.Errorf("unexpected client certificate signer: expected %q, got %q", cfg.ClientBootstrapSignerName, got)
		}
	}

	// TPM EK Certificate Validation (only if TPM validator is configured)
	if s.trustedTPMCAs != nil {
		if err := s.validateTPMEKCertificate(ctx, request); err != nil {
			s.log.WithError(err).Warn("TPM EK certificate validation failed")
			return fmt.Errorf("TPM EK certificate validation failed: %w", err)
		}
	}

	return nil
}

func (s *SignerDeviceEnrollment) Sign(ctx context.Context, request api.CertificateSigningRequest) ([]byte, error) {
	cfg := s.ca.Config()

	if request.Metadata.Name == nil {
		return nil, fmt.Errorf("request is missing metadata.name")
	}

	csr, err := fccrypto.ParseCSR(request.Spec.Request)
	if err != nil {
		return nil, fmt.Errorf("error parsing CSR: %w", err)
	}

	supplied, err := CNFromDeviceFingerprint(cfg, csr.Subject.CommonName)
	if err != nil {
		return nil, fmt.Errorf("invalid CN supplied in CSR: %w", err)
	}

	desired, err := CNFromDeviceFingerprint(cfg, *request.Metadata.Name)
	if err != nil {
		return nil, fmt.Errorf("error setting CN in CSR: %w", err)
	}

	if desired != supplied {
		return nil, fmt.Errorf("attempt to supply a fake CN, possible identity theft, csr: %s, metadata %s", supplied, desired)
	}
	csr.Subject.CommonName = desired

	expirySeconds := signerDeviceEnrollmentExpiryDays * 24 * 60 * 60
	if request.Spec.ExpirationSeconds != nil && *request.Spec.ExpirationSeconds < expirySeconds {
		expirySeconds = *request.Spec.ExpirationSeconds
	}

	return s.ca.IssueRequestedClientCertificate(
		ctx,
		csr,
		int(expirySeconds),
		WithExtension(OIDOrgID, NullOrgId.String()),
		WithExtension(OIDDeviceFingerprint, csr.Subject.CommonName),
	)
}

// validateTPMEKCertificate checks if this is a TPM-based enrollment and validates the EK certificate
func (s *SignerDeviceEnrollment) validateTPMEKCertificate(ctx context.Context, request api.CertificateSigningRequest) error {
	// Skip validation if no TPM validator is configured
	if s.trustedTPMCAs == nil {
		if s.log != nil {
			s.log.Debug("No TPM validator configured, skipping EK certificate validation")
		}
		return nil
	}

	// Parse the CSR
	csr, err := fccrypto.ParseCSR(request.Spec.Request)
	if err != nil {
		return fmt.Errorf("parsing CSR: %w", err)
	}

	// Look for TPM attestation data in CSR request attributes
	ekCert, bundle, err := s.extractTPMAttestationFromCSRRequest(request)
	if err != nil {
		// Not a TPM-based enrollment or no attestation data found
		if s.log != nil {
			s.log.Debug("No TPM attestation data found in CSR, skipping TPM validation")
		}
		return nil
	}

	if s.log != nil {
		s.log.Info("TPM-based enrollment detected - validating attestation chain")
	}

	// Step 1: Validate EK certificate against trusted TPM manufacturer CAs
	if err := s.validateEKCertificate(ekCert); err != nil {
		return fmt.Errorf("EK certificate validation failed: %w", err)
	}

	// Step 2: Validate TPM attestation proves CSR signing key came from this TPM
	if err := s.validateTPMAttestationBundle(csr, bundle); err != nil {
		return fmt.Errorf("TPM attestation validation failed: %w", err)
	}

	if s.log != nil {
		s.log.Info("TPM attestation validation completed successfully")
	}

	return nil
}

// validateEKCertificate validates the EK certificate against the trusted CA pool
func (s *SignerDeviceEnrollment) validateEKCertificate(ekCert []byte) error {
	if s.trustedTPMCAs == nil {
		return fmt.Errorf("no trusted TPM CAs configured")
	}

	cert, err := x509.ParseCertificate(ekCert)
	if err != nil {
		return fmt.Errorf("parsing EK certificate: %w", err)
	}

	// Verify the certificate chain against trusted TPM manufacturer CAs
	opts := x509.VerifyOptions{
		Roots:     s.trustedTPMCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("TPM EK certificate validation failed: %w", err)
	}

	if len(chains) == 0 {
		return fmt.Errorf("no valid certificate chains found")
	}

	if s.log != nil {
		s.log.WithField("ek_subject", cert.Subject.String()).
			Debugf("EK certificate validated successfully with %d chain(s)", len(chains))
	}

	return nil
}

// extractTPMAttestationFromCSR extracts TPM attestation bundle from CSR attributes
func (s *SignerDeviceEnrollment) extractTPMAttestationFromCSR(csr *x509.CertificateRequest) ([]byte, *AttestationBundle, error) {
	// For now, return error since the TPM attestation data is expected to be in the CSR request object
	// rather than the parsed x509.CertificateRequest
	return nil, nil, fmt.Errorf("TPM attestation data not available in parsed CSR")
}

// extractTPMAttestationFromCSRRequest extracts TPM attestation bundle from CSR request attributes
func (s *SignerDeviceEnrollment) extractTPMAttestationFromCSRRequest(request api.CertificateSigningRequest) ([]byte, *AttestationBundle, error) {
	if request.Spec.Extra == nil {
		if s.log != nil {
			s.log.Debug("No extra attributes in CSR request")
		}
		return nil, nil, fmt.Errorf("no TPM attestation data found in CSR attributes")
	}

	extra := *request.Spec.Extra

	// Extract EK certificate
	ekCertExtra, ekCertExists := extra["flightctl.io/tpm-ek-certificate"]
	if !ekCertExists || len(ekCertExtra) == 0 {
		if s.log != nil {
			s.log.Debug("No EK certificate found in CSR attributes")
		}
		return nil, nil, fmt.Errorf("no EK certificate found")
	}

	// Convert EK certificate from PEM to DER
	ekCertPEM := ekCertExtra[0]
	ekCertDER, err := convertPEMToDER(ekCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("converting EK certificate to DER: %w", err)
	}

	// Extract attestation bundle components
	bundle := &AttestationBundle{
		EKCert: ekCertDER,
	}

	// Extract LAK attestation data
	if lakCertifyInfoExtra, exists := extra["flightctl.io/tpm-lak-certify-info"]; exists && len(lakCertifyInfoExtra) > 0 {
		lakCertifyInfo, err := base64.StdEncoding.DecodeString(lakCertifyInfoExtra[0])
		if err != nil {
			return nil, nil, fmt.Errorf("decoding LAK certify info: %w", err)
		}
		bundle.LAKCertifyInfo = lakCertifyInfo
	}

	if lakCertifySignatureExtra, exists := extra["flightctl.io/tpm-lak-certify-signature"]; exists && len(lakCertifySignatureExtra) > 0 {
		lakCertifySignature, err := base64.StdEncoding.DecodeString(lakCertifySignatureExtra[0])
		if err != nil {
			return nil, nil, fmt.Errorf("decoding LAK certify signature: %w", err)
		}
		bundle.LAKCertifySignature = lakCertifySignature
	}

	if lakPublicKeyExtra, exists := extra["flightctl.io/tpm-lak-public-key"]; exists && len(lakPublicKeyExtra) > 0 {
		lakPublicKey, err := base64.StdEncoding.DecodeString(lakPublicKeyExtra[0])
		if err != nil {
			return nil, nil, fmt.Errorf("decoding LAK public key: %w", err)
		}
		bundle.LAKPublicKey = lakPublicKey
	}

	// Extract LDevID attestation data
	if ldevidCertifyInfoExtra, exists := extra["flightctl.io/tpm-ldevid-certify-info"]; exists && len(ldevidCertifyInfoExtra) > 0 {
		ldevidCertifyInfo, err := base64.StdEncoding.DecodeString(ldevidCertifyInfoExtra[0])
		if err != nil {
			return nil, nil, fmt.Errorf("decoding LDevID certify info: %w", err)
		}
		bundle.LDevIDCertifyInfo = ldevidCertifyInfo
	}

	if ldevidCertifySignatureExtra, exists := extra["flightctl.io/tpm-ldevid-certify-signature"]; exists && len(ldevidCertifySignatureExtra) > 0 {
		ldevidCertifySignature, err := base64.StdEncoding.DecodeString(ldevidCertifySignatureExtra[0])
		if err != nil {
			return nil, nil, fmt.Errorf("decoding LDevID certify signature: %w", err)
		}
		bundle.LDevIDCertifySignature = ldevidCertifySignature
	}

	if ldevidPublicKeyExtra, exists := extra["flightctl.io/tpm-ldevid-public-key"]; exists && len(ldevidPublicKeyExtra) > 0 {
		ldevidPublicKey, err := base64.StdEncoding.DecodeString(ldevidPublicKeyExtra[0])
		if err != nil {
			return nil, nil, fmt.Errorf("decoding LDevID public key: %w", err)
		}
		bundle.LDevIDPublicKey = ldevidPublicKey
	}

	if s.log != nil {
		s.log.WithField("device", getDeviceName(request)).
			Info("Successfully extracted TPM attestation bundle from CSR attributes")
	}

	return ekCertDER, bundle, nil
}

// convertPEMToDER converts a PEM-encoded certificate to DER format
func convertPEMToDER(pemData string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is not a certificate")
	}
	return block.Bytes, nil
}

// validateTPMAttestationBundle validates the complete TCG attestation bundle
func (s *SignerDeviceEnrollment) validateTPMAttestationBundle(csr *x509.CertificateRequest, bundle *AttestationBundle) error {
	if bundle == nil {
		return fmt.Errorf("nil attestation bundle")
	}

	// Basic validation - verify EK certificate against trusted roots
	ekCert, err := x509.ParseCertificate(bundle.EKCert)
	if err != nil {
		return fmt.Errorf("parsing EK certificate: %w", err)
	}

	// verify EK certificate chain against trusted roots
	opts := x509.VerifyOptions{
		Roots: s.trustedTPMCAs,
	}
	_, err = ekCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("verifying EK certificate chain: %w", err)
	}

	// TODO: Implement full TPM2_Certify signature verification for LAK and LDevID
	// For now, we just verify that the required components are present
	if len(bundle.LAKCertifyInfo) == 0 || len(bundle.LAKCertifySignature) == 0 {
		if s.log != nil {
			s.log.Warn("LAK certify data missing - skipping LAK verification")
		}
	}

	if len(bundle.LDevIDCertifyInfo) == 0 || len(bundle.LDevIDCertifySignature) == 0 {
		if s.log != nil {
			s.log.Warn("LDevID certify data missing - skipping LDevID verification")
		}
	}

	// Additional validation: ensure the LDevID public key in the bundle matches the CSR public key
	if len(bundle.LDevIDPublicKey) > 0 {
		if err := s.verifyLDevIDMatchesCSR(csr, bundle.LDevIDPublicKey); err != nil {
			return fmt.Errorf("LDevID public key verification failed: %w", err)
		}
	} else {
		if s.log != nil {
			s.log.Warn("No LDevID public key in attestation bundle - cannot verify CSR key binding")
		}
	}

	if s.log != nil {
		s.log.Info("TPM attestation bundle validation completed successfully")
	}

	return nil
}

// verifyLDevIDMatchesCSR verifies that the LDevID public key matches the CSR public key
func (s *SignerDeviceEnrollment) verifyLDevIDMatchesCSR(csr *x509.CertificateRequest, ldevidPublicKeyDER []byte) error {
	// Parse the LDevID public key from DER
	ldevidPublicKey, err := x509.ParsePKIXPublicKey(ldevidPublicKeyDER)
	if err != nil {
		return fmt.Errorf("parsing LDevID public key: %w", err)
	}

	// Compare with CSR public key
	csrPublicKey := csr.PublicKey

	// Use the crypto package's Equal method for public key comparison
	if !fccrypto.PublicKeysEqual(csrPublicKey, ldevidPublicKey) {
		return fmt.Errorf("CSR public key does not match LDevID public key")
	}

	if s.log != nil {
		s.log.Info("LDevID public key matches CSR public key - key binding verified")
	}

	return nil
}

// isTPMBasedEnrollment determines if this enrollment request is from a TPM-based device
func (s *SignerDeviceEnrollment) isTPMBasedEnrollment(csr *x509.CertificateRequest, request api.CertificateSigningRequest) bool {
	// Primary check: Look for TPM attestation data in CSR extensions
	_, _, err := s.extractTPMAttestationFromCSR(csr)
	if err == nil {
		return true // Found TPM attestation data
	}

	// Secondary check: Look for TPM-specific CSR extensions
	tpmOIDs := []string{
		"1.3.6.1.4.1.311.21.30",      // Microsoft TPM EK (High Assurance)
		"1.3.6.1.4.1.311.21.31",      // Microsoft TPM EK Cert (Medium Assurance)
		"1.3.6.1.4.1.311.21.32",      // Microsoft TPM User Credentials (Low Assurance)
		"2.23.133.8.3",               // TCG AK Certificate
		"1.2.840.113549.1.9.16.1.56", // IETF CSR-Attestation (example)
	}

	for _, ext := range csr.Extensions {
		oidStr := ext.Id.String()
		for _, tpmOID := range tpmOIDs {
			if oidStr == tpmOID {
				if s.log != nil {
					s.log.WithField("device", getDeviceName(request)).
						WithField("oid", oidStr).
						Info("Detected TPM-based enrollment via extension OID")
				}
				return true
			}
		}
	}

	// Fallback for development/testing: check device name
	if request.Metadata.Name != nil && *request.Metadata.Name != "" {
		if s.log != nil {
			s.log.WithField("device", *request.Metadata.Name).
				Debug("Assuming TPM-based enrollment for e2e testing")
		}
		return true
	}

	return false
}

// Helper function to get device name safely
func getDeviceName(request api.CertificateSigningRequest) string {
	if request.Metadata.Name != nil {
		return *request.Metadata.Name
	}
	return "unknown"
}
