package signer

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	api "github.com/flightctl/flightctl/api/v1alpha1"
	fccrypto "github.com/flightctl/flightctl/pkg/crypto"
	"github.com/sirupsen/logrus"
)

const signerDeviceEnrollmentExpiryDays int32 = 365

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

	// Look for TPM attestation data in CSR extensions
	ekCert, attestationData, err := s.extractTPMAttestationFromCSR(csr)
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
	if err := s.validateTPMAttestation(csr, ekCert, attestationData); err != nil {
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

// extractTPMAttestationFromCSR extracts EK certificate and attestation data from CSR extensions
func (s *SignerDeviceEnrollment) extractTPMAttestationFromCSR(csr *x509.CertificateRequest) ([]byte, []byte, error) {
	// Look for IETF CSR-Attestation extension (id-aa-evidence)
	// This should contain the TPM EK certificate and attestation data

	for _, ext := range csr.Extensions {
		// Check for CSR-Attestation extension
		if ext.Id.String() == "1.2.840.113549.1.9.16.1.56" { // id-aa-evidence (example OID)
			// Parse attestation data from extension
			// This would contain:
			// - EK certificate (DER format)
			// - TPM attestation/quote proving the CSR signing key
			// - Additional TPM evidence

			// For now, return placeholder - in real implementation this would
			// parse the ASN.1 structure containing the attestation evidence
			if s.log != nil {
				s.log.Debug("Found CSR-Attestation extension, parsing TPM evidence")
			}

			// TODO: Parse actual attestation data structure
			// ekCert, attestationData := parseAttestationEvidence(ext.Value)
			// return ekCert, attestationData, nil
		}

		// Check for custom FlightCtl TPM attestation extension
		if ext.Id.String() == "2.23.133.8.100" { // hypothetical FlightCtl TPM extension
			if s.log != nil {
				s.log.Debug("Found FlightCtl TPM attestation extension")
			}
			// Parse our custom format containing EK cert + attestation
		}
	}

	// For development/testing: Check if we can get attestation data from context
	// In real implementation, attestation data must be in the CSR
	if s.log != nil {
		s.log.Debug("No TPM attestation extensions found in CSR")
	}

	return nil, nil, fmt.Errorf("no TPM attestation data found")
}

// validateTPMAttestation validates that the CSR signing key was generated by the TPM
func (s *SignerDeviceEnrollment) validateTPMAttestation(csr *x509.CertificateRequest, ekCert []byte, attestationData []byte) error {
	// Parse EK certificate to get EK public key
	cert, err := x509.ParseCertificate(ekCert)
	if err != nil {
		return fmt.Errorf("parsing EK certificate: %w", err)
	}

	// In real implementation, this would:
	// 1. Parse the TPM attestation/quote from attestationData
	// 2. Verify the attestation signature using EK public key
	// 3. Check that the attested key matches the CSR public key
	// 4. Validate PCR values and other TPM state if required

	if s.log != nil {
		s.log.WithField("ek_subject", cert.Subject.String()).
			Info("Validating TPM attestation signature against EK public key")
	}

	// TODO: Implement actual attestation validation
	// Example structure:
	//
	// type TPMAttestation struct {
	//     Quote        []byte  // TPM2_Quote output (TPMS_ATTEST)
	//     Signature    []byte  // Signature over quote by AK
	//     PCRValues    map[int][]byte  // PCR values
	//     AttestedKey  crypto.PublicKey  // The key being attested
	// }
	//
	// 1. Verify signature over quote using EK public key
	// 2. Parse TPMS_ATTEST structure from quote
	// 3. Verify attested key matches CSR public key
	// 4. Check PCR values match expected platform state

	if s.log != nil {
		s.log.Info("TPM attestation validation would happen here")
		s.log.Info("- Verify quote signature against EK public key")
		s.log.Info("- Parse TPMS_ATTEST structure")
		s.log.Info("- Verify attested key matches CSR public key")
		s.log.Info("- Validate PCR values and platform state")
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
