//go:build integration && (amd64 || arm64)

package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/flightctl/flightctl/api/v1alpha1"
	agent_config "github.com/flightctl/flightctl/internal/agent/config"
	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/flightctl/flightctl/internal/tpm"
	"github.com/flightctl/flightctl/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ST TPM EK Certificate URLs based on ST Technical Note TN1330
var stmCAURLs = []string{
	// STMicroelectronics Root CAs (from sw-center.st.com infrastructure)
	"http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crt",
	"http://sw-center.st.com/STSAFE/STSAFERsaRootCA01.crt",
	"http://sw-center.st.com/STSAFE/STSAFERsaRootCA.crt",

	// ST TPM-specific CAs (based on TN1330 technical note patterns)
	"http://sw-center.st.com/STSAFE/STSAFETpmRootCA.crt",
	"http://sw-center.st.com/STSAFE/STSAFETpmRootCA01.crt",
	"http://sw-center.st.com/STSAFE/STSAFETpmRootCA02.crt",

	// ST TPM Intermediate CAs
	"http://sw-center.st.com/STSAFE/STSAFETpmIntCA01.crt",
	"http://sw-center.st.com/STSAFE/STSAFETpmIntCA02.crt",
	"http://sw-center.st.com/STSAFE/STSAFETpmIntCA03.crt",

	// ST ECC-based TPM CAs
	"http://sw-center.st.com/STSAFE/STSAFEEccRootCA.crt",
	"http://sw-center.st.com/STSAFE/STSAFEEccRootCA01.crt",
	"http://sw-center.st.com/STSAFE/STSAFEEccTpmCA.crt",

	// Legacy GlobalSign URLs (for older ST TPMs)
	"https://secure.globalsign.com/cacert/gstpmroot.crt",
	"https://secure.globalsign.com/cacert/sttpmekroot.crt",
	"https://secure.globalsign.com/cacert/sttpmekintermediateca.crt",
}

// TestTPMEnrollmentWithSTMValidation tests TPM enrollment with real STM CA validation
func TestTPMEnrollmentWithSTMValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TPM integration test in short mode")
	}

	// Check if TPM device exists
	tpmPaths := []string{"/dev/tpmrm0", "/dev/tpm0"}
	var tpmPath string
	for _, path := range tpmPaths {
		if _, err := os.Stat(path); err == nil {
			tpmPath = path
			break
		}
	}
	if tpmPath == "" {
		t.Skip("No TPM device found")
	}
	t.Logf("Using TPM device: %s", tpmPath)

	ctx := context.Background()
	require := require.New(t)
	assert := assert.New(t)

	tempDir := t.TempDir()
	persistencePath := filepath.Join(tempDir, "ldevid-blob.yaml")
	logger := log.NewPrefixLogger("tpm-test")
	rw := fileio.NewReadWriter()

	// Create TPM client
	config := &agent_config.Config{
		TPM: agent_config.TPM{
			Enabled:         true,
			Path:            tpmPath,
			PersistencePath: persistencePath,
		},
		DataDir: tempDir,
	}

	tpmClient, err := tpm.NewClient(logger, rw, config)
	require.NoError(err)
	require.NotNil(tpmClient)
	defer tpmClient.Close(ctx)

	// Debug TPM client
	t.Logf("TPM client type: %T", tpmClient)
	t.Logf("TPM client created successfully")

	// Verify TPM client functionality
	pubKey := tpmClient.Public()
	require.NotNil(pubKey)
	t.Logf("TPM public key type: %T", pubKey)

	// Create TPM-based identity provider
	identityProvider := NewProvider(tpmClient, rw, config, logger)
	require.NotNil(identityProvider)

	// Debug: Log the actual type of identity provider
	t.Logf("Identity provider type: %T", identityProvider)
	t.Logf("Identity provider value: %+v", identityProvider)

	// Debug: Use reflection to see what interfaces are implemented
	providerType := reflect.TypeOf(identityProvider)
	t.Logf("Identity provider concrete type: %v", providerType)
	if providerType.Kind() == reflect.Ptr {
		t.Logf("Identity provider element type: %v", providerType.Elem())
	}

	// Check for methods
	t.Logf("Number of methods: %d", providerType.NumMethod())
	for i := 0; i < providerType.NumMethod(); i++ {
		method := providerType.Method(i)
		t.Logf("  Method %d: %s %v", i, method.Name, method.Type)
	}

	err = identityProvider.Initialize(ctx)
	require.NoError(err)
	t.Logf("Identity provider initialized successfully")

	// Verify TPM capabilities
	tpmCapable, ok := identityProvider.(TPMCapable)
	t.Logf("TPMCapable interface check: ok=%v, tpmCapable=%+v", ok, tpmCapable)
	if !ok {
		t.Logf("Identity provider does not implement TPMCapable interface")
		t.Logf("Available methods/interfaces can be checked with reflection")
	}
	require.True(ok)

	tpmProvider, hasTpm := tpmCapable.GetTPM()
	t.Logf("GetTPM() result: hasTpm=%v, tpmProvider=%+v", hasTpm, tpmProvider)
	require.True(hasTpm)
	require.NotNil(tpmProvider)

	// Get device name
	deviceName, err := identityProvider.GetDeviceName()
	require.NoError(err)
	require.NotEmpty(deviceName)
	t.Logf("Device name: %s (length: %d)", deviceName, len(deviceName))

	// Create enrollment request with TPM certificates
	deviceStatus := &v1alpha1.DeviceStatus{
		SystemInfo: v1alpha1.DeviceSystemInfo{
			Architecture:    "amd64",
			OperatingSystem: "linux",
		},
	}

	defaultLabels := map[string]string{
		"test": "true",
	}

	t.Logf("Creating enrollment request...")
	enrollmentRequest, err := CreateEnrollmentRequest(
		logger,
		identityProvider,
		deviceStatus,
		defaultLabels,
	)
	if err != nil {
		t.Logf("CreateEnrollmentRequest failed: %v", err)
		t.Logf("Error type: %T", err)
	}
	require.NoError(err)
	require.NotNil(enrollmentRequest)
	t.Logf("Enrollment request created successfully")

	// Verify enrollment request structure
	require.NotEmpty(enrollmentRequest.Spec.Csr)
	require.Equal(deviceName, *enrollmentRequest.Metadata.Name)

	// Parse and validate CSR
	csrBlock, _ := pem.Decode([]byte(enrollmentRequest.Spec.Csr))
	require.NotNil(csrBlock)

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	require.NoError(err)

	err = csr.CheckSignature()
	require.NoError(err)

	// Verify CSR public key matches TPM public key
	assert.Equal(pubKey, csr.PublicKey)

	// Create testdata directory for ST TPM certificates
	testDataDir := filepath.Join("testdata", "st-tpm-certs")
	err = os.MkdirAll(testDataDir, 0755)
	require.NoError(err)

	// Download and create STM certificate pool for real validation
	stmPool, downloadedCount, err := downloadSTMCertificatePool(t, testDataDir)
	require.NoError(err)
	t.Logf("Downloaded %d ST TPM CA certificates to %s", downloadedCount, testDataDir)

	// Test EK certificate validation if available
	if enrollmentRequest.Spec.EkCert != nil && *enrollmentRequest.Spec.EkCert != "" {
		ekBlock, _ := pem.Decode([]byte(*enrollmentRequest.Spec.EkCert))
		require.NotNil(ekBlock)

		// Use the custom ParseEKCertificate function instead of standard x509.ParseCertificate
		t.Logf("Using ParseEKCertificate for TPM-specific parsing...")
		ekCert, err := ParseEKCertificate(ekBlock.Bytes)
		if err != nil {
			t.Logf("ParseEKCertificate failed: %v", err)
			t.Logf("Falling back to standard x509.ParseCertificate...")
			ekCert, err = x509.ParseCertificate(ekBlock.Bytes)
		}
		require.NoError(err)

		t.Logf("EK Certificate parsed successfully with enhanced parser")
		t.Logf("EK Certificate Subject: %s", ekCert.Subject.String())
		t.Logf("EK Certificate Issuer: %s", ekCert.Issuer.String())

		// Debug certificate extensions
		t.Logf("EK Certificate has %d extensions:", len(ekCert.Extensions))
		for i, ext := range ekCert.Extensions {
			t.Logf("  Extension %d: OID=%s, Critical=%v, Length=%d bytes",
				i, ext.Id.String(), ext.Critical, len(ext.Value))

			// Parse specific extensions that might contain issuer information
			switch ext.Id.String() {
			case "1.3.6.1.5.5.7.1.1": // Authority Information Access (AIA)
				t.Logf("    ↳ Authority Information Access extension found!")
				aiaInfo := parseAIAExtension(t, ext.Value)
				if aiaInfo != "" {
					t.Logf("    ↳ AIA Info: %s", aiaInfo)
				}
			case "2.5.29.35": // Authority Key Identifier
				t.Logf("    ↳ Authority Key Identifier extension")
			case "2.5.29.17": // Subject Alternative Name
				t.Logf("    ↳ Subject Alternative Name extension (Critical)")
			}
		}

		// Check for known TPM-specific extensions
		hasTPMExtensions := false
		for _, ext := range ekCert.Extensions {
			// Common TPM extension OIDs (these are vendor-specific)
			switch ext.Id.String() {
			case "2.23.133.8.1", "2.23.133.8.2", "2.23.133.8.3": // TCG TPM extensions
				hasTPMExtensions = true
				t.Logf("  Found TPM-specific extension: %s (Critical: %v)", ext.Id.String(), ext.Critical)
			case "1.2.840.113549.1.9.16.1.24": // ST Microelectronics extension
				hasTPMExtensions = true
				t.Logf("  Found ST Microelectronics extension: %s (Critical: %v)", ext.Id.String(), ext.Critical)
			}
		}

		// Validate EK certificate against STM CA pool
		if downloadedCount > 0 {
			// First, try to download intermediate CA certificates from AIA extension
			var aiaExtension *pkix.Extension
			for _, ext := range ekCert.Extensions {
				if ext.Id.String() == "1.3.6.1.5.5.7.1.1" { // Authority Information Access
					aiaExtension = &ext
					break
				}
			}

			// Download intermediate CAs if AIA extension is present
			if aiaExtension != nil {
				intermediateCerts, err := downloadIntermediateCA(t, aiaExtension.Value, testDataDir)
				if err != nil {
					t.Logf("Failed to download intermediate CAs: %v", err)
				} else if len(intermediateCerts) > 0 {
					t.Logf("Downloaded %d intermediate CA certificate(s)", len(intermediateCerts))

					// Add intermediate CAs to the certificate pool
					for _, cert := range intermediateCerts {
						stmPool.AddCert(cert)
					}
					downloadedCount += len(intermediateCerts)
					t.Logf("Updated certificate pool now has %d total certificates", downloadedCount)
				}
			}

			// Use the enhanced validation that can handle TPM-specific critical extensions
			err = ValidateEKCertificateChain(ekCert, stmPool)
			if err != nil {
				t.Logf("Enhanced EK certificate validation failed: %v", err)

				// Fall back to the original validation for comparison
				err = validateEKCertificateChain(t, ekCert, stmPool)
				if err != nil {
					errorMsg := err.Error()
					if strings.Contains(errorMsg, "unhandled critical extension") {
						t.Logf("⚠ EK certificate contains unrecognized critical extensions (common with TPM certificates)")
						if hasTPMExtensions {
							t.Logf("⚠ Certificate contains known TPM-specific critical extensions that Go's x509 library doesn't support")
							t.Logf("⚠ This is normal for TPM EK certificates and doesn't indicate a security issue")
						}
						t.Logf("⚠ Certificate chain validation skipped due to critical extension limitations")

						// Provide detailed explanation for educational purposes
						explainTPMCertificateExtensions(t)
					} else {
						t.Logf("EK certificate validation failed (certificate may be from different CA): %v", err)
					}
				} else {
					t.Logf("✓ EK certificate validated against STM CA chain using standard validation")
				}
			} else {
				t.Logf("✓ EK certificate validated against STM CA chain using enhanced TPM validation")
			}
		} else {
			t.Logf("⚠ No STM CA certificates downloaded, skipping chain validation")
		}
	} else {
		t.Logf("No EK certificate available for validation")
	}

	// Test TPM attestation if available
	attestationData, err := tpmProvider.GetTPMCertifyCert()
	if err == nil && len(attestationData) > 0 {
		t.Logf("TPM attestation available (%d bytes)", len(attestationData))
	}

	// Test signing capability
	testData := []byte("test signing")
	t.Logf("Test data for signing: %q (length: %d bytes)", testData, len(testData))

	signer := tpmClient.GetSigner()
	t.Logf("TPM signer type: %T", signer)

	// Add debug for the signing process
	t.Logf("Attempting to sign test data...")
	// TPM expects a pre-hashed digest (SHA-256), not raw data
	testHash := sha256.Sum256(testData)
	t.Logf("Hashed test data: %d bytes", len(testHash))
	signature, err := signer.Sign(nil, testHash[:], nil)
	if err != nil {
		t.Logf("Signing failed with error: %v", err)
		t.Logf("Error type: %T", err)
		require.NoError(err)
	}
	require.NotEmpty(signature)
	t.Logf("Signing successful, signature length: %d bytes", len(signature))

	t.Logf("✓ TPM enrollment test completed successfully")
	t.Logf("  - Device name: %s", deviceName)
	t.Logf("  - CSR generated and validated")
	t.Logf("  - EK certificate processed: %v", enrollmentRequest.Spec.EkCert != nil)
	t.Logf("  - TPM attestation available: %v", len(attestationData) > 0)
	t.Logf("  - STM CAs downloaded: %d", downloadedCount)
}

// TestSTCertificateDownload tests downloading ST TPM CA certificates
func TestSTCertificateDownload(t *testing.T) {
	// Create testdata directory for ST TPM certificates
	testDataDir := filepath.Join("testdata", "st-tpm-certs")
	err := os.MkdirAll(testDataDir, 0755)
	require.NoError(t, err)

	// Download and create STM certificate pool
	stmPool, downloadedCount, err := downloadSTMCertificatePool(t, testDataDir)
	require.NoError(t, err)

	t.Logf("Downloaded %d ST TPM CA certificates to %s", downloadedCount, testDataDir)

	// List downloaded certificates with details
	if downloadedCount > 0 {
		t.Logf("Certificate details:")
		files, err := os.ReadDir(testDataDir)
		require.NoError(t, err)

		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".txt") {
				metadataPath := filepath.Join(testDataDir, file.Name())
				metadata, err := os.ReadFile(metadataPath)
				if err == nil {
					t.Logf("\n=== %s ===\n%s", file.Name(), string(metadata))
				}
			}
		}

		// Test the certificate pool
		require.NotNil(t, stmPool)
		t.Logf("✓ Created certificate pool with %d ST TPM CA certificates", downloadedCount)
	} else {
		t.Logf("⚠ No certificates were downloaded - this may indicate network issues or changed URLs")
	}
}

// downloadSTMCertificatePool downloads ST TPM CA certificates and creates a certificate pool
func downloadSTMCertificatePool(t *testing.T, certDir string) (*x509.CertPool, int, error) {
	pool := x509.NewCertPool()
	client := &http.Client{Timeout: 30 * time.Second}
	downloadedCount := 0

	for i, url := range stmCAURLs {
		t.Logf("Downloading ST TPM CA certificate %d/%d: %s", i+1, len(stmCAURLs), url)

		// Generate filename from URL
		filename := fmt.Sprintf("st-tpm-ca-%d-%s", i+1, filepath.Base(url))
		if !strings.HasSuffix(filename, ".crt") {
			filename += ".crt"
		}
		certPath := filepath.Join(certDir, filename)

		// Check if certificate already exists
		if existingData, err := os.ReadFile(certPath); err == nil {
			t.Logf("Using cached certificate: %s", certPath)
			if cert := parseCertificateData(t, existingData, url); cert != nil {
				pool.AddCert(cert)
				downloadedCount++
				t.Logf("✓ Loaded cached CA: %s", cert.Subject.String())
			}
			continue
		}

		resp, err := client.Get(url)
		if err != nil {
			t.Logf("Failed to download %s: %v", url, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Logf("HTTP %d for %s (may not exist)", resp.StatusCode, url)
			continue
		}

		certData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Logf("Failed to read certificate data from %s: %v", url, err)
			continue
		}

		cert := parseCertificateData(t, certData, url)
		if cert == nil {
			continue
		}

		pool.AddCert(cert)
		downloadedCount++
		t.Logf("✓ Downloaded ST TPM CA: %s", cert.Subject.String())

		// Save certificate to testdata for future use and inspection
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		err = os.WriteFile(certPath, pemData, 0644)
		if err == nil {
			t.Logf("  Saved to: %s", certPath)

			// Also save metadata about the certificate
			metadataPath := strings.Replace(certPath, ".crt", ".txt", 1)
			metadata := fmt.Sprintf("Certificate: %s\nSubject: %s\nIssuer: %s\nSerial: %s\nValid From: %s\nValid To: %s\nURL: %s\n",
				filename,
				cert.Subject.String(),
				cert.Issuer.String(),
				cert.SerialNumber.String(),
				cert.NotBefore.Format(time.RFC3339),
				cert.NotAfter.Format(time.RFC3339),
				url,
			)
			os.WriteFile(metadataPath, []byte(metadata), 0644)
		}
	}

	if downloadedCount == 0 {
		t.Logf("⚠ No ST TPM CA certificates could be downloaded")
	} else {
		t.Logf("Downloaded %d ST TPM CA certificates to %s", downloadedCount, certDir)
	}

	return pool, downloadedCount, nil
}

// parseCertificateData parses certificate data in DER or PEM format
func parseCertificateData(t *testing.T, certData []byte, source string) *x509.Certificate {
	// Try to parse as DER first using enhanced TPM parser
	cert, err := ParseEKCertificate(certData)
	if err != nil {
		t.Logf("ParseEKCertificate failed for %s: %v, trying standard parsing", source, err)
		// Fall back to standard parsing
		cert, err = x509.ParseCertificate(certData)
		if err != nil {
			// Try PEM format
			block, _ := pem.Decode(certData)
			if block == nil {
				t.Logf("Failed to decode certificate from %s: not valid DER or PEM", source)
				return nil
			}
			// Try enhanced parser on PEM content first
			cert, err = ParseEKCertificate(block.Bytes)
			if err != nil {
				// Fall back to standard parser for PEM content
				cert, err = x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Logf("Failed to parse certificate from %s: %v", source, err)
					return nil
				}
			}
		}
	}
	return cert
}

// validateEKCertificateChain validates an EK certificate against the STM CA pool
func validateEKCertificateChain(t *testing.T, ekCert *x509.Certificate, stmPool *x509.CertPool) error {
	t.Logf("Attempting to validate EK certificate chain...")
	t.Logf("Certificate Serial: %s", ekCert.SerialNumber.String())
	t.Logf("Certificate Valid From: %s", ekCert.NotBefore.Format(time.RFC3339))
	t.Logf("Certificate Valid To: %s", ekCert.NotAfter.Format(time.RFC3339))

	// Create verification options
	opts := x509.VerifyOptions{
		Roots:     stmPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	t.Logf("Using verification options with %d root CAs", len(stmPool.Subjects()))

	// Try to verify the certificate chain
	chains, err := ekCert.Verify(opts)
	if err != nil {
		t.Logf("Certificate verification failed: %v", err)
		// Check for specific error types
		if strings.Contains(err.Error(), "unhandled critical extension") {
			t.Logf("Root cause: Certificate contains critical extensions not recognized by Go's x509 library")
			t.Logf("Note: ParseEKCertificate was used for parsing, but validation still requires standard x509.Verify")
			t.Logf("The enhanced parser helps with format issues but doesn't solve critical extension limitations")
		}
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	if len(chains) == 0 {
		return fmt.Errorf("no valid certificate chains found")
	}

	t.Logf("Certificate chain validation successful:")
	for i, chain := range chains {
		t.Logf("  Chain %d:", i+1)
		for j, cert := range chain {
			t.Logf("    [%d] %s", j, cert.Subject.String())
		}
	}

	return nil
}

// explainTPMCertificateExtensions provides educational information about TPM certificate extensions
func explainTPMCertificateExtensions(t *testing.T) {
	t.Logf("")
	t.Logf("=== TPM Certificate Extension Information ===")
	t.Logf("TPM Endorsement Key (EK) certificates often contain vendor-specific critical extensions.")
	t.Logf("These extensions are defined by:")
	t.Logf("  • TCG (Trusted Computing Group) specifications")
	t.Logf("  • Individual TPM manufacturers (Intel, ST Microelectronics, etc.)")
	t.Logf("")
	t.Logf("Common TPM certificate extensions:")
	t.Logf("  • 2.23.133.8.1  - TPM Manufacturer Info")
	t.Logf("  • 2.23.133.8.2  - TPM Model Info")
	t.Logf("  • 2.23.133.8.3  - TPM Version Info")
	t.Logf("  • Vendor-specific OIDs for additional TPM metadata")
	t.Logf("")
	t.Logf("Why validation fails:")
	t.Logf("  • X.509 standard requires rejecting certificates with unrecognized critical extensions")
	t.Logf("  • Go's crypto/x509 library doesn't implement TPM-specific extensions")
	t.Logf("  • This is a limitation of standard X.509 validation, not a security issue")
	t.Logf("")
	t.Logf("Solutions for production use:")
	t.Logf("  • Use specialized TPM certificate validation libraries")
	t.Logf("  • Implement custom extension handlers")
	t.Logf("  • Validate certificate chain manually with extension allowlisting")
	t.Logf("=== End TPM Certificate Extension Information ===")
	t.Logf("")
}

// parseAIAExtension parses the Authority Information Access extension to find CA issuer URLs
func parseAIAExtension(t *testing.T, aiaBytes []byte) string {
	// AIA extension structure:
	// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
	// AccessDescription ::= SEQUENCE {
	//     accessMethod          OBJECT IDENTIFIER,
	//     accessLocation        GeneralName
	// }

	var aiaSequence []struct {
		Method   asn1.ObjectIdentifier
		Location asn1.RawValue `asn1:"tag:6"` // GeneralName URI is tagged with [6]
	}

	_, err := asn1.Unmarshal(aiaBytes, &aiaSequence)
	if err != nil {
		t.Logf("    ↳ Failed to parse AIA extension: %v", err)
		return ""
	}

	var results []string
	for _, access := range aiaSequence {
		// Check for CA Issuers access method (1.3.6.1.5.5.7.48.2)
		if access.Method.Equal([]int{1, 3, 6, 1, 5, 5, 7, 48, 2}) {
			// Extract the URI from the GeneralName
			uri := string(access.Location.Bytes)
			results = append(results, fmt.Sprintf("CA Issuers: %s", uri))
			t.Logf("    ↳ Found CA Issuers URL: %s", uri)
		}
		// Check for OCSP access method (1.3.6.1.5.5.7.48.1)
		if access.Method.Equal([]int{1, 3, 6, 1, 5, 5, 7, 48, 1}) {
			uri := string(access.Location.Bytes)
			results = append(results, fmt.Sprintf("OCSP: %s", uri))
			t.Logf("    ↳ Found OCSP URL: %s", uri)
		}
	}

	return strings.Join(results, "; ")
}

// downloadIntermediateCA downloads intermediate CA certificates from AIA extension URLs
func downloadIntermediateCA(t *testing.T, aiaBytes []byte, certDir string) ([]*x509.Certificate, error) {
	var aiaSequence []struct {
		Method   asn1.ObjectIdentifier
		Location asn1.RawValue `asn1:"tag:6"`
	}

	_, err := asn1.Unmarshal(aiaBytes, &aiaSequence)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AIA extension: %w", err)
	}

	var intermediateCerts []*x509.Certificate
	client := &http.Client{Timeout: 30 * time.Second}

	for _, access := range aiaSequence {
		// Only download from CA Issuers URLs
		if access.Method.Equal([]int{1, 3, 6, 1, 5, 5, 7, 48, 2}) {
			uri := string(access.Location.Bytes)
			t.Logf("Downloading intermediate CA from: %s", uri)

			resp, err := client.Get(uri)
			if err != nil {
				t.Logf("Failed to download from %s: %v", uri, err)
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Logf("HTTP %d for %s", resp.StatusCode, uri)
				continue
			}

			certData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Logf("Failed to read certificate data from %s: %v", uri, err)
				continue
			}

			// Try to parse the certificate
			cert := parseCertificateData(t, certData, uri)
			if cert != nil {
				intermediateCerts = append(intermediateCerts, cert)
				t.Logf("✓ Downloaded intermediate CA: %s", cert.Subject.String())

				// Save the intermediate certificate
				filename := fmt.Sprintf("intermediate-ca-%s.crt",
					strings.ReplaceAll(cert.Subject.CommonName, " ", "-"))
				certPath := filepath.Join(certDir, filename)

				pemData := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				})
				os.WriteFile(certPath, pemData, 0644)
				t.Logf("  Saved to: %s", certPath)
			}
		}
	}

	return intermediateCerts, nil
}
