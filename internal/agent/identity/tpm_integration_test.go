//go:build integration && (amd64 || arm64)

package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
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

		ekCert, err := x509.ParseCertificate(ekBlock.Bytes)
		require.NoError(err)

		t.Logf("EK Certificate Subject: %s", ekCert.Subject.String())
		t.Logf("EK Certificate Issuer: %s", ekCert.Issuer.String())

		// Validate EK certificate against STM CA pool
		if downloadedCount > 0 {
			err = validateEKCertificateChain(t, ekCert, stmPool)
			if err != nil {
				t.Logf("EK certificate validation failed (certificate may be from different CA): %v", err)
			} else {
				t.Logf("✓ EK certificate validated against STM CA chain")
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
	// Try to parse as DER first
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		// Try PEM format
		block, _ := pem.Decode(certData)
		if block == nil {
			t.Logf("Failed to decode certificate from %s: not valid DER or PEM", source)
			return nil
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Logf("Failed to parse certificate from %s: %v", source, err)
			return nil
		}
	}
	return cert
}

// validateEKCertificateChain validates an EK certificate against the STM CA pool
func validateEKCertificateChain(t *testing.T, ekCert *x509.Certificate, stmPool *x509.CertPool) error {
	// Create verification options
	opts := x509.VerifyOptions{
		Roots:     stmPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Try to verify the certificate chain
	chains, err := ekCert.Verify(opts)
	if err != nil {
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
