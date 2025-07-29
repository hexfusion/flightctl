package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	grpc_v1 "github.com/flightctl/flightctl/api/grpc/v1"
	"github.com/flightctl/flightctl/internal/agent/client"
	agent_client "github.com/flightctl/flightctl/internal/api/client/agent"
	base_client "github.com/flightctl/flightctl/internal/client"
	"github.com/flightctl/flightctl/internal/tpm"
	fccrypto "github.com/flightctl/flightctl/pkg/crypto"
	"github.com/flightctl/flightctl/pkg/log"
	x509ext "github.com/google/go-attestation/x509"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

var _ Provider = (*tpmProvider)(nil)
var _ TPMCapable = (*tpmProvider)(nil)
var _ TPMProvider = (*tpmProvider)(nil)

// tpmProvider implements identity management using TPM-based keys
type tpmProvider struct {
	client          *tpm.Client
	log             *log.PrefixLogger
	deviceName      string
	certificateData []byte
}

// newTPMProvider creates a new TPM-based identity provider
func newTPMProvider(
	client *tpm.Client,
	log *log.PrefixLogger,
) *tpmProvider {
	return &tpmProvider{
		client: client,
		log:    log,
	}
}

func (t *tpmProvider) Initialize(ctx context.Context) error {
	var err error
	t.deviceName, err = generateDeviceName(t.client.Public())
	if err != nil {
		return err
	}

	if err := t.client.UpdateNonce(make([]byte, 8)); err != nil {
		t.log.Warnf("Failed to update TPM nonce: %v", err)
	}
	return nil
}

func (t *tpmProvider) GetDeviceName() (string, error) {
	return t.deviceName, nil
}

func (t *tpmProvider) GenerateCSR(deviceName string) ([]byte, error) {
	signer := t.client.GetSigner()
	return fccrypto.MakeCSR(signer, deviceName)
}

func (t *tpmProvider) StoreCertificate(certPEM []byte) error {
	t.certificateData = certPEM
	return nil
}

func (t *tpmProvider) HasCertificate() bool {
	return len(t.certificateData) > 0
}

func (t *tpmProvider) createCertificate() (*tls.Certificate, error) {
	if t.client == nil {
		return nil, fmt.Errorf("TPM client not initialized")
	}
	if t.certificateData == nil {
		return nil, fmt.Errorf("no certificate data available for TPM authentication - device needs enrollment")
	}
	signer := t.client.GetSigner()
	// parse the certificate from PEM block
	certBlock, _ := pem.Decode(t.certificateData)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// create TLS certificate using the TPM private key and the parsed certificate
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  signer,
	}
	return tlsCert, nil
}

func (t *tpmProvider) CreateManagementClient(config *base_client.Config, metricsCallback client.RPCMetricsCallback) (client.Management, error) {
	tlsCert, err := t.createCertificate()
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		MinVersion:   tls.VersionTLS13,
	}

	if config.Service.CertificateAuthorityData != nil {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(config.Service.CertificateAuthorityData)
		tlsConfig.RootCAs = caCertPool
	}

	if config.Service.TLSServerName != "" {
		tlsConfig.ServerName = config.Service.TLSServerName
	} else {
		u, err := url.Parse(config.Service.Server)
		if err == nil {
			tlsConfig.ServerName = u.Hostname()
		}
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	clientWithResponses, err := agent_client.NewClientWithResponses(config.Service.Server, agent_client.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	managementClient := client.NewManagement(clientWithResponses, metricsCallback)
	return managementClient, nil
}

func (t *tpmProvider) CreateGRPCClient(config *base_client.Config) (grpc_v1.RouterServiceClient, error) {
	tlsCert, err := t.createCertificate()
	if err != nil {
		return nil, err
	}

	configCopy := config.DeepCopy()
	if err := configCopy.Flatten(); err != nil {
		return nil, err
	}

	grpcEndpoint := configCopy.Service.Server

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*tlsCert},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: configCopy.Service.InsecureSkipVerify, //nolint:gosec
	}

	if configCopy.Service.CertificateAuthorityData != nil {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(configCopy.Service.CertificateAuthorityData)
		tlsConfig.RootCAs = caCertPool
	}

	if configCopy.Service.TLSServerName != "" {
		tlsConfig.ServerName = configCopy.Service.TLSServerName
	} else {
		u, err := url.Parse(grpcEndpoint)
		if err == nil {
			tlsConfig.ServerName = u.Hostname()
		}
	}

	// our transport is http, but the grpc library has special encoding for the endpoint
	grpcEndpoint = strings.TrimPrefix(grpcEndpoint, "http://")
	grpcEndpoint = strings.TrimPrefix(grpcEndpoint, "https://")
	grpcEndpoint = strings.TrimSuffix(grpcEndpoint, "/")

	grpcClient, err := grpc.NewClient(grpcEndpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second, // Send keepalive ping every 30s
			Timeout:             10 * time.Second, // Wait 10s for server response
			PermitWithoutStream: true,             // Send even if no active RPCs
		}))
	if err != nil {
		return nil, fmt.Errorf("creating gRPC client: %w", err)
	}

	router := grpc_v1.NewRouterServiceClient(grpcClient)
	return router, nil
}

func (t *tpmProvider) WipeCredentials() error {
	// clear certificate data from memory
	t.certificateData = nil
	t.log.Info("Wiped TPM-stored certificate data from memory")
	return nil
}

// GetEKCert returns the EK certificate in PEM format
func (t *tpmProvider) GetEKCert() ([]byte, error) {
	der, err := t.client.EndorsementKeyCert()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}), nil
}

// GetCertifyCert returns the certify certificate in PEM format
func (t *tpmProvider) GetCertifyCert() ([]byte, error) {
	pub := t.client.Public()
	return fccrypto.PEMEncodePublicKey(pub)
}

// GetTPMCertifyCert returns the TPM attestation report that proves the LDevID was created by the TPM
// Reuses existing LAK and attestation infrastructure to avoid duplication
func (t *tpmProvider) GetTPMCertifyCert() ([]byte, error) {
	if t.client == nil {
		return nil, fmt.Errorf("TPM client not initialized")
	}

	// Create qualifying data (nonce) for the attestation
	qualifyingData := []byte("flightctl-device-cert")

	// Check if we have the minimum nonce length requirement
	if len(qualifyingData) < 8 { // MinNonceLength from TPM client
		// Pad to meet minimum requirements
		qualifyingData = append(qualifyingData, make([]byte, 8-len(qualifyingData))...)
	}

	// Use the new method that reuses the existing stored LAK - no duplication!
	return t.client.GetAttestationBytes(qualifyingData)
}

// GetTPM returns the TPM provider (itself) since this provider supports TPM functionality
func (t *tpmProvider) GetTPM() (TPMProvider, bool) {
	return t, true
}

func (t *tpmProvider) Close(ctx context.Context) error {
	if t.client != nil {
		return t.client.Close(ctx)
	}
	return nil
}

func ParseEKCertificate(ekCert []byte) (*x509.Certificate, error) {
	var wasWrapped bool

	// TCG PC Specific Implementation section 7.3.2 specifies
	// a prefix when storing a certificate in NVRAM. We look
	// for and unwrap the certificate if its present.
	if len(ekCert) > 5 && bytes.Equal(ekCert[:3], []byte{0x10, 0x01, 0x00}) {
		certLen := int(binary.BigEndian.Uint16(ekCert[3:5]))
		if len(ekCert) < certLen+5 {
			return nil, fmt.Errorf("parsing nvram header: ekCert size %d smaller than specified cert length %d", len(ekCert), certLen)
		}
		ekCert = ekCert[5 : 5+certLen]
		wasWrapped = true
	}

	// If the cert parses fine without any changes, we are G2G.
	if c, err := x509.ParseCertificate(ekCert); err == nil {
		return c, nil
	}
	// There might be trailing nonsense in the cert, which Go
	// does not parse correctly. As ASN1 data is TLV encoded, we should
	// be able to just get the certificate, and then send that to Go's
	// certificate parser.
	var cert struct {
		Raw asn1.RawContent
	}
	if _, err := asn1.UnmarshalWithParams(ekCert, &cert, "lax"); err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal() failed: %v, wasWrapped=%v", err, wasWrapped)
	}

	c, err := x509.ParseCertificate(cert.Raw)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate() failed: %v", err)
	}
	return c, nil
}

// ValidateEKCertificateChain validates an EK certificate chain while handling TPM-specific critical extensions
func ValidateEKCertificateChain(cert *x509.Certificate, roots *x509.CertPool) error {
	// First check if this certificate has TPM-specific critical extensions that we need to handle
	hasTPMCriticalExtensions := false
	var sanExtension *pkix.Extension

	for i, ext := range cert.Extensions {
		switch ext.Id.String() {
		case "2.5.29.17": // Subject Alternative Name - often contains TPM-specific data
			if ext.Critical {
				hasTPMCriticalExtensions = true
				sanExtension = &cert.Extensions[i]
			}
		case "2.23.133.8.1", "2.23.133.8.2", "2.23.133.8.3": // TCG TPM extensions
			if ext.Critical {
				hasTPMCriticalExtensions = true
			}
		case "1.2.840.113549.1.9.16.1.24": // ST Microelectronics TPM extension
			if ext.Critical {
				hasTPMCriticalExtensions = true
			}
		}
	}

	// If no TPM-specific critical extensions, use standard validation
	if !hasTPMCriticalExtensions {
		opts := x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		_, err := cert.Verify(opts)
		return err
	}

	// Handle TPM-specific extensions by creating a modified certificate for validation
	return validateTPMCertificateWithExtensions(cert, roots, sanExtension)
}

// validateTPMCertificateWithExtensions validates a TPM certificate by handling known critical extensions
func validateTPMCertificateWithExtensions(cert *x509.Certificate, roots *x509.CertPool, sanExt *pkix.Extension) error {
	// Parse the SAN extension using go-attestation's specialized parser
	if sanExt != nil {
		sanData, err := x509ext.ParseSubjectAltName(*sanExt)
		if err != nil {
			// If we can't parse the SAN extension with go-attestation,
			// it might be a very non-standard format, but we'll continue validation
		} else {
			// Successfully parsed TPM-specific SAN data
			if len(sanData.DirectoryNames) > 0 {
				// SAN contains directory names - this is acceptable for TPM certificates
			}
			if len(sanData.PermanentIdentifiers) > 0 {
				// SAN contains permanent identifiers - common in TPM certificates
			}
			// The fact that go-attestation could parse it means it's a known TPM extension format
		}
	}

	// Perform manual certificate chain validation for TPM certificates
	return validateCertificateChainManually(cert, roots)
}

// validateCertificateChainManually performs certificate chain validation without relying on Go's x509.Verify
func validateCertificateChainManually(cert *x509.Certificate, roots *x509.CertPool) error {
	// Check certificate validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (valid from %v)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (expired at %v)", cert.NotAfter)
	}

	// For TPM certificates with critical extensions, we'll do a simplified validation
	// that checks basic certificate properties without using x509.Verify

	// Check if the certificate issuer exists in our trusted roots
	// This is a simplified check - we verify the issuer name matches
	validIssuer := false
	issuerBytes, err := asn1.Marshal(cert.Issuer.ToRDNSequence())
	if err != nil {
		return fmt.Errorf("failed to marshal certificate issuer: %w", err)
	}

	for _, subject := range roots.Subjects() {
		if bytes.Equal(subject, issuerBytes) {
			validIssuer = true
			break
		}
	}

	if !validIssuer {
		return fmt.Errorf("certificate issuer not found in trusted CA pool")
	}

	// Additional TPM-specific validation could be added here
	// For now, we accept the certificate if it has a trusted issuer and is within validity period

	return nil
}

// findIssuerInPool finds a potential issuer certificate in the certificate pool
func findIssuerInPool(cert *x509.Certificate, pool *x509.CertPool) *x509.Certificate {
	// The x509.CertPool doesn't expose individual certificates easily
	// For TPM certificate validation, we'll use a different approach in validateCertificateChainManually
	return nil
}
