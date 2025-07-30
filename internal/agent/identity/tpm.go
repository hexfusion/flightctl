package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
// Now uses TCG compliant attestation with EK->LAK and EK->LDevID certify operations
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

	// Use the new TCG compliant attestation method
	return t.client.GetTCGAttestationBytes(qualifyingData)
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
	// TPM certificates often contain critical extensions that Go's x509 library doesn't recognize.
	// We temporarily remove known TPM critical extensions from the unhandled list to allow
	// standard validation to proceed, then restore them.

	// Store original unhandled extensions
	originalUnhandled := make([]asn1.ObjectIdentifier, len(cert.UnhandledCriticalExtensions))
	copy(originalUnhandled, cert.UnhandledCriticalExtensions)

	// Temporarily remove known TPM critical extensions
	removeKnownTPMExtensions(cert)

	// Attempt standard validation with full security checks
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	_, err := cert.Verify(opts)

	// Restore original unhandled extensions list
	cert.UnhandledCriticalExtensions = originalUnhandled

	return err
}

// removeKnownTPMExtensions temporarily removes known TPM critical extensions
// from the certificate's UnhandledCriticalExtensions list.
//
// This allows Go's standard x509.Verify() to proceed with full cryptographic
// validation while bypassing only the specific extensions we know are safe.
func removeKnownTPMExtensions(cert *x509.Certificate) {
	// Define TPM-specific critical extensions that we can safely ignore during validation.
	// These are commonly found in TPM EK certificates and contain vendor-specific data.
	knownTPMExtensionOIDs := []asn1.ObjectIdentifier{
		{2, 5, 29, 17}, // Subject Alternative Name (with TPM-specific directoryName content)
		{2, 5, 29, 19}, // Basic Constraints (sometimes with vendor-specific values)
		// Additional TPM extension OIDs can be added here as needed:
		// {2, 23, 133, 8, 1}, // TCG TPM Manufacturer
		// {2, 23, 133, 8, 2}, // TCG TPM Model
		// {2, 23, 133, 8, 3}, // TCG TPM Version
	}

	// Filter out known TPM extensions from unhandled critical extensions
	filtered := cert.UnhandledCriticalExtensions[:0] // Reuse slice capacity
	for _, unhandledOID := range cert.UnhandledCriticalExtensions {
		isKnownTPMExt := false
		for _, knownOID := range knownTPMExtensionOIDs {
			if unhandledOID.Equal(knownOID) {
				isKnownTPMExt = true
				break
			}
		}
		if !isKnownTPMExt {
			filtered = append(filtered, unhandledOID)
		}
	}
	cert.UnhandledCriticalExtensions = filtered
}
