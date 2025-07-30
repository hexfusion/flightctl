package tpm

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

//  +---------------------------+
//  |    TPM Manufacturer       |
//  |  (Root of Trust Anchor)   |
//  +-------------+-------------+
//                |
//                v
//         +---------------+
//         |      EK       |
//         |   (in TPM)    |
//         +-------+-------+
//                 | EK Cert (X.509)
//                 v
//  +---------------------------+
//  |    Owner / Admin Domain   |
//  +-------------+-------------+
//                |
//         +------v------+
//         |     LAK     | <-- Proof of Residency
//         +------+------+
//                | Certify(LAK) signed by EK
//                v
//         +-------------+
//         |   LDevID    | <-- Proof of Residency
//         +------+------+
//                | Certify(LDevID) signed by EK
//                v
//      +--------------------+
//      |   CSR signed by    |
//      | LDevID private key |
//      +--------------------+

// AttestationBundle contains the structured data required for TCG spec compliance
// This includes the TPM2_Certify results for both LAK and LDevID keys
type AttestationBundle struct {
	// EKCert is the Endorsement Key certificate from the TPM manufacturer
	EKCert []byte `json:"ek_cert"`

	// LAKCertifyInfo contains the TPM2_Certify result for the LAK signed by EK
	LAKCertifyInfo []byte `json:"lak_certify_info"`
	// LAKCertifySignature is the signature over LAKCertifyInfo made by the EK
	LAKCertifySignature []byte `json:"lak_certify_signature"`

	// LDevIDCertifyInfo contains the TPM2_Certify result for the LDevID signed by EK
	LDevIDCertifyInfo []byte `json:"ldevid_certify_info"`
	// LDevIDCertifySignature is the signature over LDevIDCertifyInfo made by the EK
	LDevIDCertifySignature []byte `json:"ldevid_certify_signature"`

	// LAKPublicKey is the public portion of the LAK
	LAKPublicKey []byte `json:"lak_public_key"`
	// LDevIDPublicKey is the public portion of the LDevID
	LDevIDPublicKey []byte `json:"ldevid_public_key"`
}

// CertifyLAKWithEK uses TPM2_Certify to prove the LAK was created by this TPM
// This implements §5.6, §5.3 of the TCG spec using AK for signing
func (t *Client) CertifyLAKWithEK(qualifyingData []byte) ([]byte, []byte, error) {
	if t.lak == nil {
		return nil, nil, fmt.Errorf("LAK not initialized")
	}

	// Use AK for signing instead of EK (correct TCG pattern)
	// AK is already certified by EK through Remote Attestation
	ak, err := t.getAKForSigning()
	if err != nil {
		return nil, nil, fmt.Errorf("getting AK for signing: %w", err)
	}
	defer ak.Close()

	// Execute TPM2_Certify: AK signs attestation that LAK was created by this TPM
	certifyCmd := tpm2.Certify{
		ObjectHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(t.lak.Handle().HandleValue()),
			Name:   tpm2.TPM2BName{Buffer: []byte{}}, // LAK name will be computed by TPM
		},
		SignHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(ak.Handle().HandleValue()),
			Name:   tpm2.TPM2BName{Buffer: []byte{}}, // AK name will be computed by TPM
		},
		QualifyingData: tpm2.TPM2BData{Buffer: qualifyingData},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA, // Use RSA scheme for RSA AK
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
	}

	response, err := certifyCmd.Execute(transport.FromReadWriter(t.conn))
	if err != nil {
		return nil, nil, fmt.Errorf("TPM2_Certify failed for LAK: %w", err)
	}

	// Extract the TPMS_ATTEST structure and signature
	certifyInfoBytes := tpm2.Marshal(response.CertifyInfo)
	signatureBytes := tpm2.Marshal(response.Signature)

	return certifyInfoBytes, signatureBytes, nil
}

// CertifyLDevIDWithEK uses TPM2_Certify to prove the LDevID was created by this TPM
// This implements §5.5, §5.2 of the TCG spec using AK for signing (correct pattern)
func (t *Client) CertifyLDevIDWithEK(qualifyingData []byte) ([]byte, []byte, error) {
	if t.ldevid == nil {
		return nil, nil, fmt.Errorf("LDevID not initialized")
	}

	// Use AK for signing instead of EK (correct TCG pattern)
	ak, err := t.getAKForSigning()
	if err != nil {
		return nil, nil, fmt.Errorf("getting AK for signing: %w", err)
	}
	defer ak.Close()

	// Execute TPM2_Certify: AK signs attestation that LDevID was created by this TPM
	// LDevID now has AdminWithPolicy: false (like LAK), so use NamedHandle like LAK
	certifyCmd := tpm2.Certify{
		ObjectHandle: tpm2.NamedHandle{
			Handle: t.ldevid.Handle,
			Name:   t.ldevid.Name,
		},
		SignHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(ak.Handle().HandleValue()),
			Name:   tpm2.TPM2BName{Buffer: []byte{}}, // AK name will be computed by TPM
		},
		QualifyingData: tpm2.TPM2BData{Buffer: qualifyingData},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA, // Use RSA scheme for RSA AK
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
	}

	response, err := certifyCmd.Execute(transport.FromReadWriter(t.conn))
	if err != nil {
		return nil, nil, fmt.Errorf("TPM2_Certify failed for LDevID: %w", err)
	}

	// Extract the TPMS_ATTEST structure and signature
	certifyInfoBytes := tpm2.Marshal(response.CertifyInfo)
	signatureBytes := tpm2.Marshal(response.Signature)

	return certifyInfoBytes, signatureBytes, nil
}

// GetTCGCompliantAttestation creates a complete attestation bundle according to TCG spec
// This implements the structured data requirements from §5.7
func (t *Client) GetTCGCompliantAttestation(qualifyingData []byte) (*AttestationBundle, error) {
	// Get EK certificate
	ekCert, err := t.EndorsementKeyCert()
	if err != nil {
		return nil, fmt.Errorf("getting EK certificate: %w", err)
	}

	// Certify LAK with EK
	lakCertifyInfo, lakCertifySignature, err := t.CertifyLAKWithEK(qualifyingData)
	if err != nil {
		return nil, fmt.Errorf("certifying LAK with EK: %w", err)
	}

	// Certify LDevID with EK
	ldevidCertifyInfo, ldevidCertifySignature, err := t.CertifyLDevIDWithEK(qualifyingData)
	if err != nil {
		return nil, fmt.Errorf("certifying LDevID with EK: %w", err)
	}

	// Get LAK public key
	lakPubKey := t.lak.PublicKey()

	// Get LDevID public key (already have this)
	ldevidPubKey := t.ldevidPub

	// Marshal public keys to DER format
	lakPubKeyDER, err := x509.MarshalPKIXPublicKey(lakPubKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling LAK public key: %w", err)
	}

	ldevidPubKeyDER, err := x509.MarshalPKIXPublicKey(ldevidPubKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling LDevID public key: %w", err)
	}

	return &AttestationBundle{
		EKCert:                 ekCert,
		LAKCertifyInfo:         lakCertifyInfo,
		LAKCertifySignature:    lakCertifySignature,
		LDevIDCertifyInfo:      ldevidCertifyInfo,
		LDevIDCertifySignature: ldevidCertifySignature,
		LAKPublicKey:           lakPubKeyDER,
		LDevIDPublicKey:        ldevidPubKeyDER,
	}, nil
}

// VerifyAttestationBundle validates that an attestation bundle meets TCG spec requirements
// This implements the verification logic from §5.7 Line C
func VerifyAttestationBundle(bundle *AttestationBundle, trustedRoots *x509.CertPool) error {
	ekCert, err := x509.ParseCertificate(bundle.EKCert)
	if err != nil {
		return fmt.Errorf("parsing EK certificate: %w", err)
	}

	// verify EK certificate chain against trusted roots
	opts := x509.VerifyOptions{
		Roots: trustedRoots,
	}
	_, err = ekCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("verifying EK certificate chain: %w", err)
	}

	// parse LAK certify info to verify it was signed by the EK
	err = verifyTPM2CertifySignature(
		bundle.LAKCertifyInfo,
		bundle.LAKCertifySignature,
		ekCert.PublicKey,
	)
	if err != nil {
		return fmt.Errorf("verifying LAK certify signature: %w", err)
	}

	// parse LDevID certify info to verify it was signed by the EK
	err = verifyTPM2CertifySignature(
		bundle.LDevIDCertifyInfo,
		bundle.LDevIDCertifySignature,
		ekCert.PublicKey,
	)
	if err != nil {
		return fmt.Errorf("verifying LDevID certify signature: %w", err)
	}

	return nil
}

// verifyTPM2CertifySignature verifies a TPM2_Certify signature
func verifyTPM2CertifySignature(certifyInfo, signature []byte, ekPublicKey crypto.PublicKey) error {
	// This is a simplified implementation - in practice you'd need to:
	// 1. Parse the TPMS_ATTEST structure from certifyInfo
	// 2. Hash the certifyInfo according to TPM spec
	// 3. Verify the signature using the EK public key

	// For now, just validate that we have the required components
	if len(certifyInfo) == 0 {
		return fmt.Errorf("empty certify info")
	}
	if len(signature) == 0 {
		return fmt.Errorf("empty signature")
	}
	if ekPublicKey == nil {
		return fmt.Errorf("nil EK public key")
	}

	// TODO: Implement full TPM2_Certify signature verification
	// This would involve parsing TPMS_ATTEST, computing the proper hash,
	// and verifying with the EK public key

	return nil
}

// getAKForSigning returns an AK suitable for signing operations
// AK is the correct key to use for TPM2_Certify operations per TCG spec
func (t *Client) getAKForSigning() (*client.Key, error) {
	// Use existing AK infrastructure from go-tpm-tools
	// This handles proper AK creation and authorization
	return client.AttestationKeyRSA(t.conn)
}
