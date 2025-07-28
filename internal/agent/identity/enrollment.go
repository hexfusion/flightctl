package identity

import (
	"fmt"

	"github.com/flightctl/flightctl/api/v1alpha1"
	"github.com/flightctl/flightctl/pkg/log"
)

// CreateEnrollmentRequest creates an enrollment request using the identity provider
// Automatically includes TPM attestation certificates if the provider supports them
func CreateEnrollmentRequest(
	log *log.PrefixLogger,
	identityProvider Provider,
	deviceStatus *v1alpha1.DeviceStatus,
	defaultLabels map[string]string,
) (*v1alpha1.EnrollmentRequest, error) {
	deviceName, err := identityProvider.GetDeviceName()
	if err != nil {
		return nil, fmt.Errorf("failed to get device name: %w", err)
	}

	csr, err := identityProvider.GenerateCSR(deviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSR: %w", err)
	}

	req := &v1alpha1.EnrollmentRequest{
		ApiVersion: "v1alpha1",
		Kind:       "EnrollmentRequest",
		Metadata: v1alpha1.ObjectMeta{
			Name: &deviceName,
		},
		Spec: v1alpha1.EnrollmentRequestSpec{
			Csr:          string(csr),
			DeviceStatus: deviceStatus,
			Labels:       &defaultLabels,
		},
	}

	// TPM certificates are best effort for enrollment. If they are not
	// available, the device will not be able to enroll as TPM verified but this
	// will be observable by the service.
	tpmProvider, ok := identityProvider.(*tpmProvider)
	if !ok {
		log.Warnf("Identity provider does not support TPM attestation")
		return req, nil
	}

	// Attempt to get EK certificate - this is optional and should not fail enrollment
	ekCert, err := tpmProvider.GetEKCert()
	if err != nil {
		log.Warnf("Failed to get EK cert (device will enroll without TPM attestation): %v", err)
		// Continue with enrollment without EK certificate
	} else if len(ekCert) > 0 {
		ekCertStr := string(ekCert)
		req.Spec.EkCert = &ekCertStr
		log.Debugf("Successfully included EK certificate in enrollment request")
	} else {
		log.Warnf("EK certificate is empty (device will enroll without TPM attestation)")
	}

	// Attempt to get TPM certify certificate - this is the TPM2 Certify structure signed by the EK/AK
	tpmCertifyCert, err := tpmProvider.GetTPMCertifyCert()
	if err != nil {
		log.Warnf("Failed to get TPM certify cert (continuing enrollment without TPM attestation): %v", err)
	} else if len(tpmCertifyCert) > 0 {
		tpmCertifyCertStr := string(tpmCertifyCert)
		req.Spec.TpmCertifyCert = &tpmCertifyCertStr
		log.Debugf("Successfully included TPM certify certificate in enrollment request")
	}

	// Get the credential public key - this is the PEM-encoded public key that must match the CSR
	credentialPubKey, err := tpmProvider.GetCertifyCert()
	if err != nil {
		log.Warnf("Failed to get credential public key (continuing enrollment without TPM attestation): %v", err)
	} else if len(credentialPubKey) > 0 {
		credentialPubKeyStr := string(credentialPubKey)
		req.Spec.CredentialPublicKey = &credentialPubKeyStr
		log.Debugf("Successfully included credential public key in enrollment request")
	}

	return req, nil
}
