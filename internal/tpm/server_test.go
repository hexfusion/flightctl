package tpm

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoveSANFromUnhandledExtensions(t *testing.T) {
	// SAN OID: 2.5.29.17
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	// Some other OIDs for testing
	keyUsageOID := asn1.ObjectIdentifier{2, 5, 29, 15}
	basicConstraintsOID := asn1.ObjectIdentifier{2, 5, 29, 19}
	extKeyUsageOID := asn1.ObjectIdentifier{2, 5, 29, 37}

	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected []asn1.ObjectIdentifier
	}{
		{
			name:     "nil certificate",
			cert:     nil,
			expected: nil,
		},
		{
			name: "empty unhandled extensions",
			cert: &x509.Certificate{
				UnhandledCriticalExtensions: []asn1.ObjectIdentifier{},
			},
			expected: []asn1.ObjectIdentifier{},
		},
		{
			name: "no SAN extension",
			cert: &x509.Certificate{
				UnhandledCriticalExtensions: []asn1.ObjectIdentifier{
					keyUsageOID,
					basicConstraintsOID,
				},
			},
			expected: []asn1.ObjectIdentifier{
				keyUsageOID,
				basicConstraintsOID,
			},
		},
		{
			name: "only SAN extension",
			cert: &x509.Certificate{
				UnhandledCriticalExtensions: []asn1.ObjectIdentifier{
					sanOID,
				},
			},
			expected: []asn1.ObjectIdentifier{},
		},
		{
			name: "SAN extension at beginning",
			cert: &x509.Certificate{
				UnhandledCriticalExtensions: []asn1.ObjectIdentifier{
					sanOID,
					keyUsageOID,
					basicConstraintsOID,
				},
			},
			expected: []asn1.ObjectIdentifier{
				keyUsageOID,
				basicConstraintsOID,
			},
		},
		{
			name: "SAN extension in middle",
			cert: &x509.Certificate{
				UnhandledCriticalExtensions: []asn1.ObjectIdentifier{
					keyUsageOID,
					sanOID,
					basicConstraintsOID,
				},
			},
			expected: []asn1.ObjectIdentifier{
				keyUsageOID,
				basicConstraintsOID,
			},
		},
		{
			name: "SAN extension at end",
			cert: &x509.Certificate{
				UnhandledCriticalExtensions: []asn1.ObjectIdentifier{
					keyUsageOID,
					basicConstraintsOID,
					sanOID,
				},
			},
			expected: []asn1.ObjectIdentifier{
				keyUsageOID,
				basicConstraintsOID,
			},
		},
		{
			name: "multiple SAN extensions",
			cert: &x509.Certificate{
				UnhandledCriticalExtensions: []asn1.ObjectIdentifier{
					sanOID,
					keyUsageOID,
					sanOID,
					basicConstraintsOID,
					sanOID,
				},
			},
			expected: []asn1.ObjectIdentifier{
				keyUsageOID,
				basicConstraintsOID,
			},
		},
		{
			name: "all extensions are SAN",
			cert: &x509.Certificate{
				UnhandledCriticalExtensions: []asn1.ObjectIdentifier{
					sanOID,
					sanOID,
					sanOID,
				},
			},
			expected: []asn1.ObjectIdentifier{},
		},
		{
			name: "mixed extensions with duplicates",
			cert: &x509.Certificate{
				UnhandledCriticalExtensions: []asn1.ObjectIdentifier{
					keyUsageOID,
					sanOID,
					keyUsageOID,
					extKeyUsageOID,
					sanOID,
					basicConstraintsOID,
				},
			},
			expected: []asn1.ObjectIdentifier{
				keyUsageOID,
				keyUsageOID,
				extKeyUsageOID,
				basicConstraintsOID,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy if cert is not nil to avoid modifying test data
			var testCert *x509.Certificate
			if tt.cert != nil {
				testCert = &x509.Certificate{
					UnhandledCriticalExtensions: make([]asn1.ObjectIdentifier, len(tt.cert.UnhandledCriticalExtensions)),
				}
				copy(testCert.UnhandledCriticalExtensions, tt.cert.UnhandledCriticalExtensions)
			}

			removeSANFromUnhandledExtensions(testCert)

			if testCert == nil {
				assert.Nil(t, tt.expected)
			} else {
				require.Equal(t, len(tt.expected), len(testCert.UnhandledCriticalExtensions),
					"expected %d extensions, got %d", len(tt.expected), len(testCert.UnhandledCriticalExtensions))
				assert.Equal(t, tt.expected, testCert.UnhandledCriticalExtensions)
			}
		})
	}
}

func TestRemoveSANFromUnhandledExtensions_PreservesOrder(t *testing.T) {
	// Ensure that non-SAN extensions maintain their relative order
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	oid1 := asn1.ObjectIdentifier{1, 2, 3, 4}
	oid2 := asn1.ObjectIdentifier{1, 2, 3, 5}
	oid3 := asn1.ObjectIdentifier{1, 2, 3, 6}
	oid4 := asn1.ObjectIdentifier{1, 2, 3, 7}

	cert := &x509.Certificate{
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{
			oid1,
			sanOID,
			oid2,
			oid3,
			sanOID,
			oid4,
		},
	}

	removeSANFromUnhandledExtensions(cert)

	expected := []asn1.ObjectIdentifier{oid1, oid2, oid3, oid4}
	assert.Equal(t, expected, cert.UnhandledCriticalExtensions, "order of non-SAN OIDs should be preserved")
}
