package verify

import (
	"crypto/x509"
)

// validateKeyUsage validates certificate Key Usage and Extended Key Usage for PDF signing
// according to RFC 9336 and common industry practices
func validateKeyUsage(cert *x509.Certificate, options *VerifyOptions) (kuValid bool, kuError string, ekuValid bool, ekuError string) {
	// Validate Key Usage
	kuValid = true
	ekuValid = true

	// Check Digital Signature bit in Key Usage
	if options.RequireDigitalSignatureKU && (cert.KeyUsage&x509.KeyUsageDigitalSignature) == 0 {
		kuValid = false
		kuError = "certificate does not have Digital Signature key usage"
	}

	// Check for Non-Repudiation (Content Commitment) if present
	// This is optional but recommended for PDF signing
	if options.AllowNonRepudiationKU && (cert.KeyUsage&x509.KeyUsageContentCommitment) != 0 {
		// Non-repudiation is present and allowed - this is good
	}

	// Validate Extended Key Usage
	if len(cert.ExtKeyUsage) == 0 {
		ekuValid = false
		ekuError = "certificate has no Extended Key Usage extension"
		return
	}

	// Check if any required EKUs are present
	hasRequiredEKU := false
	if len(options.RequiredEKUs) > 0 {
		for _, requiredEKU := range options.RequiredEKUs {
			for _, certEKU := range cert.ExtKeyUsage {
				if certEKU == requiredEKU {
					hasRequiredEKU = true
					break
				}
			}
			if hasRequiredEKU {
				break
			}
		}
	}

	// Check if any allowed EKUs are present (fallback)
	hasAllowedEKU := false
	if len(options.AllowedEKUs) > 0 {
		for _, allowedEKU := range options.AllowedEKUs {
			for _, certEKU := range cert.ExtKeyUsage {
				if certEKU == allowedEKU {
					hasAllowedEKU = true
					break
				}
			}
			if hasAllowedEKU {
				break
			}
		}
	}

	// Check for ExtKeyUsageAny which is too permissive for PDF signing
	hasAnyEKU := false
	for _, certEKU := range cert.ExtKeyUsage {
		if certEKU == x509.ExtKeyUsageAny {
			hasAnyEKU = true
			break
		}
	}

	// Determine EKU validity
	if hasRequiredEKU {
		// Has a required EKU - this is the best case
		ekuValid = true
	} else if hasAllowedEKU {
		// Has an allowed EKU but not a required one
		ekuValid = true
		if len(options.RequiredEKUs) > 0 {
			ekuError = "certificate uses acceptable but not preferred Extended Key Usage"
		}
	} else if hasAnyEKU {
		// Has ExtKeyUsageAny - warn but don't fail for backward compatibility
		ekuValid = true
		ekuError = "certificate uses ExtKeyUsageAny which is too permissive for PDF signing"
	} else {
		// No suitable EKU found
		ekuValid = false
		ekuError = "certificate does not have suitable Extended Key Usage for PDF signing"
	}

	return
}

// getVerificationEKUs returns the appropriate Extended Key Usages for certificate verification
// Includes Document Signing EKU and common alternatives
func getVerificationEKUs() []x509.ExtKeyUsage {
	return []x509.ExtKeyUsage{
		x509.ExtKeyUsage(36),            // Document Signing EKU (1.3.6.1.5.5.7.3.36) per RFC 9336
		x509.ExtKeyUsageEmailProtection, // Email Protection (1.3.6.1.5.5.7.3.4) - common alternative
		x509.ExtKeyUsageClientAuth,      // Client Authentication (1.3.6.1.5.5.7.3.2) - another alternative
		x509.ExtKeyUsageAny,             // Any EKU - for backward compatibility (less secure)
	}
}
