//! Real post-quantum signature verification using NIST-standardized algorithms.
//! ML-DSA-65 (Dilithium3), FALCON-512, SLH-DSA-SHA2-128f (SPHINCS+).
//! This is not structural validation. This is the actual math.

use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

/// Verify an ML-DSA-65 (Dilithium3) signature against a public key and message.
pub fn verify_mldsa65(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    use pqcrypto_dilithium::dilithium3;

    let pk = dilithium3::PublicKey::from_bytes(public_key).map_err(|_| {
        format!(
            "Invalid ML-DSA-65 public key ({} bytes, expected {})",
            public_key.len(),
            dilithium3::public_key_bytes()
        )
    })?;

    let sig = dilithium3::DetachedSignature::from_bytes(signature).map_err(|_| {
        format!(
            "Invalid ML-DSA-65 signature ({} bytes, expected {})",
            signature.len(),
            dilithium3::signature_bytes()
        )
    })?;

    match pqcrypto_dilithium::dilithium3::verify_detached_signature(&sig, message, &pk) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify a FALCON-512 signature against a public key and message.
pub fn verify_falcon512(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    use pqcrypto_falcon::falcon512;

    let pk = falcon512::PublicKey::from_bytes(public_key).map_err(|_| {
        format!(
            "Invalid FALCON-512 public key ({} bytes, expected {})",
            public_key.len(),
            falcon512::public_key_bytes()
        )
    })?;

    let sig = falcon512::DetachedSignature::from_bytes(signature).map_err(|_| {
        format!(
            "Invalid FALCON-512 signature ({} bytes, expected up to {})",
            signature.len(),
            falcon512::signature_bytes()
        )
    })?;

    match pqcrypto_falcon::falcon512::verify_detached_signature(&sig, message, &pk) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify an SLH-DSA-SHA2-128f (SPHINCS+-SHA2-128f-simple) signature.
pub fn verify_slhdsa128f(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    use pqcrypto_sphincsplus::sphincssha2128fsimple;

    let pk = sphincssha2128fsimple::PublicKey::from_bytes(public_key).map_err(|_| {
        format!(
            "Invalid SLH-DSA public key ({} bytes, expected {})",
            public_key.len(),
            sphincssha2128fsimple::public_key_bytes()
        )
    })?;

    let sig = sphincssha2128fsimple::DetachedSignature::from_bytes(signature).map_err(|_| {
        format!(
            "Invalid SLH-DSA signature ({} bytes, expected {})",
            signature.len(),
            sphincssha2128fsimple::signature_bytes()
        )
    })?;

    match pqcrypto_sphincsplus::sphincssha2128fsimple::verify_detached_signature(
        &sig, message, &pk,
    ) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generate a test keypair and sign a message (for testing and demo purposes).
pub fn generate_test_bundle(message: &[u8]) -> TestBundle {
    use pqcrypto_dilithium::dilithium3;
    use pqcrypto_falcon::falcon512;
    use pqcrypto_sphincsplus::sphincssha2128fsimple;

    let (mldsa_pk, mldsa_sk) = dilithium3::keypair();
    let mldsa_sig = dilithium3::detached_sign(message, &mldsa_sk);

    let (falcon_pk, falcon_sk) = falcon512::keypair();
    let falcon_sig = falcon512::detached_sign(message, &falcon_sk);

    let (slhdsa_pk, slhdsa_sk) = sphincssha2128fsimple::keypair();
    let slhdsa_sig = sphincssha2128fsimple::detached_sign(message, &slhdsa_sk);

    TestBundle {
        mldsa_pk: mldsa_pk.as_bytes().to_vec(),
        mldsa_sig: mldsa_sig.as_bytes().to_vec(),
        falcon_pk: falcon_pk.as_bytes().to_vec(),
        falcon_sig: falcon_sig.as_bytes().to_vec(),
        slhdsa_pk: slhdsa_pk.as_bytes().to_vec(),
        slhdsa_sig: slhdsa_sig.as_bytes().to_vec(),
    }
}

pub struct TestBundle {
    pub mldsa_pk: Vec<u8>,
    pub mldsa_sig: Vec<u8>,
    pub falcon_pk: Vec<u8>,
    pub falcon_sig: Vec<u8>,
    pub slhdsa_pk: Vec<u8>,
    pub slhdsa_sig: Vec<u8>,
}

/// Verify all three families against a message.
pub fn verify_all(
    message: &[u8],
    mldsa_pk: &[u8],
    mldsa_sig: &[u8],
    falcon_pk: &[u8],
    falcon_sig: &[u8],
    slhdsa_pk: &[u8],
    slhdsa_sig: &[u8],
) -> CryptoVerificationResult {
    let mldsa = verify_mldsa65(mldsa_pk, message, mldsa_sig).unwrap_or(false);
    let falcon = verify_falcon512(falcon_pk, message, falcon_sig).unwrap_or(false);
    let slhdsa = verify_slhdsa128f(slhdsa_pk, message, slhdsa_sig).unwrap_or(false);

    let valid_count = [mldsa, falcon, slhdsa].iter().filter(|&&v| v).count();

    CryptoVerificationResult {
        mldsa_valid: mldsa,
        falcon_valid: falcon,
        slhdsa_valid: slhdsa,
        all_valid: valid_count == 3,
        two_of_three: valid_count >= 2,
    }
}

pub struct CryptoVerificationResult {
    pub mldsa_valid: bool,
    pub falcon_valid: bool,
    pub slhdsa_valid: bool,
    pub all_valid: bool,
    pub two_of_three: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa65_sign_verify() {
        let message = b"test message for ML-DSA-65";
        let bundle = generate_test_bundle(message);
        assert!(verify_mldsa65(&bundle.mldsa_pk, message, &bundle.mldsa_sig).unwrap());
    }

    #[test]
    fn test_falcon512_sign_verify() {
        let message = b"test message for FALCON-512";
        let bundle = generate_test_bundle(message);
        assert!(verify_falcon512(&bundle.falcon_pk, message, &bundle.falcon_sig).unwrap());
    }

    #[test]
    fn test_slhdsa_sign_verify() {
        let message = b"test message for SLH-DSA";
        let bundle = generate_test_bundle(message);
        assert!(verify_slhdsa128f(&bundle.slhdsa_pk, message, &bundle.slhdsa_sig).unwrap());
    }

    #[test]
    fn test_verify_all_three() {
        let message = b"test all three families";
        let bundle = generate_test_bundle(message);
        let result = verify_all(
            message,
            &bundle.mldsa_pk,
            &bundle.mldsa_sig,
            &bundle.falcon_pk,
            &bundle.falcon_sig,
            &bundle.slhdsa_pk,
            &bundle.slhdsa_sig,
        );
        assert!(result.all_valid);
        assert!(result.two_of_three);
    }

    #[test]
    fn test_wrong_message_fails() {
        let message = b"original message";
        let wrong = b"wrong message";
        let bundle = generate_test_bundle(message);
        assert!(!verify_mldsa65(&bundle.mldsa_pk, wrong, &bundle.mldsa_sig).unwrap());
    }

    #[test]
    fn test_two_of_three_with_one_bad() {
        let message = b"two of three test";
        let bundle = generate_test_bundle(message);
        // Corrupt the SLH-DSA signature by using a wrong-length or bad sig
        // We can't use arbitrary bytes for from_bytes (it checks length),
        // so we sign with a different message to get a valid-format but wrong sig
        let wrong_message = b"wrong message for slhdsa";
        let wrong_bundle = generate_test_bundle(wrong_message);
        let result = verify_all(
            message,
            &bundle.mldsa_pk,
            &bundle.mldsa_sig,
            &bundle.falcon_pk,
            &bundle.falcon_sig,
            &bundle.slhdsa_pk,
            &wrong_bundle.slhdsa_sig, // valid format, wrong message
        );
        assert!(result.mldsa_valid);
        assert!(result.falcon_valid);
        assert!(!result.slhdsa_valid);
        assert!(result.two_of_three);
        assert!(!result.all_valid);
    }
}
