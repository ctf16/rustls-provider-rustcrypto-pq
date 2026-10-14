//! Signature verification for certificates and CertificateVerify: ECDSA
//! P-256/P-384 with SHA-256/384/512 (p256, p384), Ed25519 (ed25519-dalek),
//! RSA PKCS#1 v1.5 and PSS with SHA-256/384/512 (rsa; keys of 2048 bits or
//! more) and ML-DSA-44/65/87 (ml-dsa; pure ML-DSA with an empty context, as
//! TLS uses it).

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsaParams};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::signature::hazmat::PrehashVerifier;
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};
use rustls::SignatureScheme;
use sha2::Digest;

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P256_SHA512,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ECDSA_P384_SHA512,
        ED25519,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
        ML_DSA_44,
        ML_DSA_65,
        ML_DSA_87,
    ],
    mapping: &[
        (SignatureScheme::ML_DSA_87, &[ML_DSA_87]),
        (SignatureScheme::ML_DSA_65, &[ML_DSA_65]),
        (SignatureScheme::ML_DSA_44, &[ML_DSA_44]),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256],
        ),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

// ---- ECDSA (DER signatures, as X.509 and TLS carry them) ----

#[derive(Clone, Copy, Debug)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn digest(self, msg: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => sha2::Sha256::digest(msg).to_vec(),
            Hash::Sha384 => sha2::Sha384::digest(msg).to_vec(),
            Hash::Sha512 => sha2::Sha512::digest(msg).to_vec(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Curve {
    P256,
    P384,
}

#[derive(Debug)]
struct Ecdsa(Curve, Hash, AlgorithmIdentifier);

impl SignatureVerificationAlgorithm for Ecdsa {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        match self.0 {
            Curve::P256 => alg_id::ECDSA_P256,
            Curve::P384 => alg_id::ECDSA_P384,
        }
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.2
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let prehash = self.1.digest(message);
        let ok = match self.0 {
            Curve::P256 => {
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let sig =
                    p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                vk.verify_prehash(&prehash, &sig).is_ok()
            }
            Curve::P384 => {
                let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let sig =
                    p384::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                vk.verify_prehash(&prehash, &sig).is_ok()
            }
        };
        ok.then_some(()).ok_or(InvalidSignature)
    }
}

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm =
    &Ecdsa(Curve::P256, Hash::Sha256, alg_id::ECDSA_SHA256);
static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm =
    &Ecdsa(Curve::P256, Hash::Sha384, alg_id::ECDSA_SHA384);
static ECDSA_P256_SHA512: &dyn SignatureVerificationAlgorithm =
    &Ecdsa(Curve::P256, Hash::Sha512, alg_id::ECDSA_SHA512);
static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm =
    &Ecdsa(Curve::P384, Hash::Sha256, alg_id::ECDSA_SHA256);
static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm =
    &Ecdsa(Curve::P384, Hash::Sha384, alg_id::ECDSA_SHA384);
static ECDSA_P384_SHA512: &dyn SignatureVerificationAlgorithm =
    &Ecdsa(Curve::P384, Hash::Sha512, alg_id::ECDSA_SHA512);

// ---- Ed25519 ----

#[derive(Debug)]
struct Ed25519;

impl SignatureVerificationAlgorithm for Ed25519 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let pk: &[u8; 32] = public_key.try_into().map_err(|_| InvalidSignature)?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(pk).map_err(|_| InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
        vk.verify_strict(message, &sig)
            .map_err(|_| InvalidSignature)
    }
}

static ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519;

// ---- RSA (the public key as webpki passes it: PKCS#1 RSAPublicKey) ----

#[derive(Clone, Copy, Debug)]
enum RsaPadding {
    Pkcs1,
    Pss,
}

#[derive(Debug)]
struct Rsa(RsaPadding, Hash, AlgorithmIdentifier);

impl SignatureVerificationAlgorithm for Rsa {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.2
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key = rsa::RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| InvalidSignature)?;
        // as webpki's other backends: no RSA keys under 2048 bits
        if key.size() < 256 {
            return Err(InvalidSignature);
        }
        let ok =
            match self.0 {
                RsaPadding::Pkcs1 => {
                    let sig = rsa::pkcs1v15::Signature::try_from(signature)
                        .map_err(|_| InvalidSignature)?;
                    match self.1 {
                        Hash::Sha256 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key)
                            .verify(message, &sig),
                        Hash::Sha384 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key)
                            .verify(message, &sig),
                        Hash::Sha512 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(key)
                            .verify(message, &sig),
                    }
                }
                RsaPadding::Pss => {
                    let sig =
                        rsa::pss::Signature::try_from(signature).map_err(|_| InvalidSignature)?;
                    match self.1 {
                        Hash::Sha256 => {
                            rsa::pss::VerifyingKey::<sha2::Sha256>::new(key).verify(message, &sig)
                        }
                        Hash::Sha384 => {
                            rsa::pss::VerifyingKey::<sha2::Sha384>::new(key).verify(message, &sig)
                        }
                        Hash::Sha512 => {
                            rsa::pss::VerifyingKey::<sha2::Sha512>::new(key).verify(message, &sig)
                        }
                    }
                }
            };
        ok.map_err(|_| InvalidSignature)
    }
}

static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm =
    &Rsa(RsaPadding::Pkcs1, Hash::Sha256, alg_id::RSA_PKCS1_SHA256);
static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm =
    &Rsa(RsaPadding::Pkcs1, Hash::Sha384, alg_id::RSA_PKCS1_SHA384);
static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm =
    &Rsa(RsaPadding::Pkcs1, Hash::Sha512, alg_id::RSA_PKCS1_SHA512);
static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm =
    &Rsa(RsaPadding::Pss, Hash::Sha256, alg_id::RSA_PSS_SHA256);
static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm =
    &Rsa(RsaPadding::Pss, Hash::Sha384, alg_id::RSA_PSS_SHA384);
static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm =
    &Rsa(RsaPadding::Pss, Hash::Sha512, alg_id::RSA_PSS_SHA512);

// ---- ML-DSA (FIPS 204) ----

#[derive(Debug)]
struct MlDsa<P: 'static>(AlgorithmIdentifier, std::marker::PhantomData<fn() -> P>);

impl<P: MlDsaParams + 'static> SignatureVerificationAlgorithm for MlDsa<P> {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.0
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.0
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let pk = EncodedVerifyingKey::<P>::try_from(public_key).map_err(|_| InvalidSignature)?;
        let sig = EncodedSignature::<P>::try_from(signature).map_err(|_| InvalidSignature)?;
        let sig = ml_dsa::Signature::<P>::decode(&sig).ok_or(InvalidSignature)?;
        ml_dsa::VerifyingKey::<P>::decode(&pk)
            .verify_with_context(message, &[], &sig)
            .then_some(())
            .ok_or(InvalidSignature)
    }
}

static ML_DSA_44: &dyn SignatureVerificationAlgorithm =
    &MlDsa::<ml_dsa::MlDsa44>(alg_id::ML_DSA_44, std::marker::PhantomData);
static ML_DSA_65: &dyn SignatureVerificationAlgorithm =
    &MlDsa::<ml_dsa::MlDsa65>(alg_id::ML_DSA_65, std::marker::PhantomData);
static ML_DSA_87: &dyn SignatureVerificationAlgorithm =
    &MlDsa::<ml_dsa::MlDsa87>(alg_id::ML_DSA_87, std::marker::PhantomData);
