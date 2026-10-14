//! Private keys and signing: ECDSA P-256/P-384 (deterministic, RFC 6979),
//! Ed25519, RSA (PSS and PKCS#1 v1.5) and ML-DSA-44/65/87 (hedged, pure
//! ML-DSA with an empty context).
//!
//! ML-DSA private keys: PKCS#8 with the ML-DSA-PrivateKey CHOICE of RFC 9881
//! in any of its three forms: seed, expandedKey, or both (OpenSSL's default).
//! The ml-dsa crate reads only the seed form, so the decoding is here.

use std::sync::Arc;

use ml_dsa::{ExpandedSigningKeyBytes, MlDsaParams};
use pkcs8::DecodePrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer as _};
use rustls::pki_types::{alg_id, AlgorithmIdentifier, PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{public_key_to_spki, Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};

#[derive(Debug)]
pub struct KeyLoader;

impl rustls::crypto::KeyProvider for KeyLoader {
    fn load_private_key(&self, key: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        match key {
            PrivateKeyDer::Pkcs8(k) => load_pkcs8(k.secret_pkcs8_der()),
            PrivateKeyDer::Pkcs1(k) => rsa::RsaPrivateKey::from_pkcs1_der(k.secret_pkcs1_der())
                .map(|k| Arc::new(Rsa::new(k)) as Arc<dyn SigningKey>)
                .map_err(|e| Error::General(format!("RSA private key: {e}"))),
            PrivateKeyDer::Sec1(k) => {
                let der = k.secret_sec1_der();
                if let Ok(sk) = p256::SecretKey::from_sec1_der(der) {
                    return Ok(Arc::new(EcdsaP256(sk.into())));
                }
                if let Ok(sk) = p384::SecretKey::from_sec1_der(der) {
                    return Ok(Arc::new(EcdsaP384(sk.into())));
                }
                Err(Error::General(
                    "SEC1 private key: not P-256 or P-384".into(),
                ))
            }
            _ => Err(Error::General("unsupported private key format".into())),
        }
    }
}

const ML_DSA_44_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
const ML_DSA_65_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
const ML_DSA_87_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

fn load_pkcs8(der: &[u8]) -> Result<Arc<dyn SigningKey>, Error> {
    let info = pkcs8::PrivateKeyInfoRef::try_from(der)
        .map_err(|e| Error::General(format!("PKCS#8: {e}")))?;
    let private_key = info.private_key.as_bytes();
    match info.algorithm.oid {
        ML_DSA_44_OID => return MlDsa::<ml_dsa::MlDsa44>::load(private_key, MlDsaKind::Ml44),
        ML_DSA_65_OID => return MlDsa::<ml_dsa::MlDsa65>::load(private_key, MlDsaKind::Ml65),
        ML_DSA_87_OID => return MlDsa::<ml_dsa::MlDsa87>::load(private_key, MlDsaKind::Ml87),
        _ => {}
    }
    if let Ok(k) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
        return Ok(Arc::new(EcdsaP256(k)));
    }
    if let Ok(k) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
        return Ok(Arc::new(EcdsaP384(k)));
    }
    if let Ok(k) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
        return Ok(Arc::new(Ed25519(k)));
    }
    if let Ok(k) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
        return Ok(Arc::new(Rsa::new(k)));
    }
    Err(Error::General(format!(
        "unsupported PKCS#8 key algorithm {}",
        info.algorithm.oid
    )))
}

fn sign_err<E: std::fmt::Display>(e: E) -> Error {
    Error::General(format!("signing failed: {e}"))
}

/// a signer for keys that sign with one scheme only
macro_rules! single_scheme_signer {
    ($key:ident, $scheme:expr, $alg:expr, $alg_id:expr) => {
        impl SigningKey for $key {
            fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
                offered
                    .contains(&$scheme)
                    .then(|| Box::new($key(self.0.clone())) as Box<dyn Signer>)
            }

            fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
                Some(public_key_to_spki(&$alg_id, self.public_key_bytes()))
            }

            fn algorithm(&self) -> SignatureAlgorithm {
                $alg
            }
        }

        impl Signer for $key {
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
                self.sign_bytes(message)
            }

            fn scheme(&self) -> SignatureScheme {
                $scheme
            }
        }

        impl std::fmt::Debug for $key {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($key))
            }
        }
    };
}

// ---- ECDSA ----

struct EcdsaP256(p256::ecdsa::SigningKey);
struct EcdsaP384(p384::ecdsa::SigningKey);

impl EcdsaP256 {
    fn public_key_bytes(&self) -> Vec<u8> {
        p256::PublicKey::from(self.0.verifying_key())
            .to_sec1_bytes()
            .into_vec()
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let sig: p256::ecdsa::Signature = self.0.try_sign(message).map_err(sign_err)?;
        Ok(sig.to_der().to_vec())
    }
}

impl EcdsaP384 {
    fn public_key_bytes(&self) -> Vec<u8> {
        p384::PublicKey::from(self.0.verifying_key())
            .to_sec1_bytes()
            .into_vec()
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let sig: p384::ecdsa::Signature = self.0.try_sign(message).map_err(sign_err)?;
        Ok(sig.to_der().to_vec())
    }
}

single_scheme_signer!(
    EcdsaP256,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureAlgorithm::ECDSA,
    alg_id::ECDSA_P256
);
single_scheme_signer!(
    EcdsaP384,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureAlgorithm::ECDSA,
    alg_id::ECDSA_P384
);

// ---- Ed25519 ----

struct Ed25519(ed25519_dalek::SigningKey);

impl Ed25519 {
    fn public_key_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let sig: ed25519_dalek::Signature = self.0.try_sign(message).map_err(sign_err)?;
        Ok(sig.to_bytes().to_vec())
    }
}

single_scheme_signer!(
    Ed25519,
    SignatureScheme::ED25519,
    SignatureAlgorithm::ED25519,
    alg_id::ED25519
);

// ---- RSA: PSS (TLS 1.3, preferred) or PKCS#1 v1.5 (TLS 1.2), each with SHA-512/384/256 ----

struct Rsa(Arc<RsaKeys>);

/// the signing keys for each scheme, made once (the rsa crate's signing keys
/// own their private key)
struct RsaKeys {
    public: rsa::RsaPublicKey,
    pss256: rsa::pss::SigningKey<sha2::Sha256>,
    pss384: rsa::pss::SigningKey<sha2::Sha384>,
    pss512: rsa::pss::SigningKey<sha2::Sha512>,
    pkcs256: rsa::pkcs1v15::SigningKey<sha2::Sha256>,
    pkcs384: rsa::pkcs1v15::SigningKey<sha2::Sha384>,
    pkcs512: rsa::pkcs1v15::SigningKey<sha2::Sha512>,
}

const RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

impl Rsa {
    fn new(k: rsa::RsaPrivateKey) -> Self {
        Rsa(Arc::new(RsaKeys {
            public: k.to_public_key(),
            pss256: rsa::pss::SigningKey::new(k.clone()),
            pss384: rsa::pss::SigningKey::new(k.clone()),
            pss512: rsa::pss::SigningKey::new(k.clone()),
            pkcs256: rsa::pkcs1v15::SigningKey::new(k.clone()),
            pkcs384: rsa::pkcs1v15::SigningKey::new(k.clone()),
            pkcs512: rsa::pkcs1v15::SigningKey::new(k),
        }))
    }
}

impl SigningKey for Rsa {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = RSA_SCHEMES.iter().find(|s| offered.contains(s))?;
        Some(Box::new(RsaSigner(self.0.clone(), *scheme)))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        let pkcs1 = self.0.public.to_pkcs1_der().ok()?;
        Some(public_key_to_spki(
            &alg_id::RSA_ENCRYPTION,
            pkcs1.as_bytes(),
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

impl std::fmt::Debug for Rsa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Rsa")
    }
}

struct RsaSigner(Arc<RsaKeys>, SignatureScheme);

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let rng = &mut getrandom::SysRng;
        let k = &self.0;
        Ok(match self.1 {
            SignatureScheme::RSA_PSS_SHA256 => k
                .pss256
                .try_sign_with_rng(rng, message)
                .map_err(sign_err)?
                .to_vec(),
            SignatureScheme::RSA_PSS_SHA384 => k
                .pss384
                .try_sign_with_rng(rng, message)
                .map_err(sign_err)?
                .to_vec(),
            SignatureScheme::RSA_PSS_SHA512 => k
                .pss512
                .try_sign_with_rng(rng, message)
                .map_err(sign_err)?
                .to_vec(),
            SignatureScheme::RSA_PKCS1_SHA256 => k
                .pkcs256
                .try_sign_with_rng(rng, message)
                .map_err(sign_err)?
                .to_vec(),
            SignatureScheme::RSA_PKCS1_SHA384 => k
                .pkcs384
                .try_sign_with_rng(rng, message)
                .map_err(sign_err)?
                .to_vec(),
            SignatureScheme::RSA_PKCS1_SHA512 => k
                .pkcs512
                .try_sign_with_rng(rng, message)
                .map_err(sign_err)?
                .to_vec(),
            s => return Err(Error::General(format!("RSA: unexpected scheme {s:?}"))),
        })
    }

    fn scheme(&self) -> SignatureScheme {
        self.1
    }
}

impl std::fmt::Debug for RsaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaSigner({:?})", self.1)
    }
}

// ---- ML-DSA ----

#[derive(Clone, Copy)]
enum MlDsaKind {
    Ml44,
    Ml65,
    Ml87,
}

impl MlDsaKind {
    fn scheme(self) -> SignatureScheme {
        match self {
            MlDsaKind::Ml44 => SignatureScheme::ML_DSA_44,
            MlDsaKind::Ml65 => SignatureScheme::ML_DSA_65,
            MlDsaKind::Ml87 => SignatureScheme::ML_DSA_87,
        }
    }

    fn alg_id(self) -> AlgorithmIdentifier {
        match self {
            MlDsaKind::Ml44 => alg_id::ML_DSA_44,
            MlDsaKind::Ml65 => alg_id::ML_DSA_65,
            MlDsaKind::Ml87 => alg_id::ML_DSA_87,
        }
    }

    /// (k, l, η) of FIPS 204's parameter sets
    fn params(self) -> (usize, usize, u16) {
        match self {
            MlDsaKind::Ml44 => (4, 4, 2),
            MlDsaKind::Ml65 => (6, 5, 4),
            MlDsaKind::Ml87 => (8, 7, 2),
        }
    }

    /// whether an expandedKey of the right length passes FIPS 204 skDecode's
    /// range check: after ρ, K and tr (128 bytes), s1 and s2 hold (l + k) x 256
    /// coefficients, each η - s in bitlen(2η) bits, so at most 2η (t0's 13-bit
    /// fields can't be out of range). The ml-dsa crate asserts this instead of
    /// returning an error, so a corrupted key file would panic.
    fn expanded_in_range(self, sk: &[u8]) -> bool {
        let (k, l, eta) = self.params();
        let bits = if eta == 2 { 3 } else { 4 };
        let packed = &sk[128..128 + (k + l) * 256 * bits / 8];
        (0..(k + l) * 256).all(|i| {
            let (byte, shift) = (i * bits / 8, i * bits % 8);
            let word =
                u16::from_le_bytes([packed[byte], packed.get(byte + 1).copied().unwrap_or(0)]);
            (word >> shift) & ((1 << bits) - 1) <= 2 * eta
        })
    }
}

struct MlDsa<P: MlDsaParams> {
    key: Arc<MlDsaKey<P>>,
    public: Vec<u8>,
    kind: MlDsaKind,
}

/// An ML-DSA-87 expanded key is about 100 KiB, and unoptimized builds copy it
/// on every move, so it never moves by value here: the ml-dsa crate's
/// SigningKey (from a seed) keeps it on the heap, an expandedKey is boxed.
enum MlDsaKey<P: MlDsaParams> {
    Seeded(ml_dsa::SigningKey<P>),
    Expanded(Box<ml_dsa::ExpandedSigningKey<P>>),
}

impl<P: MlDsaParams> MlDsaKey<P> {
    fn expanded(&self) -> &ml_dsa::ExpandedSigningKey<P> {
        match self {
            MlDsaKey::Seeded(k) => k.expanded_key(),
            MlDsaKey::Expanded(k) => k,
        }
    }
}

/// one DER TLV at the start of B: (tag, contents, rest)
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&l0, b) = b.split_first()?;
    let (len, b) = match l0 {
        0..=0x7f => (l0 as usize, b),
        0x81 => (*b.first()? as usize, &b[1..]),
        0x82 => (
            (*b.first()? as usize) << 8 | *b.get(1)? as usize,
            b.get(2..)?,
        ),
        _ => return None,
    };
    (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
}

impl<P: MlDsaParams + 'static> MlDsa<P> {
    /// from the ML-DSA-PrivateKey: seed [0] IMPLICIT OCTET STRING,
    /// expandedKey OCTET STRING, or both SEQUENCE { seed, expandedKey }
    #[allow(deprecated)] // the expanded form has no non-deprecated decoder
    fn load(private_key: &[u8], kind: MlDsaKind) -> Result<Arc<dyn SigningKey>, Error> {
        let bad = |why: &str| Error::General(format!("ML-DSA private key: {why}"));
        let from_seed = |seed: &[u8]| -> Result<MlDsaKey<P>, Error> {
            let seed = ml_dsa::Seed::try_from(seed).map_err(|_| bad("seed is not 32 bytes"))?;
            Ok(MlDsaKey::Seeded(ml_dsa::SigningKey::<P>::from_seed(&seed)))
        };
        let from_expanded = |bytes: &[u8]| -> Result<MlDsaKey<P>, Error> {
            let enc = ExpandedSigningKeyBytes::<P>::try_from(bytes)
                .map_err(|_| bad("wrong expanded key length"))?;
            if !kind.expanded_in_range(bytes) {
                return Err(bad("expanded key coefficients out of range"));
            }
            Ok(MlDsaKey::Expanded(Box::new(
                ml_dsa::ExpandedSigningKey::<P>::from_expanded(&enc),
            )))
        };
        let (tag, contents, rest) = tlv(private_key).ok_or_else(|| bad("not DER"))?;
        if !rest.is_empty() {
            return Err(bad("trailing data"));
        }
        let key = match tag {
            0x80 => from_seed(contents)?,
            0x04 => from_expanded(contents)?,
            0x30 => {
                let (t1, seed, rest) = tlv(contents).ok_or_else(|| bad("bad seed"))?;
                let (t2, expanded, rest) = tlv(rest).ok_or_else(|| bad("bad expandedKey"))?;
                if t1 != 0x04 || t2 != 0x04 || !rest.is_empty() {
                    return Err(bad("bad 'both' encoding"));
                }
                let key = from_seed(seed)?;
                // the two halves must describe the same key
                if key.expanded().to_expanded().as_slice() != expanded {
                    return Err(bad("seed and expandedKey don't match"));
                }
                key
            }
            _ => return Err(bad("unknown ML-DSA-PrivateKey form")),
        };
        let public = key.expanded().verifying_key().encode().to_vec();
        Ok(Arc::new(MlDsa {
            key: Arc::new(key),
            public,
            kind,
        }))
    }
}

impl<P: MlDsaParams + 'static> SigningKey for MlDsa<P> {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&self.kind.scheme()).then(|| {
            Box::new(MlDsa {
                key: self.key.clone(),
                public: Vec::new(),
                kind: self.kind,
            }) as Box<dyn Signer>
        })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(&self.kind.alg_id(), &self.public))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        // (TLS 1.2 has no code for ML-DSA, as in rustls's aws-lc-rs provider)
        SignatureAlgorithm::Unknown(0)
    }
}

impl<P: MlDsaParams + 'static> Signer for MlDsa<P> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let sig = self
            .key
            .expanded()
            .sign_randomized(message, &[], &mut getrandom::SysRng)
            .map_err(sign_err)?;
        Ok(sig.encode().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.kind.scheme()
    }
}

impl<P: MlDsaParams> std::fmt::Debug for MlDsa<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsa({:?})", self.kind.scheme())
    }
}
