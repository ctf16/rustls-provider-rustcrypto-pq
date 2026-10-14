//! The provider against rustls's aws-lc-rs provider (crate::testkit), and
//! the parts aws-lc-rs has no counterpart for: MLKEM512 and
//! SecP384r1MLKEM1024 against aws-lc-rs's components, and our ML-DSA
//! private-key decoding. Run optimized (ML-KEM and ML-DSA are slow without):
//!   cargo test --release

use crate::testkit::*;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::{CipherSuite, NamedGroup};

fn ours() -> CryptoProvider {
    crate::provider()
}

#[test]
fn key_exchange_agrees_with_aws_lc_rs() {
    use NamedGroup::*;
    assert_eq!(
        kx_agrees(&ours()),
        [
            X25519MLKEM768,
            secp256r1MLKEM768,
            X25519,
            secp256r1,
            secp384r1,
            MLKEM768,
            MLKEM1024
        ]
    );
}

#[test]
fn secp384r1mlkem1024_agrees_with_aws_lc_rs_components() {
    let ours = ours();
    let g = group(&ours, NamedGroup::Unknown(0x11ed)).unwrap();
    let reference = secp384r1mlkem1024_reference();
    for _ in 0..32 {
        assert_agree(g, &reference);
        assert_agree(&reference, g);
    }
}

/// a ciphertext that isn't the one encapsulated gives a pseudorandom
/// secret, not an error (FIPS 203 implicit rejection), so a server can't
/// tell; the client's handshake then fails at Finished
#[test]
fn mlkem_rejects_altered_ciphertexts_implicitly() {
    let ours = ours();
    for name in [
        NamedGroup::MLKEM512,
        NamedGroup::MLKEM768,
        NamedGroup::MLKEM1024,
    ] {
        let g = group(&ours, name).unwrap();
        let client = g.start().unwrap();
        let server = g.start_and_complete(client.pub_key()).unwrap();
        let mut ct = server.pub_key.clone();
        let mid = ct.len() / 2;
        ct[mid] ^= 1;
        let secret = client.complete(&ct).unwrap();
        assert_eq!(secret.secret_bytes().len(), 32);
        assert_ne!(
            secret.secret_bytes(),
            server.secret.secret_bytes(),
            "{name:?}"
        );
    }
}

#[test]
fn malformed_key_shares_are_refused() {
    // per group: 5 client and 4 server share lengths; each bad point (7
    // X25519, 6 NIST) as client and as server share; 2 ML-KEM keys over q
    let x25519 = 9 + 2 * 7;
    let nist = 9 + 2 * 6;
    let mlkem = 9 + 2;
    let hybrids = (x25519 + 2) + 2 * (nist + 2);
    assert_eq!(
        malformed_shares_refused(&ours()),
        hybrids + x25519 + 2 * nist + 3 * mlkem
    );
}

#[test]
fn signatures_agree_with_aws_lc_rs() {
    assert_eq!(signatures_agree(&ours()), KEY_TYPES);
}

#[test]
fn hashes_hkdf_and_prf_agree_with_aws_lc_rs() {
    use CipherSuite::*;
    assert_eq!(
        primitives_agree(&ours()),
        [
            TLS13_AES_256_GCM_SHA384,
            TLS13_AES_128_GCM_SHA256,
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ]
    );
}

#[test]
fn handshakes() {
    // TLS 1.3: 7 certificate types x 3 suites x (9 groups with itself, 7
    // with aws-lc-rs each way); TLS 1.2: (3 ECDSA/Ed25519 certificate types
    // x 3 suites + RSA x 3 suites) x 3 groups, in each of the 3 pairs
    assert_eq!(
        handshake_matrix(&ours()),
        7 * 3 * (9 + 7 + 7) + (3 * 3 + 3) * 3 * 3
    );
}

#[test]
fn hello_retry_requests() {
    assert_eq!(hello_retry_matrix(&ours()), 9 + 7 + 7);
}

#[test]
fn sessions_resume() {
    // per pair: TLS 1.3 and 1.2, each 3 suites with ECDSA and 3 with RSA
    assert_eq!(resumption(&ours()), 3 * 2 * (3 + 3));
}

#[test]
fn bulk_data_and_key_updates() {
    // per pair: 3 TLS 1.3 and 3 TLS 1.2 (ECDSA) suites, 3 rounds of 64 KiB each way
    assert_eq!(bulk_and_key_updates(&ours()), 3 * 6 * 3 * 2 * 64 * 1024);
}

#[test]
fn tampered_records_are_refused() {
    let refused = tampered_records_refused(&ours());
    // per pair (2): TLS 1.3 records of 40 + 1 + 16 bytes after a 5-byte
    // header, 3 suites; TLS 1.2 GCM records add an 8-byte explicit nonce
    // (2 suites per certificate type), ChaCha20 doesn't (1); +3 each
    let tls13 = 3 * (5 + 40 + 1 + 16 + 3);
    let tls12 = 2 * (2 * (5 + 8 + 40 + 16 + 3) + (5 + 40 + 16 + 3));
    assert_eq!(refused, 2 * (tls13 + tls12));
}

#[test]
fn random_inputs_never_panic() {
    let n = iterations();
    // 9 groups x 2 roles, 16 verification algorithms, 12 key files
    assert_eq!(random_inputs(&ours()), n * (9 * 2 + 16 + 12));
}

// ---- our ML-DSA private-key decoding ----

fn public_key(file: &str) -> Vec<u8> {
    let k = ours()
        .key_provider
        .load_private_key(key(file))
        .unwrap_or_else(|e| panic!("{file}: {e}"));
    k.public_key().unwrap().as_ref().to_vec()
}

#[test]
fn every_key_encoding_loads_the_same_key() {
    for (kt, alternatives) in [
        ("p256", &["p256.sec1.key"][..]),
        ("p384", &["p384.sec1.key"]),
        ("rsa2048", &["rsa2048.pkcs1.key"]),
        ("mldsa44", &["mldsa44.seed.key", "mldsa44.expanded.key"]),
        ("mldsa65", &["mldsa65.seed.key", "mldsa65.expanded.key"]),
        ("mldsa87", &["mldsa87.seed.key", "mldsa87.expanded.key"]),
    ] {
        let spki = spki(&format!("{kt}.spki.pem"));
        assert_eq!(public_key(&format!("{kt}.key")), spki, "{kt}.key");
        for file in alternatives {
            assert_eq!(public_key(file), spki, "{file}");
        }
    }
}

/// keys decoded from the seed and from the expanded form sign alike: each
/// one's signatures verify with the public key in the certificate
#[test]
fn mldsa_keys_sign_in_every_encoding() {
    let ours = ours();
    for (kt, scheme) in [
        ("mldsa44", rustls::SignatureScheme::ML_DSA_44),
        ("mldsa65", rustls::SignatureScheme::ML_DSA_65),
        ("mldsa87", rustls::SignatureScheme::ML_DSA_87),
    ] {
        let spki = spki(&format!("{kt}.spki.pem"));
        for file in [
            format!("{kt}.key"),
            format!("{kt}.seed.key"),
            format!("{kt}.expanded.key"),
        ] {
            let k = ours.key_provider.load_private_key(key(&file)).unwrap();
            let sig = k
                .choose_scheme(&[scheme])
                .unwrap()
                .sign(b"message")
                .unwrap();
            verify(&reference(), scheme, &spki, b"message", &sig)
                .unwrap_or_else(|_| panic!("{file}"));
        }
    }
}

/// in the "both" form, a seed and an expandedKey that don't belong together
/// are refused (otherwise which one signs would decide the key)
#[test]
fn mldsa_seed_and_expanded_key_must_match() {
    let ours = ours();
    for (kt, expanded_len) in [("mldsa44", 2560), ("mldsa65", 4032), ("mldsa87", 4896)] {
        let PrivateKeyDer::Pkcs8(both) = key(&format!("{kt}.key")) else {
            panic!()
        };
        let der = both.secret_pkcs8_der().to_vec();
        // ... SEQUENCE { OCTET STRING seed (32), OCTET STRING expandedKey }: the
        // expandedKey ends the DER, after its 4-byte header and the seed
        let expanded_at = der.len() - expanded_len;
        let seed_at = expanded_at - 4 - 32;
        for (what, at) in [("expandedKey", expanded_at + 100), ("seed", seed_at + 5)] {
            let mut bad = der.clone();
            bad[at] ^= 1;
            assert!(
                ours.key_provider
                    .load_private_key(PrivateKeyDer::Pkcs8(bad.into()))
                    .is_err(),
                "{kt}: loaded a key with its {what} altered"
            );
        }
    }
}

/// an expandedKey with an s1 coefficient out of range (FIPS 204 skDecode)
/// is refused: the ml-dsa crate's decoder would panic on it
#[test]
fn mldsa_expanded_key_out_of_range_is_refused() {
    let ours = ours();
    for (kt, expanded_len) in [("mldsa44", 2560), ("mldsa65", 4032), ("mldsa87", 4896)] {
        let PrivateKeyDer::Pkcs8(k) = key(&format!("{kt}.expanded.key")) else {
            panic!()
        };
        let mut der = k.secret_pkcs8_der().to_vec();
        // s1 starts after rho, K and tr (128 bytes); 0xff is 7 in 3 bits, 15 in 4
        let s1 = der.len() - expanded_len + 128;
        der[s1] = 0xff;
        assert!(
            ours.key_provider
                .load_private_key(PrivateKeyDer::Pkcs8(der.into()))
                .is_err(),
            "{kt}"
        );
    }
}
