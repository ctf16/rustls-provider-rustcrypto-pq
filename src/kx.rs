//! Key exchange: X25519 (x25519-dalek), P-256 and P-384 (p256, p384),
//! ML-KEM-512/768/1024 (ml-kem, FIPS 203) and the draft-ietf-tls-ecdhe-mlkem
//! hybrids built from them (crate::hybrid). ML-KEM and the hybrids are
//! TLS 1.3 only.

use ml_kem::{Decapsulate, Encapsulate, Generate, KeyExport, TryKeyInit};
use crate::hybrid::Hybrid;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

use super::rng;

pub static ALL: &[&dyn SupportedKxGroup] = &[
    X25519MLKEM768,
    SECP256R1MLKEM768,
    SECP384R1MLKEM1024,
    &X25519,
    &P256,
    &P384,
    &MLKEM512,
    &MLKEM768,
    &MLKEM1024,
];

fn bad_share() -> Error {
    PeerMisbehaved::InvalidKeyShare.into()
}

// ---- X25519 ----

#[derive(Debug)]
pub struct X25519;

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng());
        let pub_key = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Ok(Box::new(ActiveX25519 { secret, pub_key }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct ActiveX25519 {
    secret: x25519_dalek::EphemeralSecret,
    pub_key: [u8; 32],
}

impl ActiveKeyExchange for ActiveX25519 {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer.try_into().map_err(|_| bad_share())?;
        let shared = self.secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        // an all-zero secret: the peer sent a low-order point
        if !shared.was_contributory() {
            return Err(bad_share());
        }
        Ok(SharedSecret::from(&shared.as_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

// ---- P-256, P-384 (uncompressed points, as TLS requires) ----

macro_rules! nist_curve {
    ($name:ident, $active:ident, $krate:ident, $group:expr, $point_len:expr) => {
        #[derive(Debug)]
        pub struct $name;

        impl SupportedKxGroup for $name {
            fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
                let secret = $krate::ecdh::EphemeralSecret::generate_from_rng(&mut rng());
                let pub_key = secret.public_key().to_sec1_bytes().into_vec();
                debug_assert_eq!(pub_key.len(), $point_len);
                Ok(Box::new($active { secret, pub_key }))
            }

            fn name(&self) -> NamedGroup {
                $group
            }
        }

        struct $active {
            secret: $krate::ecdh::EphemeralSecret,
            pub_key: Vec<u8>,
        }

        impl ActiveKeyExchange for $active {
            fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
                if peer.len() != $point_len || peer[0] != 0x04 {
                    return Err(bad_share());
                }
                let peer = $krate::PublicKey::from_sec1_bytes(peer).map_err(|_| bad_share())?;
                let shared = self.secret.diffie_hellman(&peer);
                Ok(SharedSecret::from(&shared.raw_secret_bytes()[..]))
            }

            fn pub_key(&self) -> &[u8] {
                &self.pub_key
            }

            fn group(&self) -> NamedGroup {
                $group
            }
        }
    };
}

nist_curve!(P256, ActiveP256, p256, NamedGroup::secp256r1, 65);
nist_curve!(P384, ActiveP384, p384, NamedGroup::secp384r1, 97);

// ---- ML-KEM (FIPS 203) ----

macro_rules! ml_kem {
    ($name:ident, $active:ident, $params:ty, $group:expr) => {
        #[derive(Debug)]
        pub struct $name;

        impl SupportedKxGroup for $name {
            fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
                let dk = ml_kem::DecapsulationKey::<$params>::try_generate_from_rng(&mut getrandom::SysRng)
                    .map_err(|_| Error::FailedToGetRandomBytes)?;
                let pub_key = dk.encapsulation_key().to_bytes().to_vec();
                Ok(Box::new($active { dk, pub_key }))
            }

            fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
                let ek = ml_kem::EncapsulationKey::<$params>::new_from_slice(client_share).map_err(|_| bad_share())?;
                let (ct, shared) = ek.encapsulate_with_rng(&mut rng());
                Ok(CompletedKeyExchange {
                    group: $group,
                    pub_key: ct.to_vec(),
                    secret: SharedSecret::from(&shared[..]),
                })
            }

            fn name(&self) -> NamedGroup {
                $group
            }

            fn usable_for_version(&self, version: ProtocolVersion) -> bool {
                version == ProtocolVersion::TLSv1_3
            }
        }

        struct $active {
            dk: ml_kem::DecapsulationKey<$params>,
            pub_key: Vec<u8>,
        }

        impl ActiveKeyExchange for $active {
            fn complete(self: Box<Self>, ciphertext: &[u8]) -> Result<SharedSecret, Error> {
                let ct = ml_kem::Ciphertext::<$params>::try_from(ciphertext).map_err(|_| bad_share())?;
                Ok(SharedSecret::from(&self.dk.decapsulate(&ct)[..]))
            }

            fn pub_key(&self) -> &[u8] {
                &self.pub_key
            }

            fn group(&self) -> NamedGroup {
                $group
            }
        }
    };
}

ml_kem!(MlKem512, ActiveMlKem512, ml_kem::MlKem512, NamedGroup::MLKEM512);
ml_kem!(MlKem768, ActiveMlKem768, ml_kem::MlKem768, NamedGroup::MLKEM768);
ml_kem!(MlKem1024, ActiveMlKem1024, ml_kem::MlKem1024, NamedGroup::MLKEM1024);

static MLKEM512: MlKem512 = MlKem512;
static MLKEM768: MlKem768 = MlKem768;
static MLKEM1024: MlKem1024 = MlKem1024;

// ---- hybrids ----

/// ML-KEM encapsulation key and ciphertext lengths (FIPS 203)
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;
const MLKEM1024_EK_LEN: usize = 1568;
const MLKEM1024_CT_LEN: usize = 1568;

pub static X25519MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    name: NamedGroup::X25519MLKEM768,
    classical: &X25519,
    pq: &MLKEM768,
    pq_first: true,
    pq_client_len: MLKEM768_EK_LEN,
    pq_server_len: MLKEM768_CT_LEN,
};

pub static SECP256R1MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    name: NamedGroup::secp256r1MLKEM768,
    classical: &P256,
    pq: &MLKEM768,
    pq_first: false,
    pq_client_len: MLKEM768_EK_LEN,
    pq_server_len: MLKEM768_CT_LEN,
};

pub static SECP384R1MLKEM1024: &dyn SupportedKxGroup = &Hybrid {
    // (rustls 0.23 has no named variant for this one)
    name: NamedGroup::Unknown(0x11ed),
    classical: &P384,
    pq: &MLKEM1024,
    pq_first: false,
    pq_client_len: MLKEM1024_EK_LEN,
    pq_server_len: MLKEM1024_CT_LEN,
};
