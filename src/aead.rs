//! AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 (aes-gcm, chacha20poly1305)
//! as TLS 1.3 and TLS 1.2 record protection. TLS 1.3 and TLS 1.2
//! ChaCha20-Poly1305 use the sequence number XORed into the IV as nonce; TLS
//! 1.2 AES-GCM sends an 8-byte explicit nonce (we use the same construction).

use std::marker::PhantomData;

use aes_gcm::aead::{AeadInOut, KeyInit};
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError, NONCE_LEN,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};

const TAG_LEN: usize = 16;
const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const MAX_FRAGMENT_LEN: usize = 16384;

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub struct Aead<A: 'static>(Kind, PhantomData<fn() -> A>);

pub static AES_128_GCM: Aead<aes_gcm::Aes128Gcm> = Aead(Kind::Aes128Gcm, PhantomData);
pub static AES_256_GCM: Aead<aes_gcm::Aes256Gcm> = Aead(Kind::Aes256Gcm, PhantomData);
pub static CHACHA20_POLY1305: Aead<chacha20poly1305::ChaCha20Poly1305> =
    Aead(Kind::ChaCha20Poly1305, PhantomData);

/// the RustCrypto AEADs used here (12-byte nonce, 16-byte tag)
pub trait Cipher: AeadInOut + KeyInit + Send + Sync + 'static {}
impl<A: AeadInOut + KeyInit + Send + Sync + 'static> Cipher for A {}

impl<A: Cipher> Aead<A> {
    fn cipher(key: &AeadKey) -> A {
        A::new_from_slice(key.as_ref()).expect("AEAD key length from the cipher suite")
    }

    fn key_len(&self) -> usize {
        match self.0 {
            Kind::Aes128Gcm => 16,
            Kind::Aes256Gcm | Kind::ChaCha20Poly1305 => 32,
        }
    }

    fn secrets(&self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        match self.0 {
            Kind::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            Kind::Aes256Gcm => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            Kind::ChaCha20Poly1305 => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
        }
    }
}

/// encrypt BUF in place with NONCE and AAD; the tag to append
fn seal<A: Cipher>(
    c: &A,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    let nonce = aes_gcm::aead::Nonce::<A>::try_from(&nonce[..]).map_err(|_| Error::EncryptError)?;
    let tag = c
        .encrypt_inout_detached(&nonce, aad, buf.into())
        .map_err(|_| Error::EncryptError)?;
    tag.as_slice().try_into().map_err(|_| Error::EncryptError)
}

/// decrypt BUF in place, checking TAG
fn open<A: Cipher>(
    c: &A,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    let nonce = aes_gcm::aead::Nonce::<A>::try_from(&nonce[..]).map_err(|_| Error::DecryptError)?;
    let tag = aes_gcm::aead::Tag::<A>::try_from(tag).map_err(|_| Error::DecryptError)?;
    c.decrypt_inout_detached(&nonce, aad, buf.into(), &tag)
        .map_err(|_| Error::DecryptError)
}

// ---- TLS 1.3 ----

impl<A: Cipher> Tls13AeadAlgorithm for Aead<A> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher(Self::cipher(&key), iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher(Self::cipher(&key), iv))
    }

    fn key_len(&self) -> usize {
        Aead::key_len(self)
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(self.secrets(key, iv))
    }
}

struct Tls13Cipher<A>(A, Iv);

impl<A: Cipher> MessageEncrypter for Tls13Cipher<A> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let tag = seal(
            &self.0,
            &Nonce::new(&self.1, seq).0,
            &make_tls13_aad(total_len),
            payload.as_mut(),
        )?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl<A: Cipher> MessageDecrypter for Tls13Cipher<A> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let aad = make_tls13_aad(payload.len());
        let plain_len = payload.len() - TAG_LEN;
        let (cipher, tag) = payload.split_at_mut(plain_len);
        open(&self.0, &Nonce::new(&self.1, seq).0, &aad, cipher, tag)?;
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

// ---- TLS 1.2 ----

impl<A: Cipher> Tls12AeadAlgorithm for Aead<A> {
    fn encrypter(&self, key: AeadKey, iv: &[u8], explicit: &[u8]) -> Box<dyn MessageEncrypter> {
        let c = Self::cipher(&key);
        if self.0 == Kind::ChaCha20Poly1305 {
            Box::new(Tls12ChaCha(c, Iv::copy(iv)))
        } else {
            Box::new(Tls12Gcm(c, gcm_iv(iv, explicit)))
        }
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let c = Self::cipher(&key);
        if self.0 == Kind::ChaCha20Poly1305 {
            Box::new(Tls12ChaCha(c, Iv::copy(iv)))
        } else {
            let mut salt = [0u8; NONCE_LEN];
            salt[..4].copy_from_slice(iv);
            Box::new(Tls12Gcm(c, Iv::new(salt)))
        }
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        if self.0 == Kind::ChaCha20Poly1305 {
            KeyBlockShape {
                enc_key_len: 32,
                fixed_iv_len: NONCE_LEN,
                explicit_nonce_len: 0,
            }
        } else {
            KeyBlockShape {
                enc_key_len: Aead::key_len(self),
                fixed_iv_len: 4,
                explicit_nonce_len: GCM_EXPLICIT_NONCE_LEN,
            }
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let iv = if self.0 == Kind::ChaCha20Poly1305 {
            Iv::copy(iv)
        } else {
            gcm_iv(iv, explicit)
        };
        Ok(self.secrets(key, iv))
    }
}

/// the 4-byte salt from the key block and the 8-byte explicit part
fn gcm_iv(salt: &[u8], explicit: &[u8]) -> Iv {
    let mut iv = [0u8; NONCE_LEN];
    iv[..4].copy_from_slice(salt);
    iv[4..].copy_from_slice(explicit);
    Iv::new(iv)
}

struct Tls12ChaCha<A>(A, Iv);

impl<A: Cipher> MessageEncrypter for Tls12ChaCha<A> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let mut payload =
            PrefixedPayload::with_capacity(self.encrypted_payload_len(msg.payload.len()));
        payload.extend_from_chunks(&msg.payload);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        let tag = seal(&self.0, &Nonce::new(&self.1, seq).0, &aad, payload.as_mut())?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

impl<A: Cipher> MessageDecrypter for Tls12ChaCha<A> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        if msg.payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let plain_len = msg.payload.len() - TAG_LEN;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        let (cipher, tag) = msg.payload.split_at_mut(plain_len);
        open(&self.0, &Nonce::new(&self.1, seq).0, &aad, cipher, tag)?;
        msg.payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

/// encrypter: the full IV (salt + explicit part); decrypter: the salt only
struct Tls12Gcm<A>(A, Iv);

impl<A: Cipher> MessageEncrypter for Tls12Gcm<A> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let mut payload =
            PrefixedPayload::with_capacity(self.encrypted_payload_len(msg.payload.len()));
        let nonce = Nonce::new(&self.1, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        payload.extend_from_slice(&nonce[4..]);
        payload.extend_from_chunks(&msg.payload);
        let tag = seal(
            &self.0,
            &nonce,
            &aad,
            &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LEN..],
        )?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LEN + TAG_LEN
    }
}

impl<A: Cipher> MessageDecrypter for Tls12Gcm<A> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        if msg.payload.len() < GCM_EXPLICIT_NONCE_LEN + TAG_LEN {
            return Err(Error::DecryptError);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&self.1.as_ref()[..4]);
        nonce[4..].copy_from_slice(&msg.payload[..GCM_EXPLICIT_NONCE_LEN]);
        let plain_len = msg.payload.len() - GCM_EXPLICIT_NONCE_LEN - TAG_LEN;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        let (_, rest) = msg.payload.split_at_mut(GCM_EXPLICIT_NONCE_LEN);
        let (cipher, tag) = rest.split_at_mut(plain_len);
        open(&self.0, &nonce, &aad, cipher, tag)?;
        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        Ok(
            msg.into_plain_message_range(
                GCM_EXPLICIT_NONCE_LEN..GCM_EXPLICIT_NONCE_LEN + plain_len,
            ),
        )
    }
}
