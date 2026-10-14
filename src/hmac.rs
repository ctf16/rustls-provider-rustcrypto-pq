//! HMAC-SHA-256 and HMAC-SHA-384 (hmac); rustls derives HKDF (TLS 1.3) and
//! the PRF (TLS 1.2) from these

use hmac::{KeyInit, Mac};
use rustls::crypto::hmac::{Hmac, Key, Tag};

pub struct HmacSha<D: 'static>(std::marker::PhantomData<fn() -> D>);

pub static HMAC_SHA256: HmacSha<sha2::Sha256> = HmacSha(std::marker::PhantomData);
pub static HMAC_SHA384: HmacSha<sha2::Sha384> = HmacSha(std::marker::PhantomData);

impl<D> Hmac for HmacSha<D>
where
    D: hmac::EagerHash + Send + Sync + 'static,
    hmac::Hmac<D>: KeyInit + Mac + Clone + Send + Sync,
{
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacKey(
            <hmac::Hmac<D> as KeyInit>::new_from_slice(key).expect("HMAC takes keys of any length"),
        ))
    }

    fn hash_output_len(&self) -> usize {
        <hmac::Hmac<D> as hmac::digest::OutputSizeUser>::output_size()
    }
}

struct HmacKey<M>(M);

impl<M: Mac + Clone + Send + Sync> Key for HmacKey<M> {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut m = self.0.clone();
        m.update(first);
        for part in middle {
            m.update(part);
        }
        m.update(last);
        Tag::new(&m.finalize().into_bytes())
    }

    fn tag_len(&self) -> usize {
        M::output_size()
    }
}
