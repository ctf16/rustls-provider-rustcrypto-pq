//! SHA-256 and SHA-384 (sha2) for the transcript hash

use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use sha2::Digest;

pub struct Sha<D: 'static>(HashAlgorithm, std::marker::PhantomData<fn() -> D>);

pub static SHA256: Sha<sha2::Sha256> = Sha(HashAlgorithm::SHA256, std::marker::PhantomData);
pub static SHA384: Sha<sha2::Sha384> = Sha(HashAlgorithm::SHA384, std::marker::PhantomData);

impl<D: Digest + Clone + Send + Sync + 'static> Hash for Sha<D> {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Ctx(D::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&D::digest(data))
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.0
    }

    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

struct Ctx<D>(D);

impl<D: Digest + Clone + Send + Sync + 'static> Context for Ctx<D> {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Ctx(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}
