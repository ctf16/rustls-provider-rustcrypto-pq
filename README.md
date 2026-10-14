# rustls-provider-rustcrypto-pq

A [rustls] crypto provider built on the current generation of the [RustCrypto] crates, with
post-quantum key exchange (ML-KEM, FIPS 203) and post-quantum signatures (ML-DSA, FIPS 204)
alongside the classical algorithms.

[rustls-rustcrypto] is a crate generation behind and has neither ML-KEM nor ML-DSA; this
provider is written directly against `ml-kem`, `ml-dsa`, `p256`, `p384`, `x25519-dalek`,
`ed25519-dalek`, `rsa`, `aes-gcm`, `chacha20poly1305`, `sha2` and `hmac`.

## Algorithms

**Key exchange**, in the provider's order of preference:

| Group | Code point | TLS versions |
| --- | --- | --- |
| X25519MLKEM768 | `0x11ec` | 1.3 |
| SecP256r1MLKEM768 | `0x11eb` | 1.3 |
| SecP384r1MLKEM1024 | `0x11ed` | 1.3 |
| X25519 | `0x001d` | 1.2, 1.3 |
| P-256 (secp256r1) | `0x0017` | 1.2, 1.3 |
| P-384 (secp384r1) | `0x0018` | 1.2, 1.3 |
| MLKEM512 | `0x0200` | 1.3 |
| MLKEM768 | `0x0201` | 1.3 |
| MLKEM1024 | `0x0202` | 1.3 |

The hybrids follow [draft-ietf-tls-ecdhe-mlkem]: X25519MLKEM768 puts the ML-KEM share first,
the SecP groups put the elliptic-curve share first. Pure ML-KEM follows
[draft-ietf-tls-mlkem].

**Signatures** (certificates and CertificateVerify, signing and verification):

- ML-DSA-44, ML-DSA-65, ML-DSA-87 (pure ML-DSA, empty context; signing is hedged)
- ECDSA P-256 and P-384 (signing is deterministic, RFC 6979)
- Ed25519
- RSA PSS and PKCS#1 v1.5 with SHA-256/384/512 (verification refuses keys under 2048 bits)

**Cipher suites:**

- TLS 1.3: `TLS13_AES_256_GCM_SHA384`, `TLS13_AES_128_GCM_SHA256`,
  `TLS13_CHACHA20_POLY1305_SHA256`
- TLS 1.2: `TLS_ECDHE_{ECDSA,RSA}_WITH_AES_256_GCM_SHA384`,
  `TLS_ECDHE_{ECDSA,RSA}_WITH_AES_128_GCM_SHA256`,
  `TLS_ECDHE_{ECDSA,RSA}_WITH_CHACHA20_POLY1305_SHA256`

**Private keys:** PKCS#8 for every key type; SEC1 for P-256 and P-384; PKCS#1 for RSA. ML-DSA
PKCS#8 keys are read in all three forms of RFC 9881's `ML-DSA-PrivateKey`: seed only, expanded
key only, and both (OpenSSL 3.5's default). In the "both" form the seed and the expanded key
must match.

Randomness comes from the operating system through `getrandom`.

## Usage

```toml
[dependencies]
rustls = { version = "0.23.45", default-features = false, features = ["std", "tls12"] }
rustls-provider-rustcrypto-pq = "0.1"
```

`provider()` returns a `rustls::crypto::CryptoProvider` with everything above:

```rust
use std::sync::Arc;

let provider = Arc::new(rustls_provider_rustcrypto_pq::provider());
let config = rustls::ClientConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()?
    .with_root_certificates(root_store)
    .with_no_client_auth();
```

To offer fewer groups, or change their order, edit `kx_groups` before building a config. For
example, post-quantum hybrids only:

```rust
use rustls::NamedGroup;

let mut provider = rustls_provider_rustcrypto_pq::provider();
provider.kx_groups.retain(|g| {
    matches!(g.name(), NamedGroup::X25519MLKEM768 | NamedGroup::secp256r1MLKEM768)
        // SecP384r1MLKEM1024: rustls 0.23 has no name for it
        || g.name() == NamedGroup::Unknown(0x11ed)
});
```

To make it the process-wide default provider instead, call
`provider().install_default()` once at startup.

This crate enables rustls's `tls12` feature (it implements the TLS 1.2 suites); it does not
enable `aws-lc-rs` or `ring`.

## Status

- Not FIPS 140-validated: the RustCrypto crates it builds on aren't.
- `rsa` is pinned to a release candidate (`=0.10.0-rc.19`): rsa 0.10, the line on the same
  RustCrypto generation as the other crates, isn't released yet, and its API changes between
  release candidates. `ml-dsa` is at 0.1. Expect version bumps as they stabilize.
- RSA private-key operations in `rsa` aren't constant-time ([RUSTSEC-2023-0071], the Marvin
  attack; no fixed release). A TLS server, or a client with a client certificate, signing with
  an RSA key may leak it to an attacker who can time its handshakes; prefer ML-DSA, ECDSA or
  Ed25519 keys there. `cargo audit` reports this advisory for any project using this crate.
- No security audit of this crate. Review it before relying on it.

## Tests

The tests check the provider against rustls's `aws-lc-rs` provider: key exchange in both roles
for every group, refusal of malformed key shares (wrong lengths, small-order and off-curve
points, ML-KEM keys failing FIPS 203's modulus check), signatures in both directions, hashes,
HKDF and the TLS 1.2 PRF, in-memory mutual-TLS handshakes for every suite × group × certificate
type, HelloRetryRequest, resumption, key updates, tampered records, and random inputs. ML-KEM
and ML-DSA are slow unoptimized, so run them in release mode:

```sh
cargo test --release
```

The keys and certificates are generated on the first run by `testdata/make.sh`, which needs
OpenSSL 3.5 or later (for ML-DSA). It uses `openssl` from the `PATH`; point `OPENSSL` at another
binary if that one is older (macOS ships LibreSSL):

```sh
OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl cargo test --release
```

`PQC_TEST_ITERATIONS` sets the rounds of the random-input tests (default 200).

## Minimum supported Rust version

1.89, set by the RustCrypto dependencies.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.

[rustls]: https://github.com/rustls/rustls
[RustCrypto]: https://github.com/RustCrypto
[rustls-rustcrypto]: https://crates.io/crates/rustls-rustcrypto
[draft-ietf-tls-ecdhe-mlkem]: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
[draft-ietf-tls-mlkem]: https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/
[RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071.html
