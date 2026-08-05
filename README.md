# cpcsp-rs

Safe Rust wrapper for [CryptoPro CSP 5.0](https://www.cryptopro.ru/products/csp) — the most widely used cryptographic service provider in Russia.

> **[README на русском языке →](README_RU.md)**

## Features

- **Idiomatic Rust API** — safe wrappers with RAII, `Result`, `Option`
- **Handwritten FFI bindings** — no bindgen, full control over types and layout
- **GOST cryptography** — GOST R 34.10-2012, GOST R 34.11-2012 (Magma/Kuznechick), GOST 28147-89
- **CMS operations** — sign, verify, encrypt, decrypt messages
- **Certificate stores** — open, enumerate, search certificates
- **PKCS#12 (PFX)** — import/export certificate containers
- **Symmetric encryption** — GOST 28147-89 session keys (`CryptEncrypt`/`CryptDecrypt`)
- **Key derivation & CSPRNG** — `CryptDeriveKey`, `CryptGenRandom`
- **Private keys** — acquire the private key bound to a certificate
- **Self-signed certificates** — X.509 generation (`CertCreateSelfSignCertificate`)
- **ASN.1 encode/decode** — typed DER structures with RAII (`Decoded<T>`)

## Supported Algorithms

| Algorithm | Description | FFI Constant |
|-----------|-------------|--------------|
| GOST R 34.10-2012 256 | Digital signature (256-bit) | `CALG_GOST_2012_256` |
| GOST R 34.10-2012 512 | Digital signature (512-bit) | `CALG_GOST_2012_512` |
| GOST R 34.11-2012 256 | Magma | `CALG_GOST_34_11_2012_256` |
| GOST R 34.11-2012 512 | Kuznechick | `CALG_GOST_34_11_2012_512` |
| GOST 28147-89 | Symmetric encryption | `szOID_GOST28147_89` |
| RSA, AES | Standard algorithms | via PROV_RSA_AES |

## Quick Start

### Provider and Key

```rust
use cpcsp::provider::Provider;
use cpcsp::key::Key;
use cpcsp_ffi_linux::raw_constants::*;

let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
let key = Key::gen(prov.raw_handle(), CALG_GOST_2012_256, CRYPT_EXPORTABLE)?;
println!("Key length: {} bits", key.key_len()?);
```

### Symmetric Encryption

```rust
use cpcsp::provider::Provider;
use cpcsp::key::Key;
use cpcsp::hash::Hash;
use cpcsp_ffi_linux::raw_constants::*;

let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;

// Cryptographic random bytes (CryptGenRandom)
let rnd = prov.gen_random(32)?;

// Derive a symmetric key from a hashed secret (CryptDeriveKey)
let hash = Hash::create(prov.raw_handle(), CALG_GOST_34_11_2012_256, 0)?;
hash.update(b"password")?;
let key = Key::derive(&prov, CALG_GOST28147_89, &hash, 0)?;

let encrypted = key.encrypt(b"Secret message", true)?; // final block
let mut ciphertext = encrypted.clone();
let len = key.decrypt(&mut ciphertext, true)?;
assert_eq!(&ciphertext[..len], b"Secret message");
```

### Hashing

```rust
use cpcsp::provider::Provider;
use cpcsp::hash::Hash;
use cpcsp_ffi_linux::raw_constants::*;

let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
let hash = Hash::create(prov.raw_handle(), CALG_GOST_34_11_2012_256, 0)?;
hash.update(b"Hello, CryptoPro!")?;
let digest = hash.hash_value()?;
println!("Hash: {} bytes", digest.len());
```

### Certificate Store

```rust
use cpcsp::cert_store::CertStore;

let store = CertStore::open_system("MY")?;
println!("Certificates: {}", store.count());

for cert in store.iter().take(5) {
    println!("  Subject: {:?}", cert.subject_name());
}
```

### Sign and Verify

```rust
use cpcsp::cert_store::CertStore;
use cpcsp::sign::{Signer, sign_message, verify_signature};
use cpcsp_ffi_linux::raw_constants::*;

let store = CertStore::open_system("MY")?;
let cert = store.iter().next().expect("No certificates");

let signer = Signer::new(&cert, AT_KEYEXCHANGE, szOID_GOST_R3411_2012_256);
let signed = sign_message(&[signer], b"Hello", false)?;
let result = verify_signature(&signed)?;
assert_eq!(result.content, b"Hello");
```

### Detached Signatures

```rust
use cpcsp::cert_store::CertStore;
use cpcsp::sign::{Signer, sign_message, verify_detached_signature,
                  sign_message_signer_count, message_certificates};
use cpcsp_ffi_linux::raw_constants::*;

let store = CertStore::open_system("MY")?;
let cert = store.iter().next().expect("No certificates");

let signer = Signer::new(&cert, AT_KEYEXCHANGE, szOID_GOST_R3411_2012_256);
let signed = sign_message(&[signer], b"Payload", true)?; // detached=true

// Verify the detached signature over the original data
let result = verify_detached_signature(&signed, b"Payload")?;
assert_eq!(result.content, b"Payload");

// Introspect the message
let signers = sign_message_signer_count(&signed)?;
let certs = message_certificates(&signed)?;
```

### Encrypt and Decrypt

```rust
use cpcsp::cert_store::CertStore;
use cpcsp::encrypt::{encrypt_message, decrypt_message};

let store = CertStore::open_system("MY")?;
let cert = store.iter().next().expect("No certificates");

let encrypted = encrypt_message(&[&cert], b"Secret message")?;
let decrypted = decrypt_message(&encrypted, &store)?;
assert_eq!(decrypted, b"Secret message");
```

### PKCS#12 (PFX)

```rust
use cpcsp::cert_store::CertStore;
use cpcsp::pfx::Pfx;
use cpcsp_ffi_linux::raw_constants::*;

let store = CertStore::open_system("MY")?;
let pfx = Pfx::export(&store, "password", PKCS12_EXPORT_CERTIFICATES)?;
assert!(Pfx::is_pfx_blob(&pfx));

let imported = Pfx::import(&pfx, "password")?;
println!("Imported: {} certs", imported.count());
```

### Private Key and Self-Signed Certificate

```rust
use cpcsp::provider::Provider;
use cpcsp::cert_store::CertStore;
use cpcsp::selfsign::create_self_signed;
use cpcsp_ffi_linux::raw_constants::*;

// Access the private key bound to a certificate
let store = CertStore::open_system("MY")?;
let cert = store.iter().next().expect("No certificates");
if cert.has_private_key() {
    let priv_key = cert.acquire_private_key()?;
    println!("Key spec: {}", priv_key.key_spec());
}

// Or create a self-signed certificate (needs a real key container)
let prov = Provider::acquire_system(PROV_GOST_2012_256, 0)?;
let selfsigned = create_self_signed(
    &prov,
    "CN=Example, O=Organization",
    AT_KEYEXCHANGE,
    szOID_GOST_R3411_2012_256,
    5, // validity in years
)?;
```

### ASN.1 Encode/Decode

```rust
use cpcsp::asn1::{Asn1, Decoded};
use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::CERT_PUBLIC_KEY_INFO;

let mut key_info: CERT_PUBLIC_KEY_INFO = unsafe { std::mem::zeroed() };

// Typed DER encoding (CryptEncodeObject)
let der = unsafe { Asn1::encode_typed(szX509_PUBLIC_KEY_INFO, &mut key_info)? };

// Provider-allocated decode with RAII (CryptDecodeObjectEx + ALLOC_FLAG)
let decoded: Decoded<CERT_PUBLIC_KEY_INFO> =
    unsafe { Asn1::decode_ex_alloc(szX509_PUBLIC_KEY_INFO, &der, 0)? };
let info = decoded.inner();
```

## Project Structure

```
cpcsp-rs/
├── crates/
│   ├── cpcsp-ffi-linux/    # Raw FFI bindings (Linux)
│   │   ├── src/
│   │   │   ├── raw_types.rs      # #[repr(C)] structs
│   │   │   ├── raw_constants.rs  # Constants and ALG_IDs
│   │   │   ├── capi10.rs         # libcapi10.so (50 functions)
│   │   │   └── capi20.rs         # libcapi20.so (162 functions)
│   │   └── tests/
│   │       └── layout_tests.rs   # 77 struct size/offset tests
│   └── cpcsp/              # Safe Rust API
│       ├── src/
│       │   ├── lib.rs
│       │   ├── types/            # BOOL, Handle, Blob, Error
│       │   ├── ffi_helpers/      # Buffer and string helpers
│       │   ├── provider.rs       # CryptAcquireContext, CryptGenRandom
│       │   ├── key.rs            # CryptGenKey, CryptDeriveKey, encrypt/decrypt
│       │   ├── hash.rs           # CryptCreateHash, CryptHashData
│       │   ├── cert_store.rs     # CertOpenSystemStore
│       │   ├── certificate.rs    # X.509 context, private keys
│       │   ├── sign.rs           # CryptSignMessage, detached verification
│       │   ├── encrypt.rs        # CryptEncryptMessage
│       │   ├── pfx.rs            # PFXImportCertStore
│       │   ├── asn1.rs           # Typed DER encode/decode, Decoded<T>
│       │   ├── selfsign.rs       # CertCreateSelfSignCertificate
│       │   └── chain.rs          # CertGetCertificateChain
│       └── examples/
│           ├── provider_and_key.rs
│           ├── hash_data.rs
│           ├── cert_store.rs
│           └── sign_and_verify.rs

```

## Requirements

- **CryptoPro CSP 5.0** installed at `/opt/cprocsp`
- **Linux** (amd64)
- **Rust** 2021 edition

## Building

```sh
# Set library path for linking
export RUSTFLAGS="-L /opt/cprocsp/lib/amd64"

# Run all tests
cargo test --workspace

# Run examples
cargo run --example provider_and_key
cargo run --example hash_data
cargo run --example cert_store
cargo run --example sign_and_verify

# Generate documentation
cargo doc --workspace --no-deps --open
```

## Testing

138 tests covering:
- 77 FFI layout tests (struct sizes and offsets)
- 42 unit tests (provider, key, hash, cert_store, certificate, sign, encrypt, pfx, asn1)
- 19 doc tests

```sh
cargo test --workspace
```

## Architecture

- **Two FFI crates**: `cpcsp-ffi-linux` (Linux) and future `cpcsp-ffi-windows`
- **One safe crate**: `cpcsp` with platform-conditional dependencies
- **Handwritten bindings**: no bindgen, verified against GCC `offsetof()` and `sizeof()`
- **RAII everywhere**: `Drop` for `HCRYPTPROV`, `HCRYPTKEY`, `HCRYPTHASH`, `HCERTSTORE`, `PCCERT_CONTEXT`, `Decoded<T>`, `PrivateKey`
- **Non-uniform error handling**: some CryptoPro functions return "success" when they fail (GOST quirks on MS CryptoAPI)

## License

BSD-2-Clause
