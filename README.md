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
│       │   ├── provider.rs       # CryptAcquireContext
│       │   ├── key.rs            # CryptGenKey, CryptExportKey
│       │   ├── hash.rs           # CryptCreateHash, CryptHashData
│       │   ├── cert_store.rs     # CertOpenSystemStore
│       │   ├── certificate.rs    # CertCreateCertificateContext
│       │   ├── sign.rs           # CryptSignMessage
│       │   ├── encrypt.rs        # CryptEncryptMessage
│       │   └── pfx.rs            # PFXImportCertStore
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

132 tests covering:
- 77 FFI layout tests (struct sizes and offsets)
- 42 unit tests (provider, key, hash, cert_store, certificate, sign, encrypt, pfx)
- 13 doc tests

```sh
cargo test --workspace
```

## Architecture

- **Two FFI crates**: `cpcsp-ffi-linux` (Linux) and future `cpcsp-ffi-windows`
- **One safe crate**: `cpcsp` with platform-conditional dependencies
- **Handwritten bindings**: no bindgen, verified against GCC `offsetof()` and `sizeof()`
- **RAII everywhere**: `Drop` for `HCRYPTPROV`, `HCRYPTKEY`, `HCRYPTHASH`, `HCERTSTORE`, `PCCERT_CONTEXT`
- **Non-uniform error handling**: some CryptoPro functions return "success" when they fail (GOST quirks on MS CryptoAPI)

## License

BSD-2-Clause
