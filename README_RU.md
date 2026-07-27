# cpcsp-rs

Безопасная Rust-обёртка над [CryptoPro CSP 5.0](https://www.cryptopro.ru/products/csp) — наиболее широко используемым криптографическим провайдером в России.

> **[README in English →](README.md)**

## Возможности

- **Идиоматичный Rust API** — безопасные обёртки с RAII, `Result`, `Option`
- **Рукописные FFI-биндинги** — без bindgen, полный контроль над типами и layout
- **ГОСТ-криптография** — ГОСТ Р 34.10-2012, ГОСТ Р 34.11-2012 (Магма/Лузнечик), ГОСТ 28147-89
- **CMS-операции** — подпись, проверка, шифрование, дешифрование сообщений
- **Хранилища сертификатов** — открытие, перечисление, поиск сертификатов
- **PKCS#12 (PFX)** — импорт/экспорт контейнеров с сертификатами

## Поддерживаемые алгоритмы

| Алгоритм | Описание | FFI-константа |
|----------|----------|---------------|
| ГОСТ Р 34.10-2012 256 | Электронная подпись (256 бит) | `CALG_GOST_2012_256` |
| ГОСТ Р 34.10-2012 512 | Электронная подпись (512 бит) | `CALG_GOST_2012_512` |
| ГОСТ Р 34.11-2012 256 | Хеш Стрибог-256 | `CALG_GOST_34_11_2012_256` |
| ГОСТ Р 34.11-2012 512 | Хеш Стрибог-512 | `CALG_GOST_34_11_2012_512` |
| ГОСТ 28147-89 | Симметричное шифрование | `szOID_GOST28147_89` |
| RSA, AES | Стандартные алгоритмы | через PROV_RSA_AES |

## Быстрый старт

### Провайдер и ключ

```rust
use cpcsp::provider::Provider;
use cpcsp::key::Key;
use cpcsp_ffi_linux::raw_constants::*;

let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
let key = Key::gen(prov.raw_handle(), CALG_GOST_2012_256, CRYPT_EXPORTABLE)?;
println!("Размер ключа: {} бит", key.key_len()?);
```

### Хеширование

```rust
use cpcsp::provider::Provider;
use cpcsp::hash::Hash;
use cpcsp_ffi_linux::raw_constants::*;

let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
let hash = Hash::create(prov.raw_handle(), CALG_GOST_34_11_2012_256, 0)?;
hash.update(b"Привет, КриптоПро!")?;
let digest = hash.hash_value()?;
println!("Хеш: {} байт", digest.len());
```

### Хранилище сертификатов

```rust
use cpcsp::cert_store::CertStore;

let store = CertStore::open_system("MY")?;
println!("Сертификатов: {}", store.count());

for cert in store.iter().take(5) {
    println!("  Субъект: {:?}", cert.subject_name());
}
```

### Подпись и проверка

```rust
use cpcsp::cert_store::CertStore;
use cpcsp::sign::{Signer, sign_message, verify_signature};
use cpcsp_ffi_linux::raw_constants::*;

let store = CertStore::open_system("MY")?;
let cert = store.iter().next().expect("Нет сертификатов");

let signer = Signer::new(&cert, AT_KEYEXCHANGE, szOID_GOST_R3411_2012_256);
let signed = sign_message(&[signer], b"Привет", false)?;
let result = verify_signature(&signed)?;
assert_eq!(result.content, b"Привет");
```

### Шифрование и дешифрование

```rust
use cpcsp::cert_store::CertStore;
use cpcsp::encrypt::{encrypt_message, decrypt_message};

let store = CertStore::open_system("MY")?;
let cert = store.iter().next().expect("Нет сертификатов");

let encrypted = encrypt_message(&[&cert], b"Секретное сообщение")?;
let decrypted = decrypt_message(&encrypted, &store)?;
assert_eq!(decrypted, b"Секретное сообщение");
```

### PKCS#12 (PFX)

```rust
use cpcsp::cert_store::CertStore;
use cpcsp::pfx::Pfx;
use cpcsp_ffi_linux::raw_constants::*;

let store = CertStore::open_system("MY")?;
let pfx = Pfx::export(&store, "пароль", PKCS12_EXPORT_CERTIFICATES)?;
assert!(Pfx::is_pfx_blob(&pfx));

let imported = Pfx::import(&pfx, "пароль")?;
println!("Импортировано сертификатов: {}", imported.count());
```

## Структура проекта

```
cpcsp-rs/
├── crates/
│   ├── cpcsp-ffi-linux/    # Сырые FFI-биндинги (Linux)
│   │   ├── src/
│   │   │   ├── raw_types.rs      # #[repr(C)] структуры
│   │   │   ├── raw_constants.rs  # Константы и ALG_ID
│   │   │   ├── capi10.rs         # libcapi10.so (50 функций)
│   │   │   └── capi20.rs         # libcapi20.so (162 функции)
│   │   └── tests/
│   │       └── layout_tests.rs   # 77 тестов размеров/смещений
│   └── cpcsp/              # Безопасный Rust API
│       ├── src/
│       │   ├── lib.rs
│       │   ├── types/            # BOOL, Handle, Blob, Error
│       │   ├── ffi_helpers/      # Хелперы для буферов и строк
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

## Требования

- **КриптоПро CSP 5.0** установлен в `/opt/cprocsp`
- **Linux** (amd64)
- **Rust** 2021 edition

## Сборка

```sh
# Указать путь к библиотекам для линковки
export RUSTFLAGS="-L /opt/cprocsp/lib/amd64"

# Запустить все тесты
cargo test --workspace

# Запустить примеры
cargo run --example provider_and_key
cargo run --example hash_data
cargo run --example cert_store
cargo run --example sign_and_verify

# Сгенерировать документацию
cargo doc --workspace --no-deps --open
```

## Тесты

132 теста, включая:
- 77 FFI-тестов layout (размеры и смещения структур)
- 42 unit-теста (provider, key, hash, cert_store, certificate, sign, encrypt, pfx)
- 13 doc-тестов (примеры в модулях)

```sh
cargo test --workspace
```

## Архитектура

- **Два FFI-крейта**: `cpcsp-ffi-linux` (Linux) и будущий `cpcsp-ffi-windows`
- **Один safe-крейт**: `cpcsp` с условными зависимостями от платформы
- **Рукописные биндинги**: без bindgen, проверены через GCC `offsetof()` и `sizeof()`
- **Partially RAII**: `Drop` для `HCRYPTPROV`, `HCRYPTKEY`, `HCRYPTHASH`, `HCERTSTORE`, `PCCERT_CONTEXT`
- **Неединообразная обработка ошибок**: некоторые функции КриптоПро возвращают «успех» при фактической ошибке (особенности ГОСТ в MS CryptoAPI)

## Лицензия

BSD-2-Clause
