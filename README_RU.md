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
- **Симметричное шифрование** — сессионные ключи ГОСТ 28147-89 (`CryptEncrypt`/`CryptDecrypt`)
- **Производные ключи и CSPRNG** — `CryptDeriveKey`, `CryptGenRandom`
- **Приватные ключи** — получение приватного ключа, связанного с сертификатом
- **Самоподписанные сертификаты** — генерация X.509 (`CertCreateSelfSignCertificate`)
- **ASN.1 encode/decode** — типизированное кодирование/декодирование DER с RAII (`Decoded<T>`)

## Поддерживаемые алгоритмы

| Алгоритм | Описание | FFI-константа |
|----------|----------|---------------|
| ГОСТ Р 34.10-2012 256 | Электронная подпись (256 бит) | `CALG_GOST_2012_256` |
| ГОСТ Р 34.10-2012 512 | Электронная подпись (512 бит) | `CALG_GOST_2012_512` |
| ГОСТ Р 34.11-2012 256 | Магма | `CALG_GOST_34_11_2012_256` |
| ГОСТ Р 34.11-2012 512 | Кузнечик | `CALG_GOST_34_11_2012_512` |
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

### Симметричное шифрование

```rust
use cpcsp::provider::Provider;
use cpcsp::key::Key;
use cpcsp::hash::Hash;
use cpcsp_ffi_linux::raw_constants::*;

let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;

// Криптографические случайные байты (CryptGenRandom)
let rnd = prov.gen_random(32)?;

// Производный симметричный ключ из хеша секрета (CryptDeriveKey)
let hash = Hash::create(prov.raw_handle(), CALG_GOST_34_11_2012_256, 0)?;
hash.update(b"пароль")?;
let key = Key::derive(&prov, CALG_GOST28147_89, &hash, 0)?;

let encrypted = key.encrypt(b"Секретное сообщение", true)?; // финальный блок
let mut ciphertext = encrypted.clone();
let len = key.decrypt(&mut ciphertext, true)?;
assert_eq!(&ciphertext[..len], b"Секретное сообщение");
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

### Отсоединённые подписи

```rust
use cpcsp::cert_store::CertStore;
use cpcsp::sign::{Signer, sign_message, verify_detached_signature,
                  sign_message_signer_count, message_certificates};
use cpcsp_ffi_linux::raw_constants::*;

let store = CertStore::open_system("MY")?;
let cert = store.iter().next().expect("Нет сертификатов");

let signer = Signer::new(&cert, AT_KEYEXCHANGE, szOID_GOST_R3411_2012_256);
let signed = sign_message(&[signer], b"Данные", true)?; // detached=true

// Проверка отсоединённой подписи по исходным данным
let result = verify_detached_signature(&signed, b"Данные")?;
assert_eq!(result.content, b"Данные");

// Сведения о сообщении
let signers = sign_message_signer_count(&signed)?;
let certs = message_certificates(&signed)?;
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

### Приватный ключ и самоподписанный сертификат

```rust
use cpcsp::provider::Provider;
use cpcsp::cert_store::CertStore;
use cpcsp::selfsign::create_self_signed;
use cpcsp_ffi_linux::raw_constants::*;

// Получить приватный ключ, связанный с сертификатом
let store = CertStore::open_system("MY")?;
let cert = store.iter().next().expect("Нет сертификатов");
if cert.has_private_key() {
    let priv_key = cert.acquire_private_key()?;
    println!("Key spec: {}", priv_key.key_spec());
}

// Или создать самоподписанный сертификат (нужен реальный контейнер ключей)
let prov = Provider::acquire_system(PROV_GOST_2012_256, 0)?;
let selfsigned = create_self_signed(
    &prov,
    "CN=Example, O=Organization",
    AT_KEYEXCHANGE,
    szOID_GOST_R3411_2012_256,
    5, // срок действия в годах
)?;
```

### ASN.1 Encode/Decode

```rust
use cpcsp::asn1::{Asn1, Decoded};
use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::CERT_PUBLIC_KEY_INFO;

let mut key_info: CERT_PUBLIC_KEY_INFO = unsafe { std::mem::zeroed() };

// Типизированное DER-кодирование (CryptEncodeObject)
let der = unsafe { Asn1::encode_typed(szX509_PUBLIC_KEY_INFO, &mut key_info)? };

// Декодирование с выделением провайдером и RAII (CryptDecodeObjectEx + ALLOC_FLAG)
let decoded: Decoded<CERT_PUBLIC_KEY_INFO> =
    unsafe { Asn1::decode_ex_alloc(szX509_PUBLIC_KEY_INFO, &der, 0)? };
let info = decoded.inner();
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
│       │   ├── provider.rs       # CryptAcquireContext, CryptGenRandom
│       │   ├── key.rs            # CryptGenKey, CryptDeriveKey, encrypt/decrypt
│       │   ├── hash.rs           # CryptCreateHash, CryptHashData
│       │   ├── cert_store.rs     # CertOpenSystemStore
│       │   ├── certificate.rs    # X.509 context, приватные ключи
│       │   ├── sign.rs           # CryptSignMessage, проверка detached
│       │   ├── encrypt.rs        # CryptEncryptMessage
│       │   ├── pfx.rs            # PFXImportCertStore
│       │   ├── asn1.rs           # Типизированный DER encode/decode, Decoded<T>
│       │   ├── selfsign.rs       # CertCreateSelfSignCertificate
│       │   └── chain.rs          # CertGetCertificateChain
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

138 тестов, включая:
- 77 FFI-тестов layout (размеры и смещения структур)
- 42 unit-теста (provider, key, hash, cert_store, certificate, sign, encrypt, pfx, asn1)
- 19 doc-тестов (примеры в модулях)

```sh
cargo test --workspace
```

## Архитектура

- **Два FFI-крейта**: `cpcsp-ffi-linux` (Linux) и будущий `cpcsp-ffi-windows`
- **Один safe-крейт**: `cpcsp` с условными зависимостями от платформы
- **Рукописные биндинги**: без bindgen, проверены через GCC `offsetof()` и `sizeof()`
- **Partially RAII**: `Drop` для `HCRYPTPROV`, `HCRYPTKEY`, `HCRYPTHASH`, `HCERTSTORE`, `PCCERT_CONTEXT`, `Decoded<T>`, `PrivateKey`
- **Неединообразная обработка ошибок**: некоторые функции КриптоПро возвращают «успех» при фактической ошибке (особенности ГОСТ в MS CryptoAPI)

## Лицензия

BSD-2-Clause
