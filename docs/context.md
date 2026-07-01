# cpcsp-rs — Контекст проекта (обновлено: 2026-07-01)

## Цель
Безопасная Rust FFI-обёртка над CryptoPro CSP 5.0 (`libcapi10.so`, `libcapi20.so`), предоставляющая идиоматичный Rust API.

## Ограничения и предпочтения
- Рукописные FFI-биндинги (без bindgen)
- `#[repr(C)]` структуры — точное совпадение layout с C
- Два отдельных крейта для Linux/Windows FFI + общий safe API крейт
- Feature flags для разделения win-linux
- Тестирование на реальном КриптоПро в `/opt/cprocsp`
- Обработка ошибок НЕ единообразна (ГОСТ-квирки в MS CryptoAPI)
- Комментарии и ссылки на исходники в коде
- `//` комментарии на extern блоках, `///` — на safe обёртках
- Начальный фокус: CryptoAPI (capi10 ~50 функций) и CryptoAPI Extensions (capi20 ~162 функции)
- Идиоматичный Rust API с type safety, Option/Result, Builder паттернами

## Прогресс

### Выполнено

#### Step 01: Raw FFI Bindings
- `cpcsp-ffi-linux`: `raw_types.rs` (~1300 строк), `raw_constants.rs` (~600 строк)
- `capi10.rs` (~50 functions), `capi20.rs` (162 functions)
- 77 layout тестов — все проходят
- Build scripts линковки: `libcapi10.so`, `libcapi20.so`, `librdrsup.so`

#### Step 02: Provider
- `provider.rs`: Provider::acquire/acquire_system, RAII Drop

#### Step 03: Key и Hash
- `key.rs`: Key::gen, from_blob, from_user_key, duplicate, export_blob, get/set_key_param, key_len, sign_hash, verify_signature
- `hash.rs`: Hash::create, duplicate, update, hash_session_key, get/set_hash_param, hash_value, hash_size, sign
- Эмпирические ALG_ID: CALG_GOST_2012_256=0x2400, CALG_GOST_34_11_2012_256=0x8021, CALG_GOST_34_11_2012_512=0x8022

#### Step 04: CertStore и Certificate
- `cert_store.rs`: CertStore::open_system, iter, find_by_sha1, add_encoded, add_to_system_store, from_raw
- `certificate.rs`: Certificate::from_der, subject_name, issuer_name, to_der, find_extension, get_property, sha1_hash, verify_time

#### Step 05: Sign и Encrypt
- `sign.rs`: Signer, sign_message, verify_signature, VerifyResult
- `encrypt.rs`: encrypt_message, decrypt_message, encrypt_and_sign_message

#### Step 06: PFX
- `pfx.rs`: Pfx::import, import_with_flags, is_pfx_blob, verify_password, export

#### Step 07: Примеры и Rustdoc
- 4 примера: provider_and_key, hash_data, cert_store, sign_and_verify
- Rustdoc комментарии во всех модулях
- 132 теста (42 unit + 77 layout + 13 doc)

#### Step 08: README
- README.md (EN) + README_RU.md (RU)

#### Step 09: CertChain и CertRevocation
- `chain.rs`: CertChain::build(), verify_policy(), CertRevocation::check()
- CertChainPolicy: Base, Authenticode, Ssl, BasicConstraints, NtAuth
- CertRevocationStatus: is_revoked(), error(), reason()
- raw_constants.rs: CERT_CHAIN_*, CERT_VERIFY_REV_*, CERT_TRUST_*
- MinCertChainContext: repr(C) struct для доступа к полям opaque PCCERT_CHAIN_CONTEXT

#### Step 10: ASN.1 операции
- `asn1.rs`: Asn1::encode/decode, Base64/Hex, hash, sign_and_encode, verify
- raw_constants.rs: CRYPT_STRING_*, szOID_* (ASN.1 structure types)

#### Step 11: Потоковый CryptMsg
- `msg.rs`: CryptMsg::open_to_encode/decode, update, get_param, control
- CryptMsg::encode_signed/enveloped, decode, get_type, verify_signature
- raw_constants.rs: CMSG_INNER_CONTENT_PARAM, CMSG_SIGNER_CERT_ID_PARAM

#### Step 12: CryptoPro PKI
- `pki.rs`: Pki::install_certificate, PIN callbacks, OID-информация
- OidInfo: safe обёртка над CRYPT_OID_INFO

### Тесты
136 тестов проходят:
- 77 FFI layout тестов (размеры/смещения структур)
- 42 unit теста
- 17 doc тестов

## Архитектура
```
cpcsp-rs/
├── crates/
│   ├── cpcsp-ffi-linux/    # Raw FFI bindings (Linux)
│   │   ├── src/
│   │   │   ├── raw_types.rs      # #[repr(C)] структуры (~1300 строк)
│   │   │   ├── raw_constants.rs  # Константы и ALG_ID (~600 строк)
│   │   │   ├── capi10.rs         # libcapi10.so (50 функций)
│   │   │   └── capi20.rs         # libcapi20.so (162 функции)
│   │   └── tests/
│   │       └── layout_tests.rs   # 77 тестов
│   └── cpcsp/              # Safe Rust API
│       ├── src/
│       │   ├── lib.rs
│       │   ├── types/            # BOOL, Handle, Blob, Error
│       │   ├── ffi_helpers/      # Buffer и string helpers
│       │   ├── provider.rs       # CryptAcquireContext
│       │   ├── key.rs            # CryptGenKey, CryptExportKey
│       │   ├── hash.rs           # CryptCreateHash, CryptHashData
│       │   ├── cert_store.rs     # CertOpenSystemStore
│       │   ├── certificate.rs    # CertCreateCertificateContext
│       │   ├── chain.rs          # CertGetCertificateChain
│       │   ├── asn1.rs           # CryptEncodeObject, Base64, hash
│       │   ├── msg.rs            # CryptMsgOpenToEncode/Decode
│       │   ├── sign.rs           # CryptSignMessage
│       │   ├── encrypt.rs        # CryptEncryptMessage
│       │   ├── pki.rs            # CryptoPro CPCrypt* extensions
│       │   └── pfx.rs            # PFXImportCertStore
│       └── examples/
│           ├── provider_and_key.rs
│           ├── hash_data.rs
│           ├── cert_store.rs
│           └── sign_and_verify.rs
└── docs/
    ├── step01.md
    └── ...
```

## Ключевые решения
- Два крейта FFI + один safe крейт (не bindgen)
- Handle<T> разбит на ProvHandle/KeyHandle/HashHandle (специализированные Drop)
- `check_bool()` хелпер для FFI-вызовов
- `CpcspError::last_os_error()` через GetLastError из librdrsup.so
- ALG_ID определены эмпирически (0x2400, 0x8021, 0x8022)
- PCCERT_CHAIN_CONTEXT opaque (*const c_void) — MinCertChainContext для доступа к полям

## Следующий шаг
Все 4 приоритетных блока реализованы. Возможные дальнейшие шаги:
- Примеры для chain.rs, asn1.rs, msg.rs, pki.rs
- Rustdoc для новых модулей
- Windows FFI crate (`cpcsp-ffi-windows`)
- Async/Send/Sync
- Тесты на реальных сертификатах КриптоПро
- Функции удаления/перечисления хранилищ (CertDeleteCertificateFromStore, CertEnumSystemStore, etc.)
- Контрподписи (CryptMsgCountersign)
- Самоподписанные сертификаты (CertCreateSelfSignCertificate)

Коммиты: ef395e1 → c6f64f2 → 8a0f54a → f748945 → 3e7ad6b → c5d1a1e → 8559207 → 1b95d3e → f764273 → ca2978c → 9404dbf → 755a6bc
