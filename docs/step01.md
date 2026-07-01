# Step 01 — Raw FFI bindings для CryptoPro CSP 5.0

## Цель
Создать safe Rust обёртку над CryptoPro CSP 5.0 (`libcapi10.so`, `libcapi20.so`) с
.handwritten FFI-биндингами (без bindgen).

## Архитектура
```
cpcsp-ffi-linux/   — raw FFI (Linux)
cpcsp-ffi-windows/  — raw FFI (Windows, будущее)
cpcsp/              — safe API
```

## Что сделано

### `cpcsp-ffi-linux/src/raw_types.rs`
~1300 строк. Определены `#[repr(C)]` структуры, точные layout-аналоги C-типов:

| Категория | Структуры |
|---|---|
| Базовые Windows-типы | BOOL, DWORD, WORD, BYTE, LONG, ALG_ID, UINT, HRESULT, ULONG_PTR, HWND, HMODULE, HLOCAL |
| Дескрипторы | HCRYPTPROV, HCRYPTKEY, HCRYPTHASH, HCERTSTORE, HCRYPTMSG, HCERTCHAINENGINE, HCERT_SERVER_OCSP_RESPONSE, HCRYPTOIDFUNCSET, HCRYPTOIDFUNCADDR |
| BLOB-типы | DataBlob, BitBlob, BLOBHEADER, RSAPUBKEY |
| Криптографические | HMAC_INFO, PROV_ENUMALGS, PROV_ENUMALGS_EX, CRYPT_ALGORITHM_IDENTIFIER, CRYPT_ATTRIBUTE, CRYPT_ATTRIBUTES, CRYPT_BIT_BLOB, CRYPT_KEY_PROV_INFO, CRYPT_KEY_PROV_PARAM, CRYPT_PRIVATE_KEY_INFO, CMS_DH_KEY_INFO |
| Время | FILETIME, SYSTEMTIME |
| Сертификаты | CERT_EXTENSION, CERT_RDN_ATTR, CERT_RDN, CERT_PUBLIC_KEY_INFO, CERT_INFO, CERT_CONTEXT, CERT_SIGNED_CONTENT_INFO, CERT_REQUEST_INFO, CERT_BASIC_CONSTRAINTS2_INFO, CERT_EXTENSIONS |
| CRL | CRL_ENTRY, CRL_INFO, CRL_CONTEXT |
| CTL | CTL_ENTRY, CTL_INFO, CTL_CONTEXT |
| Цепочки | CERT_USAGE_MATCH, CERT_CHAIN_PARA, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS |
| Отозванность | CERT_REVOCATION_PARA, CERT_REVOCATION_STATUS, CERT_REVOCATION_CRL_INFO |
| CMS-сообщения | CRYPT_SIGN_MESSAGE_PARA, CRYPT_VERIFY_MESSAGE_PARA, CRYPT_ENCRYPT_MESSAGE_PARA, CRYPT_DECRYPT_MESSAGE_PARA, CMSG_STREAM_INFO |
| OID | CRYPT_OID_INFO, CRYPT_OID_FUNC_ENTRY, CRYPT_URL_ARRAY, CRYPT_URL_INFO |
| Прочее | VTABLEPROVSTRUC, CTL_USAGE/CERT_ENHKEY_USAGE, CERT_NAME_INFO |

Все размеры и смещения полей проверены GCC `sizeof()`/`offsetof()` на amd64 Linux.

### `cpcsp-ffi-linux/src/raw_constants.rs`
Около 500 строк. Все `#define` константы:
- Типы провайдеров (PROV_*)
- Флаги AcquireContext (CRYPT_VERIFYCONTEXT, CRYPT_NEWKEYSET, ...)
- Флаги GenKey (CRYPT_EXPORTABLE, CRYPT_ARCHIVABLE, ...)
- Флаги ExportKey (CRYPTPublicKey, ...)
- ALG_ID (CALG_GOST_*, CALG_RSA_*, CALG_SHA*, ...)
- Параметры KP_*, HP_*, PP_*
- Типы ключей (PLAINTEXTKEYBLOB, PUBLICKEYBLOB, PRIVATEKEYBLOB, ...)
- Типы кодирования (X509_ASN_ENCODING, PKCS_7_ASN_ENCODING, ...)
- Флаги CMSG/CAdES
- Флаги хранилищ сертификатов
- Свойства сертификатов (CERT_*)
- Имена провайдеров (MS_ENH_RSA_AES_PROV, CP_RSA_FULL, ...)

### `cpcsp-ffi-linux/src/capi10.rs`
~50 функций из `libcapi10.so`:
- CryptAcquireContext / CryptReleaseContext
- CryptGenKey / CryptDeriveKey / CryptImportKey
- CryptExportKey / CryptEncrypt / CryptDecrypt
- CryptGenRandom / CryptGetKeyParam / CryptSetKeyParam
- CryptGetProvParam / CryptSetProvParam
- CryptCreateHash / CryptHashData / CryptGetHashParam
- CryptSignHash / CryptVerifySignature
- и др.

### `cpcsp-ffi-linux/src/capi20.rs`
162 функции из `libcapi20.so`:
- **Cert*** (88): CertOpenStore, CertFindCertificateInStore, CertGetCertificateChain, CertCreateSelfSignCertificate, и др.
- **CryptMsg*** (14): CryptMsgOpenToEncode/Decode, CryptMsgUpdate, CryptMsgControl, и др.
- **CryptEncode*/CryptDecode*** (5): CryptEncodeObject(Ex), CryptDecodeObject(Ex), CryptFormatObject
- **CryptString*/CryptBinary*** (4)
- **CryptSign*/CryptVerify*** (15): CryptSignAndEncodeCertificate, CryptExportPublicKeyInfo, CryptHashCertificate, и др.
- **Crypt*** (message sign/encrypt, 12): CryptSignMessage, CryptEncryptMessage, CryptDecryptMessage, и др.
- **PFX*** (5): PFXImportCertStore, PFXExportCertStore, и др.
- **CPCrypt*/CPGet*** (11): CryptoPro-расширения
- **LocalAlloc/LocalFree** (2)
- **SendPKIRequest** (1, undocumented)

### `cpcsp/tests/layout_tests.rs`
77 тестов, проверяющих `size_of` и `offset_of` для всех структур.

### `cpcsp/` safe API
- `types/bool.rs` — BOOL newtype с From-конверсиями
- `types/error.rs` — CpcspError с `last_os_error()`, `check_bool()` хелперами
- `types/handle.rs` — RAII ProvHandle/KeyHandle/HashHandle с Drop
- `types/blob.rs` — DataBlob/BitBlob обёртки
- `ffi_helpers/buffer.rs` — `call_with_buffer()` для двойного вызова
- `ffi_helpers/string.rs` — UTF-8↔UTF-16 конверсия

## Проверено
- `cargo build --workspace` — OK
- 77 layout tests + 19 unit tests — все проходят
- Все структуры проверены через GCC offsetof/sizeof на amd64 Linux

## Следующий шаг
Safe wrapper модули: `provider.rs`, `key.rs`, `hash.rs`, `cert_store.rs`, `sign.rs`, `encrypt.rs`
