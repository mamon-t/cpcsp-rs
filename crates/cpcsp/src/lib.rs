/// Safe Rust wrapper for CryptoPro CSP 5.0.
///
/// Этот crate предоставляет идиоматический Rust API для работы с
/// КриптоПро CSP через FFI-обёртку.
///
/// Основные модули:
/// - `types` — безопасные Rust-типы (BOOL, Handle, Blob, Error)
/// - `ffi_helpers` — хелперы для FFI-вызовов (двойной вызов, строки)
/// - `provider` — криптографический провайдер (CryptAcquireContext)
/// - `key` — криптографические ключи (CryptGenKey, CryptExportKey, ...)
/// - `hash` — хеш-объекты (CryptCreateHash, CryptHashData, ...)
/// - `cert_store` — хранилище сертификатов (CertOpenSystemStore, ...)
/// - `certificate` — контекст сертификата (CertCreateCertificateContext, ...)
/// - `sign` — подпись CMS-сообщений (CryptSignMessage, CryptVerifyMessageSignature)
/// - `encrypt` — шифрование CMS-сообщений (CryptEncryptMessage, CryptDecryptMessage)

#[cfg(target_os = "linux")]
pub extern crate cpcsp_ffi_linux;

pub mod types;
pub mod ffi_helpers;
pub mod provider;
pub mod key;
pub mod hash;
pub mod cert_store;
pub mod certificate;
pub mod sign;
pub mod encrypt;
