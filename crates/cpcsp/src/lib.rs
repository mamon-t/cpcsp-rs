//! # cpcsp — Safe Rust wrapper for CryptoPro CSP 5.0
//!
//! Этот crate предоставляет идиоматический Rust API для работы с
//! криптографическим провайдером КриптоПро CSP 5.0.
//!
//! ## Быстрый старт
//!
//! ```no_run
//! use cpcsp::provider::Provider;
//! use cpcsp::key::Key;
//! use cpcsp::hash::Hash;
//! use cpcsp_ffi_linux::raw_constants::*;
//!
//! // Открыть провайдер и сгенерировать ключ
//! let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT).unwrap();
//! let key = Key::gen(prov.raw_handle(), CALG_GOST_2012_256, CRYPT_EXPORTABLE).unwrap();
//!
//! // Хешировать данные
//! let hash = Hash::create(prov.raw_handle(), CALG_GOST_34_11_2012_256, 0).unwrap();
//! hash.update(b"Hello, CryptoPro!").unwrap();
//! let digest = hash.hash_value().unwrap();
//! println!("Хеш: {} байт", digest.len());
//! ```
//!
//! ## Модули
//!
//! | Модуль | Описание | FFI |
//! |--------|----------|-----|
//! | [`types`] | Безопасные Rust-типы (BOOL, Handle, Blob, Error) | — |
//! | [`provider`] | Криптографический провайдер | `CryptAcquireContext` |
//! | [`key`] | Криптографические ключи | `CryptGenKey`, `CryptExportKey` |
//! | [`hash`] | Хеш-объекты | `CryptCreateHash`, `CryptHashData` |
//! | [`cert_store`] | Хранилище сертификатов | `CertOpenSystemStore` |
//! | [`certificate`] | Контекст сертификата (X.509) | `CertCreateCertificateContext` |
//! | [`sign`] | Подпись CMS-сообщений | `CryptSignMessage` |
//! | [`encrypt`] | Шифрование CMS-сообщений | `CryptEncryptMessage` |
//! | [`pfx`] | Импорт/экспорт PKCS#12 | `PFXImportCertStore` |
//!
//! ## Поддерживаемые алгоритмы
//!
//! - **ГОСТ Р 34.12-2015** (Кузнечик/Magma) — симметричное шифрование
//! - **ГОСТ Р 34.10-2012** (256/512) — электронная цифровая подпись
//! - **ГОСТ Р 34.11-2012** (Стрибог-256/512) — хеширование
//! - **ГОСТ 28147-89** — симметричное шифрование (legacy)
//! - RSA, AES — через стандартные провайдеры
//!
//! ## Особенности
//!
//! - Все дескрипторы (`HCRYPTPROV`, `HCRYPTKEY`, `HCRYPTHASH`, `HCERTSTORE`)
//!   автоматически освобождаются через `Drop`
//! - FFI-биндинги написаны вручную (без bindgen)
//! - Тесты проверяют реальную работу с КриптоПро CSP

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
pub mod pfx;
pub mod chain;
pub mod asn1;
pub mod msg;
pub mod pki;
pub mod selfsign;
