//! Safe обёртка над `HCERTSTORE` — хранилище сертификатов.
//!
//! Модуль предоставляет безопасный API для работы с хранилищами:
//! открытие системных хранилищ, перечисление, поиск сертификатов.
//!
//! # Системные хранилища
//!
//! | Имя | Описание |
//! |-----|----------|
//! | `"MY"` | Личные сертификаты и ключи |
//! | `"ROOT"` | Корневые сертификаты |
//! | `"CA"` | Сертификаты центров сертификации |
//! | `"AddressBook"` | Сертификаты других пользователей |
//!
//! # Пример
//!
//! ```no_run
//! use cpcsp::cert_store::CertStore;
//!
//! let store = CertStore::open_system("MY")?;
//! println!("Сертификатов в MY: {}", store.count());
//!
//! for cert in store.iter().take(5) {
//!     println!("  {:?}", cert.subject_name());
//! }
//! # Ok::<(), cpcsp::types::error::CpcspError>(())
//! ```
//!
//! Источник: CSP_WinCrypt.h:4143-4753

use std::fmt;

use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::{BOOL, BYTE, DWORD, HCERTSTORE, HCRYPTPROV, PCCERT_CONTEXT};
use cpcsp_ffi_linux::capi20::*;

use crate::certificate::Certificate;
use crate::types::error::{check_bool, CpcspError};

// ---------------------------------------------------------------------------
// CertStore
// ---------------------------------------------------------------------------

/// Хранилище сертификатов.
///
/// Владеет дескриптором `HCERTSTORE` и автоматически закрывает его при drop.
/// Соответствует вызову `CertOpenSystemStoreA` / `CertCloseStore`.
pub struct CertStore {
    handle: HCERTSTORE,
}

impl CertStore {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Открыть системное хранилище по имени.
    ///
    /// Имена хранилищ: "ROOT", "CA", "MY", "AddressBook", "AuthRoot", "Disallowed", "TrustedPeople", "TrustedPublisher".
    ///
    /// # Безопасность
    /// Хранилище открывается без проверки — проверка доступа на уровне ОС.
    pub fn open_system(name: &str) -> Result<Self, CpcspError> {
        let name_cstr = std::ffi::CString::new(name).map_err(|_| CpcspError::from_raw(0x57))?;
        unsafe {
            let handle = CertOpenSystemStoreA(0 as HCRYPTPROV, name_cstr.as_ptr());
            if handle.is_null() {
                Err(CpcspError::last_os_error())
            } else {
                Ok(Self { handle })
            }
        }
    }

    /// Создать из сырого дескриптора (ownership передаётся).
    ///
    /// # Safety
    /// `handle` должен быть валидным `HCERTSTORE`, полученным из CryptoAPI.
    pub unsafe fn from_raw(handle: HCERTSTORE) -> Self {
        Self { handle }
    }
    pub fn find_by_sha1(&self, sha1_hash: &[u8]) -> Option<Certificate> {
        if sha1_hash.len() != 20 {
            return None;
        }
        unsafe {
            let ctx = CertFindCertificateInStore(
                self.handle,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SHA1_HASH,
                sha1_hash.as_ptr() as *const _,
                std::ptr::null_mut(),
            );
            if ctx.is_null() {
                None
            } else {
                Some(Certificate::from_raw(ctx))
            }
        }
    }

    /// Найти сертификат по OID расширения.
    pub fn find_extension(&self, oid: &str, prev: Option<&Certificate>) -> Option<CertExtension> {
        let _oid_cstr = std::ffi::CString::new(oid).map_err(|_| CpcspError::from_raw(0x57)).ok()?;
        unsafe {
            let prev_ptr = prev.map(|c| c.raw_handle()).unwrap_or(std::ptr::null_mut());
            let ctx = CertFindCertificateInStore(
                self.handle,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_ANY,
                std::ptr::null(),
                prev_ptr,
            );
            if ctx.is_null() {
                return None;
            }
            let cert = Certificate::from_raw(ctx);
            let ext = cert.find_extension(&oid)?;
            Some(CertExtension {
                _store: self,
                ext,
            })
        }
    }

    /// Перечислить все сертификаты.
    pub fn iter(&self) -> CertStoreIter<'_> {
        CertStoreIter {
            store: self,
            current: std::ptr::null_mut(),
        }
    }

    /// Добавить сертификат из DER-блоба.
    pub fn add_encoded(&self, cert_der: &[u8]) -> Result<Certificate, CpcspError> {
        unsafe {
            let mut ctx: PCCERT_CONTEXT = std::ptr::null_mut();
            check_bool(|| CertAddEncodedCertificateToStore(
                self.handle,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                cert_der.as_ptr(),
                cert_der.len() as DWORD,
                CERT_STORE_ADD_USE_EXISTING,
                &mut ctx,
            ))?;
            Ok(Certificate::from_raw(ctx))
        }
    }

    /// Добавить сертификат из DER-блоба в системное хранилище.
    pub fn add_to_system_store(store_name: &str, cert_der: &[u8]) -> Result<(), CpcspError> {
        let name = std::ffi::CString::new(store_name).map_err(|_| CpcspError::from_raw(0x57))?;
        unsafe {
            check_bool(|| CertAddEncodedCertificateToSystemStoreA(
                name.as_ptr(),
                cert_der.as_ptr(),
                cert_der.len() as DWORD,
            ))?;
            Ok(())
        }
    }

    /// Получить количество сертификатов.
    pub fn count(&self) -> usize {
        self.iter().count()
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Сырой дескриптор хранилища для FFI.
    pub fn raw_handle(&self) -> HCERTSTORE {
        self.handle
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        unsafe {
            CertCloseStore(self.handle, 0);
        }
    }
}

impl fmt::Debug for CertStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertStore(0x{:x})", self.handle as usize)
    }
}

// ---------------------------------------------------------------------------
// CertStoreIter
// ---------------------------------------------------------------------------

/// Итератор по сертификатам в хранилище.
pub struct CertStoreIter<'a> {
    store: &'a CertStore,
    current: PCCERT_CONTEXT,
}

impl<'a> Iterator for CertStoreIter<'a> {
    type Item = Certificate;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let ctx = CertEnumCertificatesInStore(self.store.handle, self.current);
            if ctx.is_null() {
                None
            } else {
                self.current = ctx;
                Some(Certificate::from_raw(ctx))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CertExtension (обёртка над *mut CERT_EXTENSION)
// ---------------------------------------------------------------------------

/// Расширение сертификата.
///
/// Не владеет памятью — указатель принадлежит контексту сертификата.
pub struct CertExtension<'a> {
    _store: &'a CertStore,
    ext: *mut cpcsp_ffi_linux::raw_types::CERT_EXTENSION,
}

impl<'a> CertExtension<'a> {
    /// OID расширения.
    pub fn oid(&self) -> Option<&str> {
        unsafe {
            let ext = &*self.ext;
            if ext.psz_obj_id.is_null() {
                return None;
            }
            std::ffi::CStr::from_ptr(ext.psz_obj_id).to_str().ok()
        }
    }

    /// Является ли расширение критическим.
    pub fn is_critical(&self) -> bool {
        unsafe { (*self.ext).f_critical != 0 }
    }

    /// Сырой указатель на расширение.
    pub fn raw(&self) -> *mut cpcsp_ffi_linux::raw_types::CERT_EXTENSION {
        self.ext
    }
}

use std::ffi::c_void;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_my_store() {
        let store = CertStore::open_system("MY");
        assert!(store.is_ok(), "Failed to open MY store: {:?}", store.err());
        let store = store.unwrap();
        let count = store.count();
        println!("MY store has {} certificates", count);
    }

    #[test]
    fn test_open_root_store() {
        let store = CertStore::open_system("ROOT");
        assert!(store.is_ok());
        let store = store.unwrap();
        println!("ROOT store has {} certificates", store.count());
    }

    #[test]
    fn test_store_debug() {
        let store = CertStore::open_system("MY").unwrap();
        let debug = format!("{:?}", store);
        assert!(debug.starts_with("CertStore(0x"));
    }

    #[test]
    fn test_store_iter() {
        let store = CertStore::open_system("MY").unwrap();
        for cert in store.iter().take(3) {
            println!("  cert: subject={:?}", cert.subject_name());
        }
    }
}
