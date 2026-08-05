//! Safe обёртка над `PCCERT_CONTEXT` — контекст сертификата (X.509).
//!
//! Модуль предоставляет безопасный API для работы с сертификатами:
//! создание из DER, получение имён, проверка времени, сериализация.
//!
//! # Пример
//!
//! ```no_run
//! use cpcsp::cert_store::CertStore;
//!
//! let store = CertStore::open_system("MY")?;
//! for cert in store.iter() {
//!     println!("Субъект: {:?}", cert.subject_name());
//!     println!("Издатель: {:?}", cert.issuer_name());
//!     if let Some(hash) = cert.sha1_hash() {
//!         println!("SHA1: {}", hex::encode(&hash));
//!     }
//! }
//! # Ok::<(), cpcsp::types::error::CpcspError>(())
//! ```
//!
//! Источник: CSP_WinCrypt.h:5239-5254

use std::fmt;
use std::marker::PhantomData;

use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::{DWORD, PCCERT_CONTEXT, HCRYPTPROV, BOOL};
use cpcsp_ffi_linux::capi20::*;

use crate::types::error::{check_bool, CpcspError};

// ---------------------------------------------------------------------------
// Certificate
// ---------------------------------------------------------------------------

/// Контекст сертификата (X.509).
///
/// Владеет указателем `PCCERT_CONTEXT` и автоматически освобождает его при drop.
/// Соответствует вызову `CertCreateCertificateContext` / `CertFreeCertificateContext`.
pub struct Certificate {
    handle: PCCERT_CONTEXT,
}

impl Certificate {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Создать контекст сертификата из DER-блоба.
    pub fn from_der(der: &[u8]) -> Result<Self, CpcspError> {
        unsafe {
            let ctx = CertCreateCertificateContext(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                der.as_ptr(),
                der.len() as DWORD,
            );
            if ctx.is_null() {
                Err(CpcspError::last_os_error())
            } else {
                Ok(Self { handle: ctx })
            }
        }
    }

    /// Создать из сырого указателя (ownership передаётся).
    ///
    /// # Safety
    /// `handle` должен быть валидным `PCCERT_CONTEXT`, полученным из CryptoAPI.
    pub unsafe fn from_raw(handle: PCCERT_CONTEXT) -> Self {
        Self { handle }
    }

    // -----------------------------------------------------------------------
    // Information
    // -----------------------------------------------------------------------

    /// Имя субъекта (Subject Name) в формате строки.
    pub fn subject_name(&self) -> Option<String> {
        unsafe {
            let cert_info = (*self.handle).p_cert_info;
            if cert_info.is_null() {
                return None;
            }
            let name_blob = &(*cert_info).subject;
            let mut buf = vec![0u8; 256];
            let len = CertNameToStrA(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                name_blob as *const _ as *mut _,
                CERT_SIMPLE_NAME_STR,
                buf.as_mut_ptr() as *mut i8,
                buf.len() as DWORD,
            );
            if len == 0 {
                return None;
            }
            buf.truncate((len - 1) as usize);
            String::from_utf8(buf).ok()
        }
    }

    /// Имя издателя (Issuer Name) в формате строки.
    pub fn issuer_name(&self) -> Option<String> {
        unsafe {
            let cert_info = (*self.handle).p_cert_info;
            if cert_info.is_null() {
                return None;
            }
            let name_blob = &(*cert_info).issuer;
            let mut buf = vec![0u8; 256];
            let len = CertNameToStrA(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                name_blob as *const _ as *mut _,
                CERT_SIMPLE_NAME_STR,
                buf.as_mut_ptr() as *mut i8,
                buf.len() as DWORD,
            );
            if len == 0 {
                return None;
            }
            buf.truncate((len - 1) as usize);
            String::from_utf8(buf).ok()
        }
    }

    /// Сериализовать сертификат в DER.
    pub fn to_der(&self) -> Result<Vec<u8>, CpcspError> {
        unsafe {
            let mut len: DWORD = 0;
            check_bool(|| CertSerializeCertificateStoreElement(
                self.handle,
                0,
                std::ptr::null_mut(),
                &mut len,
            ))?;
            let mut buf = vec![0u8; len as usize];
            check_bool(|| CertSerializeCertificateStoreElement(
                self.handle,
                0,
                buf.as_mut_ptr(),
                &mut len,
            ))?;
            buf.truncate(len as usize);
            Ok(buf)
        }
    }

    /// Найти расширение по OID.
    pub fn find_extension(&self, oid: &str) -> Option<*mut cpcsp_ffi_linux::raw_types::CERT_EXTENSION> {
        let oid_cstr = std::ffi::CString::new(oid).ok()?;
        unsafe {
            let cert_info = (*self.handle).p_cert_info;
            if cert_info.is_null() {
                return None;
            }
            let ext_count = (*cert_info).c_extension;
            let extensions = (*cert_info).rg_extension;
            if extensions.is_null() || ext_count == 0 {
                return None;
            }
            let ext = CertFindExtension(
                oid_cstr.as_ptr(),
                ext_count,
                extensions,
            );
            if ext.is_null() {
                None
            } else {
                Some(ext)
            }
        }
    }

    /// Получить свойство сертификата (CERT_SHA1_HASH_PROP_ID, CERT_KEY_PROV_INFO_PROP_ID, ...).
    pub fn get_property(&self, prop_id: DWORD) -> Result<Vec<u8>, CpcspError> {
        unsafe {
            let mut data_len: DWORD = 0;
            check_bool(|| CertGetCertificateContextProperty(
                self.handle,
                prop_id,
                std::ptr::null_mut(),
                &mut data_len,
            ))?;
            if data_len == 0 {
                return Ok(Vec::new());
            }
            let mut data = vec![0u8; data_len as usize];
            check_bool(|| CertGetCertificateContextProperty(
                self.handle,
                prop_id,
                data.as_mut_ptr() as *mut _,
                &mut data_len,
            ))?;
            data.truncate(data_len as usize);
            Ok(data)
        }
    }

    /// Получить SHA1-хеш сертификата.
    pub fn sha1_hash(&self) -> Option<[u8; 20]> {
        let data = self.get_property(CERT_SHA1_HASH_PROP_ID).ok()?;
        if data.len() == 20 {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&data);
            Some(hash)
        } else {
            None
        }
    }

    /// Проверить валидность времени сертификата.
    /// Возвращает 0 если валиден, отрицательное значение если истёк, положительное если ещё не действует.
    pub fn verify_time(&self) -> Result<i32, CpcspError> {
        unsafe {
            let cert_info = (*self.handle).p_cert_info;
            if cert_info.is_null() {
                return Err(CpcspError::from_raw(0x57)); // ERROR_INVALID_PARAMETER
            }
            let result = CertVerifyTimeValidity(
                std::ptr::null_mut(),
                cert_info,
            );
            Ok(result as i32)
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Сырой дескриптор сертификата для FFI.
    pub fn raw_handle(&self) -> PCCERT_CONTEXT {
        self.handle
    }

    /// Получить невладеющую ссылку на этот сертификат.
    ///
    /// Вью живёт не дольше самого сертификата и не освобождает
    /// контекст. Полезно там, где нужен кратковременный доступ без
    /// передачи владения (передача массива ссылок в FFI и т.п.).
    pub fn as_ref(&self) -> CertificateRef<'_> {
        CertificateRef {
            handle: self.handle,
            _marker: PhantomData,
        }
    }

    /// Проверить, есть ли у сертификата связанный приватный ключ
    /// (CryptFindCertificateKeyProvInfo).
    pub fn has_private_key(&self) -> bool {
        unsafe {
            CryptFindCertificateKeyProvInfo(self.handle, 0, std::ptr::null_mut()) != 0
        }
    }

    /// Получить приватный ключ, связанный с сертификатом
    /// (CryptAcquireCertificatePrivateKey).
    pub fn acquire_private_key(&self) -> Result<PrivateKey, CpcspError> {
        unsafe {
            let mut prov: HCRYPTPROV = 0;
            let mut key_spec: DWORD = 0;
            let mut caller_free: BOOL = 0;

            check_bool(|| CryptAcquireCertificatePrivateKey(
                self.handle,
                0,
                std::ptr::null_mut(),
                &mut prov,
                &mut key_spec,
                &mut caller_free,
            ))?;

            let priv_prov = if caller_free != 0 {
                PrivateProv::Owned(prov as usize)
            } else {
                PrivateProv::Borrowed(prov as usize)
            };

            Ok(PrivateKey {
                key_spec,
                prov: priv_prov,
            })
        }
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        unsafe {
            CertFreeCertificateContext(self.handle);
        }
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subject = self.subject_name().unwrap_or_default();
        let issuer = self.issuer_name().unwrap_or_default();
        write!(f, "Certificate(subject={:?}, issuer={:?})", subject, issuer)
    }
}

// ---------------------------------------------------------------------------
// CertificateRef
// ---------------------------------------------------------------------------

/// Невладеющая ссылка на контекст сертификата (X.509).
///
/// В отличие от [`Certificate`], `CertificateRef` **не освобождает**
/// контекст при drop — он лишь заимствует его у владельца и живёт
/// не дольше него (гарантируется lifetime-параметром `'a`).
///
/// Сырой дескриптор (`raw_handle`) у ссылки не публикуется, чтобы
/// исключить случайное двойное освобождение заимствованного контекста.
///
/// Контекст `CERT_CONTEXT` — opaque, refcounted, аллоцированный внутри
/// CryptoPro (как `SID` в Windows): нельзя перемещать его по значению
/// или копировать без `CertDuplicateCertificateContext`. Поэтому единый
/// способ повысить время жизни ссылки — [`CertificateRef::as_owned`].
pub struct CertificateRef<'a> {
    handle: PCCERT_CONTEXT,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CertificateRef<'a> {
    /// Создать из сырого указателя (владение НЕ передаётся).
    ///
    /// # Safety
    /// `handle` должен указывать на валидный контекст, который переживёт
    /// эту ссылку и будет освобождён владельцем.
    pub unsafe fn from_raw(handle: PCCERT_CONTEXT) -> Self {
        Self {
            handle,
            _marker: PhantomData,
        }
    }

    /// Имя субъекта (Subject Name) в формате строки.
    pub fn subject_name(&self) -> Option<String> {
        unsafe {
            let cert_info = (*self.handle).p_cert_info;
            if cert_info.is_null() {
                return None;
            }
            let name_blob = &(*cert_info).subject;
            let mut buf = vec![0u8; 256];
            let len = CertNameToStrA(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                name_blob as *const _ as *mut _,
                CERT_SIMPLE_NAME_STR,
                buf.as_mut_ptr() as *mut i8,
                buf.len() as DWORD,
            );
            if len == 0 {
                return None;
            }
            buf.truncate((len - 1) as usize);
            String::from_utf8(buf).ok()
        }
    }

    /// Имя издателя (Issuer Name) в формате строки.
    pub fn issuer_name(&self) -> Option<String> {
        unsafe {
            let cert_info = (*self.handle).p_cert_info;
            if cert_info.is_null() {
                return None;
            }
            let name_blob = &(*cert_info).issuer;
            let mut buf = vec![0u8; 256];
            let len = CertNameToStrA(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                name_blob as *const _ as *mut _,
                CERT_SIMPLE_NAME_STR,
                buf.as_mut_ptr() as *mut i8,
                buf.len() as DWORD,
            );
            if len == 0 {
                return None;
            }
            buf.truncate((len - 1) as usize);
            String::from_utf8(buf).ok()
        }
    }

    /// Проверить валидность времени сертификата.
    /// Возвращает 0 если валиден, отрицательное значение если истёк, положительное если ещё не действует.
    pub fn verify_time(&self) -> Result<i32, CpcspError> {
        unsafe {
            let cert_info = (*self.handle).p_cert_info;
            if cert_info.is_null() {
                return Err(CpcspError::from_raw(0x57)); // ERROR_INVALID_PARAMETER
            }
            Ok(CertVerifyTimeValidity(std::ptr::null_mut(), cert_info) as i32)
        }
    }

    /// Создать владеющую копию сертификата (через `CertDuplicateCertificateContext`).
    pub fn as_owned(&self) -> Option<Certificate> {
        unsafe {
            let dup = CertDuplicateCertificateContext(self.handle);
            if dup.is_null() {
                None
            } else {
                Some(Certificate::from_raw(dup))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PrivateKey
// ---------------------------------------------------------------------------

/// Приватный ключ сертификата, полученный через
/// [`Certificate::acquire_private_key`].
///
/// Если провайдер был выделен под этот сертификат (`caller_free`), структура
/// владеет им и освобождает через `CryptReleaseContext` при drop. Иначе дескриптор
/// лишь заимствуется и не освобождается.
pub struct PrivateKey {
    key_spec: DWORD,
    prov: PrivateProv,
}

enum PrivateProv {
    /// caller_free == 1 — владеем, освобождаем при drop.
    Owned(usize),
    /// caller_free == 0 — заимствуем, не освобождаем.
    Borrowed(usize),
}

impl Drop for PrivateProv {
    fn drop(&mut self) {
        if let PrivateProv::Owned(h) = self {
            if *h != 0 {
                unsafe {
                    cpcsp_ffi_linux::capi10::CryptReleaseContext(*h, 0);
                }
            }
        }
    }
}

impl PrivateKey {
    /// Key spec: `AT_KEYEXCHANGE` (1) или `AT_SIGNATURE` (2).
    pub fn key_spec(&self) -> DWORD {
        self.key_spec
    }

    /// Сырой дескриптор `HCRYPTPROV`.
    pub fn raw_prov(&self) -> usize {
        match &self.prov {
            PrivateProv::Owned(h) | PrivateProv::Borrowed(h) => *h,
        }
    }

    /// Владеет ли эта структура провайдером (можно ли его освобождать).
    pub fn owns_provider(&self) -> bool {
        matches!(self.prov, PrivateProv::Owned(_))
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("key_spec", &self.key_spec)
            .field("owns_provider", &self.owns_provider())
            .finish()
    }
}

impl fmt::Debug for CertificateRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subject = self.subject_name().unwrap_or_default();
        let issuer = self.issuer_name().unwrap_or_default();
        write!(f, "CertificateRef(subject={:?}, issuer={:?})", subject, issuer)
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CERT_SIMPLE_NAME_STR: DWORD = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_store::CertStore;

    #[test]
    fn test_open_store_and_iter() {
        let store = CertStore::open_system("MY").unwrap();
        let certs: Vec<_> = store.iter().take(5).collect();
        for cert in &certs {
            println!("  Subject: {:?}", cert.subject_name());
            println!("  Issuer:  {:?}", cert.issuer_name());
            if let Some(hash) = cert.sha1_hash() {
                println!("  SHA1: {:02x}{:02x}{:02x}...", hash[0], hash[1], hash[2]);
            }
        }
    }

    #[test]
    fn test_cert_debug() {
        let store = CertStore::open_system("MY").unwrap();
        if let Some(cert) = store.iter().next() {
            let debug = format!("{:?}", cert);
            assert!(debug.starts_with("Certificate("));
        }
    }
}
