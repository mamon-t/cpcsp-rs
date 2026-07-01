//! Safe обёртка над `PCCERT_CHAIN_CONTEXT` — цепочка сертификатов (X.509).
//!
//! Модуль предоставляет безопасный API для построения и проверки цепочек
//! сертификатов, включая проверку отозванности.
//!
//! # Пример
//!
//! ```no_run
//! use cpcsp::cert_store::CertStore;
//! use cpcsp::chain::{CertChain, CertChainPolicy};
//!
//! let store = CertStore::open_system("ROOT")?;
//! let cert = store.iter().next().unwrap();
//!
//! // Построение цепочки
//! let chain = CertChain::build(None, &cert, None, None, 0)?;
//! println!("Цепочка: {} элементов", chain.element_count());
//!
//! // Проверка политики
//! let status = chain.verify_policy(CertChainPolicy::Base)?;
//! println!("Политика: {}", status);
//! # Ok::<(), cpcsp::types::error::CpcspError>(())
//! ```
//!
//! Источник: CSP_WinCrypt.h:7926-8850

use std::ptr;
use std::ffi::c_void;

use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::{
    BOOL, DWORD, FILETIME, HCERTCHAINENGINE, HCERTSTORE, LONG, PCCERT_CONTEXT,
    CERT_CHAIN_PARA, PCERT_CHAIN_PARA,
    CERT_CHAIN_POLICY_PARA, PCERT_CHAIN_POLICY_PARA,
    CERT_CHAIN_POLICY_STATUS, PCERT_CHAIN_POLICY_STATUS,
    CERT_REVOCATION_PARA, PCERT_REVOCATION_PARA,
    CERT_REVOCATION_STATUS, PCERT_REVOCATION_STATUS,
};
use cpcsp_ffi_linux::capi20::*;

use crate::types::error::CpcspError;

// ---------------------------------------------------------------------------
// CertChainContext — минимальное repr(C) для доступа к полям opaque-структуры
// ---------------------------------------------------------------------------

/// Минимальная раскладка `CERT_CHAIN_CONTEXT` для доступа к полям.
///
/// Источник: CSP_WinCrypt.h:8170-8182
#[repr(C)]
#[derive(Clone, Debug)]
struct CertChainContext {
    cb_size: DWORD,
    trust_status: DWORD,
    trust_status_error: DWORD,
    c_chain: DWORD,
    _pad: [u8; 4],
    rgp_chain: *mut *mut c_void,
}

/// Тип для указателя на `CERT_CHAIN_CONTEXT`.
type PCertChainContext = *const CertChainContext;

// ---------------------------------------------------------------------------
// CertChainPolicy
// ---------------------------------------------------------------------------

/// Политики проверки цепочки сертификатов.
///
/// Источник: CSP_WinCrypt.h:8228
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertChainPolicy {
    /// Базовая проверка — структура сертификатов.
    Base,
    /// Проверка Authenticode.
    Authenticode,
    /// Проверка SSL/TLS.
    Ssl,
    /// Проверка базовых ограничений (Basic Constraints).
    BasicConstraints,
    /// Проверка NT-авторизации.
    NtAuth,
}

impl CertChainPolicy {
    /// OID политики для `CertVerifyCertificateChainPolicy`.
    fn as_oid(&self) -> &'static std::ffi::CStr {
        use std::ffi::CStr;
        match self {
            Self::Base => unsafe { CStr::from_bytes_with_nul_unchecked(b"1.3.6.1.5.5.7.2.1\0") },
            Self::Authenticode => unsafe { CStr::from_bytes_with_nul_unchecked(b"1.3.6.1.5.5.7.2.2\0") },
            Self::Ssl => unsafe { CStr::from_bytes_with_nul_unchecked(b"1.3.6.1.5.5.7.2.3\0") },
            Self::BasicConstraints => unsafe { CStr::from_bytes_with_nul_unchecked(b"1.3.6.1.5.5.7.2.12\0") },
            Self::NtAuth => unsafe { CStr::from_bytes_with_nul_unchecked(b"1.3.6.1.5.5.7.2.4\0") },
        }
    }
}

// ---------------------------------------------------------------------------
// CertChain
// ---------------------------------------------------------------------------

/// Цепочка сертификатов.
///
/// Владеет `PCCERT_CHAIN_CONTEXT` и автоматически освобождает его при drop.
/// Соответствует вызову `CertGetCertificateChain` / `CertFreeCertificateChain`.
pub struct CertChain {
    ctx: PCCERT_CHAIN_CONTEXT,
}

impl CertChain {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Построить цепочку сертификатов.
    ///
    /// # Параметры
    /// - `engine` — движок цепочек (`None` = движок по умолчанию).
    /// - `cert` — контекст сертификата, для которого строится цепочка.
    /// - `time` — время проверки (`None` = текущее время).
    /// - `additional_store` — дополнительное хранилище (`None` = без дополнительного).
    /// - `flags` — флаги построения (например, `CERT_CHAIN_REVOCATION_CHECK_END_CERT`).
    pub fn build(
        engine: Option<HCERTCHAINENGINE>,
        cert: &crate::certificate::Certificate,
        time: Option<&FILETIME>,
        additional_store: Option<&crate::cert_store::CertStore>,
        flags: DWORD,
    ) -> Result<Self, CpcspError> {
        let mut para: CERT_CHAIN_PARA = unsafe { std::mem::zeroed() };
        para.cb_size = std::mem::size_of::<CERT_CHAIN_PARA>() as DWORD;

        let mut ctx: PCCERT_CHAIN_CONTEXT = ptr::null_mut();

        let result = unsafe {
            CertGetCertificateChain(
                engine.unwrap_or(ptr::null_mut()),
                cert.raw_handle(),
                time.map(|t| t as *const FILETIME as *mut FILETIME)
                    .unwrap_or(ptr::null_mut()),
                additional_store
                    .map(|s| s.raw_handle())
                    .unwrap_or(ptr::null_mut()),
                &mut para as PCERT_CHAIN_PARA,
                flags,
                ptr::null_mut(),
                &mut ctx,
            )
        };

        if result == 0 {
            return Err(CpcspError::last_os_error());
        }

        if ctx.is_null() {
            return Err(CpcspError::from_raw(0x8007000E));
        }

        Ok(Self { ctx })
    }

    /// Построить цепочку с настройками по умолчанию (самый простой вариант).
    pub fn build_default(cert: &crate::certificate::Certificate) -> Result<Self, CpcspError> {
        Self::build(None, cert, None, None, 0)
    }

    /// Построить цепочку с проверкой отозванности.
    pub fn build_with_revocation(
        cert: &crate::certificate::Certificate,
        flags: DWORD,
    ) -> Result<Self, CpcspError> {
        Self::build(None, cert, None, None, flags | CERT_CHAIN_REVOCATION_CHECK_END_CERT)
    }

    // -----------------------------------------------------------------------
    // Policy verification
    // -----------------------------------------------------------------------

    /// Проверить политику цепочки сертификатов.
    pub fn verify_policy(&self, policy: CertChainPolicy) -> Result<CertChainPolicyStatus, CpcspError> {
        let mut para = CERT_CHAIN_POLICY_PARA {
            cb_size: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as DWORD,
            dw_flags: 0,
            pv_extra_policy_para: ptr::null_mut(),
        };
        let mut status = CERT_CHAIN_POLICY_STATUS {
            cb_size: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as DWORD,
            dw_error: 0,
            l_chain_index: 0,
            l_element_index: 0,
            pv_extra_policy_status: ptr::null_mut(),
        };

        let result = unsafe {
            CertVerifyCertificateChainPolicy(
                policy.as_oid().as_ptr(),
                self.ctx,
                &mut para as PCERT_CHAIN_POLICY_PARA,
                &mut status as PCERT_CHAIN_POLICY_STATUS,
            )
        };

        if result == 0 {
            return Err(CpcspError::last_os_error());
        }

        Ok(CertChainPolicyStatus {
            error: status.dw_error,
            chain_index: status.l_chain_index,
            element_index: status.l_element_index,
        })
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Количество элементов в цепочке.
    pub fn element_count(&self) -> u32 {
        let inner = self.ctx as PCertChainContext;
        unsafe { (*inner).c_chain }
    }

    /// Получить сырой дескриптор цепочки.
    pub fn as_raw(&self) -> PCCERT_CHAIN_CONTEXT {
        self.ctx
    }

    /// Дублировать цепочку (увеличен счётчик ссылок).
    pub fn duplicate(&self) -> Self {
        let new_ctx = unsafe { CertDuplicateCertificateChain(self.ctx) };
        Self { ctx: new_ctx }
    }

    /// Получить статус доверия цепочки (TrustStatus из контекста).
    pub fn trust_status(&self) -> DWORD {
        let inner = self.ctx as PCertChainContext;
        unsafe { (*inner).trust_status }
    }

    /// Получить код ошибки доверия (TrustStatusError из контекста).
    pub fn trust_status_error(&self) -> DWORD {
        let inner = self.ctx as PCertChainContext;
        unsafe { (*inner).trust_status_error }
    }
}

impl Drop for CertChain {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe {
                CertFreeCertificateChain(self.ctx);
            }
            self.ctx = ptr::null_mut();
        }
    }
}

impl std::fmt::Debug for CertChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertChain")
            .field("elements", &self.element_count())
            .field("trust_status", &self.trust_status())
            .field("trust_status_error", &self.trust_status_error())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// CertChainPolicyStatus
// ---------------------------------------------------------------------------

/// Результат проверки политики цепочки сертификатов.
#[derive(Debug, Clone)]
pub struct CertChainPolicyStatus {
    /// Код ошибки (0 = OK).
    pub error: DWORD,
    /// Индекс элемента в цепочке, где обнаружена ошибка.
    pub chain_index: LONG,
    /// Индекс элемента в элементе цепочки, где обнаружена ошибка.
    pub element_index: LONG,
}

impl CertChainPolicyStatus {
    /// Проверить, успешна ли проверка.
    pub fn is_ok(&self) -> bool {
        self.error == 0
    }

    /// Код ошибки.
    pub fn error(&self) -> DWORD {
        self.error
    }
}

impl std::fmt::Display for CertChainPolicyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_ok() {
            write!(f, "OK")
        } else {
            write!(
                f,
                "Ошибка 0x{:08X} (цепочка: {}, элемент: {})",
                self.error, self.chain_index, self.element_index
            )
        }
    }
}

// ---------------------------------------------------------------------------
// CertRevocation
// ---------------------------------------------------------------------------

/// Проверка отозванности сертификата.
pub struct CertRevocation;

impl CertRevocation {
    /// Проверить отозванность сертификата.
    ///
    /// # Параметры
    /// - `cert` — контекст сертификата для проверки.
    /// - `issuer_cert` — контекст издателя (`None` = будет найден автоматически).
    /// - `store` — хранилище для поиска CRL/OCSP (`None` = стандартное).
    /// - `flags` — флаги проверки (например, `CERT_VERIFY_REV_SERVER_OCSP`).
    pub fn check(
        cert: &crate::certificate::Certificate,
        issuer_cert: Option<&crate::certificate::Certificate>,
        store: Option<&crate::cert_store::CertStore>,
        flags: DWORD,
    ) -> Result<CertRevocationStatus, CpcspError> {
        let mut para: CERT_REVOCATION_PARA = unsafe { std::mem::zeroed() };
        para.cb_size = std::mem::size_of::<CERT_REVOCATION_PARA>() as DWORD;
        para.p_issuer_cert = issuer_cert
            .map(|c| c.raw_handle())
            .unwrap_or(ptr::null());

        let store_handle = store.map(|s| s.raw_handle());
        if let Some(h) = store_handle {
            para.rg_cert_store = &h as *const HCERTSTORE as *mut HCERTSTORE;
            para.c_cert_store = 1;
            para.h_crl_store = h;
        }

        let mut status: CERT_REVOCATION_STATUS = unsafe { std::mem::zeroed() };
        status.cb_size = std::mem::size_of::<CERT_REVOCATION_STATUS>() as DWORD;

        let cert_ptr = cert.raw_handle() as *const std::ffi::c_void;
        let contexts: [*const std::ffi::c_void; 1] = [cert_ptr];

        let result = unsafe {
            CertVerifyRevocation(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                1, // CERT_CONTEXT_REVOCATION_TYPE
                1,
                contexts.as_ptr(),
                flags,
                &mut para as PCERT_REVOCATION_PARA,
                &mut status as PCERT_REVOCATION_STATUS,
            )
        };

        Ok(CertRevocationStatus {
            error: if result == 0 { status.dw_error } else { 0 },
            index: status.dw_index,
            reason: status.dw_reason,
            has_freshness_time: status.f_has_freshness_time != 0,
            freshness_time: status.dw_freshness_time,
        })
    }

    /// Простая проверка — только с текущими настройками.
    pub fn check_simple(cert: &crate::certificate::Certificate) -> Result<CertRevocationStatus, CpcspError> {
        Self::check(cert, None, None, CERT_VERIFY_REV_SERVER_OCSP)
    }
}

// ---------------------------------------------------------------------------
// CertRevocationStatus
// ---------------------------------------------------------------------------

/// Результат проверки отозванности.
#[derive(Debug, Clone)]
pub struct CertRevocationStatus {
    /// Код ошибки (0 = не отозван).
    pub error: DWORD,
    /// Индекс сертификата в массиве.
    pub index: DWORD,
    /// Причина отмены (CRL reason code).
    pub reason: DWORD,
    /// Есть ли информация о свежести.
    pub has_freshness_time: bool,
    /// Время свежести CRL (секунды).
    pub freshness_time: DWORD,
}

impl CertRevocationStatus {
    /// Сертификат отозван?
    pub fn is_revoked(&self) -> bool {
        self.error != 0
    }

    /// Код ошибки.
    pub fn error(&self) -> DWORD {
        self.error
    }

    /// Причина отмены (CRL reason code).
    pub fn reason(&self) -> DWORD {
        self.reason
    }
}

impl std::fmt::Display for CertRevocationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_revoked() {
            write!(
                f,
                "Отозван (ошибка 0x{:08X}, причина: {})",
                self.error, self.reason
            )
        } else {
            write!(f, "Не отозван")
        }
    }
}
