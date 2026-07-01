//! Safe обёртки для CryptoPro-specific PKI функций.
//!
//! Модуль предоставляет безопасный API для работы с проприетарными
//! расширениями КриптоПро CSP: установка сертификатов, управление
//! PIN-callback, OID-информация.
//!
//! # Пример
//!
//! ```no_run
//! use cpcsp::pki::Pki;
//! use cpcsp_ffi_linux::raw_constants::*;
//!
//! // Получить информацию о хеше по умолчанию для ключа ГОСТ
//! let hash_info = Pki::get_default_hash_oid_info("1.2.643.7.1.1.1.1")?;
//! println!("ALG_ID хеша по умолчанию: 0x{:04X}", hash_info.alg_id);
//!
//! // Получить ALG_ID хеша провайдера
//! # use cpcsp::provider::Provider;
//! # let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
//! let alg_id = Pki::get_provider_hash_alg_id(prov.raw_handle(), "1.2.643.7.1.1.1.1")?;
//! println!("ALG_ID: 0x{:04X}", alg_id);
//! # Ok::<(), cpcsp::types::error::CpcspError>(())
//! ```
//!
//! Источник: capilite/CPCrypt.h, capilite/StoreUtil.h

use std::ffi::{CStr, CString};
use std::ptr;

use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::{
    ALG_ID, BOOL, BYTE, DWORD, HCRYPTPROV, PCCRYPT_OID_INFO, CRYPT_OID_INFO, CRYPT_PIN_CALLBACK,
    TRUE, FALSE,
};
use cpcsp_ffi_linux::capi20::*;

use crate::types::error::CpcspError;

// ---------------------------------------------------------------------------
// OidInfo
// ---------------------------------------------------------------------------

/// Информация об OID (обёртка над `CRYPT_OID_INFO`).
#[derive(Debug, Clone)]
pub struct OidInfo {
    /// OID алгоритма.
    pub oid: String,
    /// Имя алгоритма (Unicode).
    pub name: String,
    /// Идентификатор группы.
    pub group_id: DWORD,
    /// ALG_ID алгоритма.
    pub alg_id: ALG_ID,
}

impl OidInfo {
    /// Создать из raw-указателя (копирование данных).
    ///
    /// # Safety
    /// `ptr` должен указывать на валидную `CRYPT_OID_INFO`.
    unsafe fn from_raw_ptr(ptr: PCCRYPT_OID_INFO) -> Option<Self> {
        if ptr.is_null() {
            return None;
        }

        let info = &*ptr;

        let oid = if info.psz_oid.is_null() {
            String::new()
        } else {
            CStr::from_ptr(info.psz_oid)
                .to_string_lossy()
                .into_owned()
        };

        let name = if info.pwsz_name.is_null() {
            String::new()
        } else {
            // u16 string to String
            let mut len = 0;
            while *info.pwsz_name.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(info.pwsz_name, len);
            String::from_utf16_lossy(slice)
        };

        Some(Self {
            oid,
            name,
            group_id: info.dw_group_id,
            alg_id: info.alg_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Pki
// ---------------------------------------------------------------------------

/// CryptoPro-specific PKI операции.
pub struct Pki;

impl Pki {
    // -----------------------------------------------------------------------
    // Certificate installation
    // -----------------------------------------------------------------------

    /// Установить сертификат в хранилище (CryptoPro extension).
    ///
    /// # Параметры
    /// - `prov` — дескриптор провайдера.
    /// - `key_spec` — спецификатор ключа (например, `AT_KEYEXCHANGE`).
    /// - `certificate` — DER-данные сертификата.
    /// - `store_name` — имя хранилища (например, "MY", "ROOT", "CA").
    /// - `store_flags` — флаги хранилища.
    /// - `install_to_container` — установить в контейнер.
    pub fn install_certificate(
        prov: HCRYPTPROV,
        key_spec: DWORD,
        certificate: &[u8],
        store_name: &str,
        store_flags: DWORD,
        install_to_container: bool,
    ) -> Result<DWORD, CpcspError> {
        let store_name_utf16: Vec<u16> = store_name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut status: DWORD = 0;

        let result = unsafe {
            CPCryptInstallCertificate(
                prov,
                key_spec,
                certificate.as_ptr(),
                certificate.len() as DWORD,
                store_name_utf16.as_ptr(),
                store_flags,
                if install_to_container { TRUE } else { FALSE },
                &mut status,
            )
        };

        if result == 0 {
            return Err(CpcspError::last_os_error());
        }

        Ok(status)
    }

    // -----------------------------------------------------------------------
    // PIN callbacks
    // -----------------------------------------------------------------------

    /// Установить callback для PIN-кода.
    ///
    /// # Параметры
    /// - `callback` — функция обратного вызова для получения PIN.
    /// - `arg` — пользовательский аргумент, передаваемый в callback.
    ///
    /// # Безопасность
    /// `callback` должен быть валидной функцией C ABI.
    /// `arg` должен быть валидным указателем или null.
    pub unsafe fn set_pin_callback(
        callback: CRYPT_PIN_CALLBACK,
        arg: *mut std::ffi::c_void,
    ) {
        CPCryptSetPinCallback(callback, arg);
    }

    /// Получить текущий callback для PIN-кода.
    ///
    /// # Возвращает
    /// Кортеж (callback, arg) или None, если callback не установлен.
    pub fn get_pin_callback() -> Option<(CRYPT_PIN_CALLBACK, *mut std::ffi::c_void)> {
        let mut func: std::mem::MaybeUninit<CRYPT_PIN_CALLBACK> = std::mem::MaybeUninit::uninit();
        let mut arg: *mut std::ffi::c_void = ptr::null_mut();

        unsafe {
            CPCryptGetPinCallback(func.as_mut_ptr(), &mut arg);
            let func = func.assume_init();
            let func_ptr = func as usize;
            if func_ptr == 0 {
                None
            } else {
                Some((func, arg))
            }
        }
    }

    /// Получить PIN через текущий callback.
    ///
    /// # Параметры
    /// - `buffer` — буфер для PIN-кода.
    ///
    /// # Возвращает
    /// PIN-код как строку или ошибку.
    pub fn get_pin_from_callback(buffer: &mut [u8]) -> Result<String, CpcspError> {
        let result = unsafe {
            CPCryptGetPinFromCallback(buffer.as_mut_ptr() as *mut i8, buffer.len())
        };

        if result == 0 {
            return Err(CpcspError::last_os_error());
        }

        // Найти длину строки (до нуль-терминатора)
        let len = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        String::from_utf8(buffer[..len].to_vec())
            .map_err(|_| CpcspError::from_raw(0x57))
    }

    // -----------------------------------------------------------------------
    // OID information
    // -----------------------------------------------------------------------

    /// Получить информацию о хеше по умолчанию для публичного ключа.
    ///
    /// # Параметры
    /// - `pub_key_oid` — OID публичного ключа (например, "1.2.643.7.1.1.1.1").
    pub fn get_default_hash_oid_info(pub_key_oid: &str) -> Result<OidInfo, CpcspError> {
        let cstr = CString::new(pub_key_oid).map_err(|_| CpcspError::from_raw(0x57))?;

        let result = unsafe { CPCryptGetDefaultHashOIDInfo(cstr.as_ptr()) };

        unsafe { OidInfo::from_raw_ptr(result) }
            .ok_or_else(|| CpcspError::from_raw(0x80070002))
    }

    /// Получить ALG_ID хеша провайдера.
    ///
    /// # Параметры
    /// - `prov` — дескриптор провайдера.
    /// - `pub_key_oid` — OID публичного ключа.
    pub fn get_provider_hash_alg_id(
        prov: HCRYPTPROV,
        pub_key_oid: &str,
    ) -> Result<ALG_ID, CpcspError> {
        let cstr = CString::new(pub_key_oid).map_err(|_| CpcspError::from_raw(0x57))?;

        let alg_id = unsafe { CPCryptGetProviderHashAlgId(prov, cstr.as_ptr()) };

        if alg_id == 0 {
            return Err(CpcspError::last_os_error());
        }

        Ok(alg_id)
    }

    /// Получить ALG_ID хеша ГОСТ по умолчанию.
    ///
    /// # Параметры
    /// - `pub_key_oid` — OID публичного ключа (например, "1.2.643.7.1.1.1.1").
    pub fn get_default_gost_hash_alg_id(pub_key_oid: &str) -> Result<ALG_ID, CpcspError> {
        let cstr = CString::new(pub_key_oid).map_err(|_| CpcspError::from_raw(0x57))?;

        let alg_id = unsafe { CPGetDefaultGostHashAlgId(cstr.as_ptr()) };

        if alg_id == 0 {
            return Err(CpcspError::from_raw(0x80070002));
        }

        Ok(alg_id)
    }

    /// Получить информацию о подписи по умолчанию.
    ///
    /// # Параметры
    /// - `pub_key_oid` — OID публичного ключа.
    pub fn get_default_signature_oid_info(pub_key_oid: &str) -> Result<OidInfo, CpcspError> {
        let cstr = CString::new(pub_key_oid).map_err(|_| CpcspError::from_raw(0x57))?;

        let result = unsafe { CPCryptGetDefaultSignatureOIDInfo(cstr.as_ptr()) };

        unsafe { OidInfo::from_raw_ptr(result) }
            .ok_or_else(|| CpcspError::from_raw(0x80070002))
    }

    /// Получить информацию о подписи.
    ///
    /// # Параметры
    /// - `pub_key_oid` — OID публичного ключа.
    /// - `hash_oid` — OID хеша.
    pub fn get_signature_oid_info(
        pub_key_oid: &str,
        hash_oid: &str,
    ) -> Result<OidInfo, CpcspError> {
        let pk_oid = CString::new(pub_key_oid).map_err(|_| CpcspError::from_raw(0x57))?;
        let h_oid = CString::new(hash_oid).map_err(|_| CpcspError::from_raw(0x57))?;

        let result = unsafe { CPCryptGetSignatureOIDInfo(pk_oid.as_ptr(), h_oid.as_ptr()) };

        unsafe { OidInfo::from_raw_ptr(result) }
            .ok_or_else(|| CpcspError::from_raw(0x80070002))
    }

    /// Получить информацию о публичном ключе.
    ///
    /// # Параметры
    /// - `pub_key_oid` — OID публичного ключа.
    /// - `key_spec` — спецификатор ключа.
    pub fn get_public_key_oid_info(
        pub_key_oid: &str,
        key_spec: DWORD,
    ) -> Result<OidInfo, CpcspError> {
        let cstr = CString::new(pub_key_oid).map_err(|_| CpcspError::from_raw(0x57))?;

        let result = unsafe { CPCryptGetPublicKeyOIDInfo(cstr.as_ptr(), key_spec) };

        unsafe { OidInfo::from_raw_ptr(result) }
            .ok_or_else(|| CpcspError::from_raw(0x80070002))
    }

    // -----------------------------------------------------------------------
    // SendPKIRequest (undocumented)
    // -----------------------------------------------------------------------

    /// Отправить PKI-запрос (undocumented function).
    ///
    /// **ВНИМАНИЕ:** Функция не задокументирована. Сигнатура является
    /// предположительной и требует проверки.
    ///
    /// # Возвращает
    /// Код результата.
    pub fn send_pki_request() -> DWORD {
        unsafe { SendPKIRequest() }
    }
}
