//! Safe обёртки для ASN.1 операций — кодирование, декодирование, Base64, хеширование, подпись.
//!
//! Модуль предоставляет безопасный API для работы с ASN.1 структурами:
//! кодирование/декодирование DER, Base64, хеширование сертификатов,
//! подпись и проверка подписи.
//!
//! # Пример
//!
//! ```no_run
//! use cpcsp::asn1::Asn1;
//! use cpcsp_ffi_linux::raw_constants::*;
//!
//! // Base64 кодирование
//! let data = b"Hello, CryptoPro!";
//! let b64 = Asn1::binary_to_base64(data)?;
//! println!("Base64: {}", b64);
//!
//! // Хеширование сертификата
//! # use cpcsp::cert_store::CertStore;
//! # let store = CertStore::open_system("MY")?;
//! # let cert = store.iter().next().unwrap();
//! let hash = Asn1::hash_certificate(&cert, CALG_GOST_34_11_2012_256)?;
//! println!("Хеш: {} байт", hash.len());
//! # Ok::<(), cpcsp::types::error::CpcspError>(())
//! ```
//!
//! Источник: CSP_WinCrypt.h:788-1280

use std::ptr;

use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::{
    BYTE, DWORD, HCRYPTPROV, PCCERT_CONTEXT, CRYPT_ALGORITHM_IDENTIFIER,
};
use cpcsp_ffi_linux::capi20::*;

use crate::types::error::{check_bool, CpcspError};

// ---------------------------------------------------------------------------
// Asn1
// ---------------------------------------------------------------------------

/// ASN.1 операции: кодирование, декодирование, Base64, хеширование, подпись.
pub struct Asn1;

impl Asn1 {
    // -----------------------------------------------------------------------
    // Encode / Decode
    // -----------------------------------------------------------------------

    /// Закодировать ASN.1 структуру в DER.
    ///
    /// # Параметры
    /// - `struct_oid` — OID ASN.1 структуры (например, `szOID_X509_CERT_TO_BE_SIGNED`).
    /// - `struct_info` — указатель на структуру для кодирования.
    ///
    /// # Безопасность
    /// `struct_info` должен указывать на валидную структуру, соответствующую `struct_oid`.
    pub unsafe fn encode(
        struct_oid: &str,
        struct_info: *const std::ffi::c_void,
    ) -> Result<Vec<u8>, CpcspError> {
        let oid_cstr = std::ffi::CString::new(struct_oid)
            .map_err(|_| CpcspError::from_raw(0x57))?;

        let mut size: DWORD = 0;

        // Первый вызов — определить размер
        check_bool(|| {
            CryptEncodeObject(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                oid_cstr.as_ptr(),
                struct_info,
                ptr::null_mut(),
                &mut size,
            )
        })?;

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];

        check_bool(|| {
            CryptEncodeObject(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                oid_cstr.as_ptr(),
                struct_info,
                buf.as_mut_ptr(),
                &mut size,
            )
        })?;

        buf.truncate(size as usize);
        Ok(buf)
    }

    /// Декодировать DER в ASN.1 структуру.
    ///
    /// # Параметры
    /// - `struct_oid` — OID ASN.1 структуры.
    /// - `encoded` — DER-данные.
    /// - `struct_info` — указатель на структуру для заполнения.
    /// - `struct_size` — размер структуры в байтах.
    ///
    /// # Безопасность
    /// `struct_info` должен быть валидным указателем на структуру нужного размера.
    pub unsafe fn decode(
        struct_oid: &str,
        encoded: &[u8],
        struct_info: *mut std::ffi::c_void,
        struct_size: DWORD,
    ) -> Result<(), CpcspError> {
        let oid_cstr = std::ffi::CString::new(struct_oid)
            .map_err(|_| CpcspError::from_raw(0x57))?;

        let mut actual_size: DWORD = struct_size;

        check_bool(|| {
            CryptDecodeObject(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                oid_cstr.as_ptr(),
                encoded.as_ptr(),
                encoded.len() as DWORD,
                0,
                struct_info,
                &mut actual_size,
            )
        })?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Base64 / Hex encoding
    // -----------------------------------------------------------------------

    /// Кодировать двоичные данные в Base64 строку.
    pub fn binary_to_base64(data: &[u8]) -> Result<String, CpcspError> {
        let mut size: DWORD = 0;

        unsafe {
            check_bool(|| {
                CryptBinaryToStringA(
                    data.as_ptr(),
                    data.len() as DWORD,
                    CRYPT_STRING_BASE64,
                    ptr::null_mut(),
                    &mut size,
                )
            })?;
        }

        if size == 0 {
            return Ok(String::new());
        }

        let mut buf = vec![0u8; size as usize];

        unsafe {
            check_bool(|| {
                CryptBinaryToStringA(
                    data.as_ptr(),
                    data.len() as DWORD,
                    CRYPT_STRING_BASE64,
                    buf.as_mut_ptr() as *mut i8,
                    &mut size,
                )
            })?;
        }

        // Убрать завершающий нуль
        if size > 0 && buf[(size - 1) as usize] == 0 {
            buf.truncate((size - 1) as usize);
        }

        String::from_utf8(buf).map_err(|_| CpcspError::from_raw(0x57))
    }

    /// Кодировать двоичные данные в Base64 строку с заголовком PEM.
    pub fn binary_to_base64_header(data: &[u8]) -> Result<String, CpcspError> {
        let mut size: DWORD = 0;

        unsafe {
            check_bool(|| {
                CryptBinaryToStringA(
                    data.as_ptr(),
                    data.len() as DWORD,
                    CRYPT_STRING_BASE64HEADER,
                    ptr::null_mut(),
                    &mut size,
                )
            })?;
        }

        if size == 0 {
            return Ok(String::new());
        }

        let mut buf = vec![0u8; size as usize];

        unsafe {
            check_bool(|| {
                CryptBinaryToStringA(
                    data.as_ptr(),
                    data.len() as DWORD,
                    CRYPT_STRING_BASE64HEADER,
                    buf.as_mut_ptr() as *mut i8,
                    &mut size,
                )
            })?;
        }

        if size > 0 && buf[(size - 1) as usize] == 0 {
            buf.truncate((size - 1) as usize);
        }

        String::from_utf8(buf).map_err(|_| CpcspError::from_raw(0x57))
    }

    /// Кодировать двоичные данные в Hex строку.
    pub fn binary_to_hex(data: &[u8]) -> Result<String, CpcspError> {
        let mut size: DWORD = 0;

        unsafe {
            check_bool(|| {
                CryptBinaryToStringA(
                    data.as_ptr(),
                    data.len() as DWORD,
                    CRYPT_STRING_HEX,
                    ptr::null_mut(),
                    &mut size,
                )
            })?;
        }

        if size == 0 {
            return Ok(String::new());
        }

        let mut buf = vec![0u8; size as usize];

        unsafe {
            check_bool(|| {
                CryptBinaryToStringA(
                    data.as_ptr(),
                    data.len() as DWORD,
                    CRYPT_STRING_HEX,
                    buf.as_mut_ptr() as *mut i8,
                    &mut size,
                )
            })?;
        }

        if size > 0 && buf[(size - 1) as usize] == 0 {
            buf.truncate((size - 1) as usize);
        }

        String::from_utf8(buf).map_err(|_| CpcspError::from_raw(0x57))
    }

    /// Декодировать Base64 строку в двоичные данные.
    pub fn base64_to_binary(base64: &str) -> Result<Vec<u8>, CpcspError> {
        let cstr = std::ffi::CString::new(base64)
            .map_err(|_| CpcspError::from_raw(0x57))?;

        let mut size: DWORD = 0;

        unsafe {
            check_bool(|| {
                CryptStringToBinaryA(
                    cstr.as_ptr(),
                    0, // auto-length
                    CRYPT_STRING_BASE64,
                    ptr::null_mut(),
                    &mut size,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            })?;
        }

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];

        unsafe {
            check_bool(|| {
                CryptStringToBinaryA(
                    cstr.as_ptr(),
                    0,
                    CRYPT_STRING_BASE64,
                    buf.as_mut_ptr(),
                    &mut size,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            })?;
        }

        buf.truncate(size as usize);
        Ok(buf)
    }

    /// Декодировать Hex строку в двоичные данные.
    pub fn hex_to_binary(hex: &str) -> Result<Vec<u8>, CpcspError> {
        let cstr = std::ffi::CString::new(hex)
            .map_err(|_| CpcspError::from_raw(0x57))?;

        let mut size: DWORD = 0;

        unsafe {
            check_bool(|| {
                CryptStringToBinaryA(
                    cstr.as_ptr(),
                    0,
                    CRYPT_STRING_HEX,
                    ptr::null_mut(),
                    &mut size,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            })?;
        }

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];

        unsafe {
            check_bool(|| {
                CryptStringToBinaryA(
                    cstr.as_ptr(),
                    0,
                    CRYPT_STRING_HEX,
                    buf.as_mut_ptr(),
                    &mut size,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            })?;
        }

        buf.truncate(size as usize);
        Ok(buf)
    }

    // -----------------------------------------------------------------------
    // Hash
    // -----------------------------------------------------------------------

    /// Хешировать To-Be-Signed данные (TBS часть сертификата/CRL).
    ///
    /// # Параметры
    /// - `prov` — дескриптор провайдера.
    /// - `encoding` — тип кодирования (通常 `X509_ASN_ENCODING | PKCS_7_ASN_ENCODING`).
    /// - `encoded` — DER-данные (TBS часть).
    /// - `alg_id` — ALG_ID алгоритма хеширования.
    pub fn hash_to_be_signed(
        prov: HCRYPTPROV,
        encoded: &[u8],
        alg_id: DWORD,
    ) -> Result<Vec<u8>, CpcspError> {
        let mut size: DWORD = 0;

        unsafe {
            check_bool(|| {
                CryptHashToBeSigned(
                    prov,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    encoded.as_ptr(),
                    encoded.len() as DWORD,
                    ptr::null_mut(),
                    &mut size,
                )
            })?;
        }

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];

        unsafe {
            check_bool(|| {
                CryptHashToBeSigned(
                    prov,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    encoded.as_ptr(),
                    encoded.len() as DWORD,
                    buf.as_mut_ptr(),
                    &mut size,
                )
            })?;
        }

        buf.truncate(size as usize);
        Ok(buf)
    }

    /// Хешировать сертификат.
    ///
    /// # Параметры
    /// - `cert` — контекст сертификата.
    /// - `alg_id` — ALG_ID алгоритма хеширования (например, `CALG_GOST_34_11_2012_256`).
    pub fn hash_certificate(
        cert: &crate::certificate::Certificate,
        alg_id: DWORD,
    ) -> Result<Vec<u8>, CpcspError> {
        let der = cert.to_der()?;
        let mut size: DWORD = 0;

        unsafe {
            check_bool(|| {
                CryptHashCertificate(
                    0 as HCRYPTPROV,
                    alg_id,
                    0,
                    der.as_ptr(),
                    der.len() as DWORD,
                    ptr::null_mut(),
                    &mut size,
                )
            })?;
        }

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];

        unsafe {
            check_bool(|| {
                CryptHashCertificate(
                    0 as HCRYPTPROV,
                    alg_id,
                    0,
                    der.as_ptr(),
                    der.len() as DWORD,
                    buf.as_mut_ptr(),
                    &mut size,
                )
            })?;
        }

        buf.truncate(size as usize);
        Ok(buf)
    }

    // -----------------------------------------------------------------------
    // Sign & Encode
    // -----------------------------------------------------------------------

    /// Подписать и закодировать ASN.1 структуру (TBS → DER + подпись).
    ///
    /// # Параметры
    /// - `prov` — дескриптор провайдера.
    /// - `key_spec` — спецификатор ключа (например, `AT_KEYEXCHANGE`).
    /// - `struct_oid` — OID ASN.1 структуры.
    /// - `struct_info` — указатель на TBS-структуру.
    /// - `signature_alg` — алгоритм подписи.
    pub unsafe fn sign_and_encode(
        prov: HCRYPTPROV,
        key_spec: DWORD,
        struct_oid: &str,
        struct_info: *const std::ffi::c_void,
        signature_alg: &CRYPT_ALGORITHM_IDENTIFIER,
    ) -> Result<Vec<u8>, CpcspError> {
        let oid_cstr = std::ffi::CString::new(struct_oid)
            .map_err(|_| CpcspError::from_raw(0x57))?;

        let mut size: DWORD = 0;

        check_bool(|| {
            CryptSignAndEncodeCertificate(
                prov,
                key_spec,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                oid_cstr.as_ptr(),
                struct_info,
                signature_alg,
                ptr::null(),
                ptr::null_mut(),
                &mut size,
            )
        })?;

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];

        check_bool(|| {
            CryptSignAndEncodeCertificate(
                prov,
                key_spec,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                oid_cstr.as_ptr(),
                struct_info,
                signature_alg,
                ptr::null(),
                buf.as_mut_ptr(),
                &mut size,
            )
        })?;

        buf.truncate(size as usize);
        Ok(buf)
    }

    // -----------------------------------------------------------------------
    // Verify Signature
    // -----------------------------------------------------------------------

    /// Проверить подпись сертификата.
    ///
    /// # Параметры
    /// - `cert` — сертификат для проверки.
    /// - `issuer_cert` — сертификат издателя.
    pub fn verify_certificate_signature(
        cert: &crate::certificate::Certificate,
        issuer_cert: &crate::certificate::Certificate,
    ) -> Result<(), CpcspError> {
        let cert_der = cert.to_der()?;

        unsafe {
            check_bool(|| {
                CryptVerifyCertificateSignatureEx(
                    0 as HCRYPTPROV,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
                    cert.raw_handle() as *mut std::ffi::c_void,
                    CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
                    issuer_cert.raw_handle() as *mut std::ffi::c_void,
                    0,
                    ptr::null_mut(),
                )
            })?;
        }

        Ok(())
    }

    /// Проверить подпись сертификата (упрощённый — через открытое ключевое Info).
    ///
    /// # Параметры
    /// - `prov` — дескриптор провайдера.
    /// - `encoded` — DER-данные сертификата.
    /// - `public_key_info` — публичный ключ издателя.
    pub unsafe fn verify_signature_with_key(
        prov: HCRYPTPROV,
        encoded: &[u8],
        public_key_info: &cpcsp_ffi_linux::raw_types::CERT_PUBLIC_KEY_INFO,
    ) -> Result<(), CpcspError> {
        check_bool(|| {
            CryptVerifyCertificateSignature(
                prov,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                encoded.as_ptr(),
                encoded.len() as DWORD,
                public_key_info,
            )
        })?;

        Ok(())
    }
}
