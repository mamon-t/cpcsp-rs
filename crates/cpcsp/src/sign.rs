//! Подпись и проверка CMS-сообщений (CryptSignMessage).
//!
//! Модуль предоставляет безопасный API для создания и проверки
//! электронных подписей в формате CMS (Cryptographic Message Syntax).
//!
//! # Форматы подписи
//!
//! - **Встроенная** (attached) — данные включены в подписанное сообщение
//! - **Отсоединённая** (detached) — подпись отдельно от данных
//!
//! # Пример
//!
//! ```no_run
//! use cpcsp::cert_store::CertStore;
//! use cpcsp::sign::{Signer, sign_message, verify_signature};
//! use cpcsp_ffi_linux::raw_constants::*;
//!
//! let store = CertStore::open_system("MY")?;
//! let cert = store.iter().next().expect("Нет сертификатов");
//!
//! // Подписать
//! let signer = Signer::new(&cert, AT_KEYEXCHANGE, szOID_GOST_R3411_2012_256);
//! let signed = sign_message(&[signer], b"Hello", false)?;
//!
//! // Проверить
//! let result = verify_signature(&signed)?;
//! assert_eq!(result.content, b"Hello");
//! # Ok::<(), cpcsp::types::error::CpcspError>(())
//! ```
//!
//! Источник: CSP_WinCrypt.h:12383

use std::ptr;

use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::{DWORD, PCCERT_CONTEXT, CRYPT_SIGN_MESSAGE_PARA, CRYPT_VERIFY_MESSAGE_PARA};
use cpcsp_ffi_linux::capi20::*;

use crate::certificate::Certificate;
use crate::types::error::{check_bool, CpcspError};

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

/// Информация о подписанте для CMS-сообщения.
pub struct Signer<'a> {
    cert: &'a Certificate,
    #[allow(dead_code)]
    key_spec: DWORD,
    hash_oid: &'a str,
}

impl<'a> Signer<'a> {
    /// Создать подписанта.
    ///
    /// # Аргументы
    /// * `cert` — сертификат подписанта
    /// * `key_spec` — AT_KEYEXCHANGE (1) или AT_SIGNATURE (2)
    /// * `hash_oid` — OID алгоритма хеширования (szOID_GOST_R3411_2012_256, ...)
    pub fn new(cert: &'a Certificate, key_spec: DWORD, hash_oid: &'a str) -> Self {
        Self { cert, key_spec, hash_oid }
    }
}

// ---------------------------------------------------------------------------
// sign_message
// ---------------------------------------------------------------------------

/// Подписать сообщение (CMS SignedData).
///
/// Возвращает DER-кодированное подписанный сообщение.
///
/// # Аргументы
/// * `signers` — список подписантов (минимум 1)
/// * `data` — данные для подписи
/// * `detached` — отсоединённая подпись
pub fn sign_message(
    signers: &[Signer<'_>],
    data: &[u8],
    detached: bool,
) -> Result<Vec<u8>, CpcspError> {
    if signers.is_empty() {
        return Err(CpcspError::from_raw(0x57)); // ERROR_INVALID_PARAMETER
    }

    // Создаём CRYPT_SIGN_MESSAGE_PARA
    let sign_para = build_sign_para(signers)?;

    let data_ptr = data.as_ptr();
    let data_len = data.len() as DWORD;
    let _flags = if detached { CMSG_DETACHED_FLAG } else { 0 };

    unsafe {
        // Первый вызов — определить размер
        let mut signed_len: DWORD = 0;
        check_bool(|| CryptSignMessage(
            &sign_para as *const _ as *const _,
            if detached { 1 } else { 0 },
            1,
            &data_ptr as *const _,
            &data_len as *const _,
            ptr::null_mut(),
            &mut signed_len,
        ))?;

        if signed_len == 0 {
            return Ok(Vec::new());
        }

        // Второй вызов — подписать
        let mut signed_blob = vec![0u8; signed_len as usize];
        check_bool(|| CryptSignMessage(
            &sign_para as *const _ as *const _,
            if detached { 1 } else { 0 },
            1,
            &data_ptr as *const _,
            &data_len as *const _,
            signed_blob.as_mut_ptr(),
            &mut signed_len,
        ))?;

        signed_blob.truncate(signed_len as usize);
        Ok(signed_blob)
    }
}

// ---------------------------------------------------------------------------
// verify_signature
// ---------------------------------------------------------------------------

/// Проверить подпись CMS-сообщения.
///
/// Возвращает подписанные данные (decoded content).
pub fn verify_signature(
    signed_blob: &[u8],
) -> Result<VerifyResult, CpcspError> {
    let verify_para = build_verify_para()?;

    unsafe {
        // Первый вызов — определить размер decoded
        let mut decoded_len: DWORD = 0;
        check_bool(|| CryptVerifyMessageSignature(
            &verify_para as *const _ as *const _,
            0, // dw_signer_index
            signed_blob.as_ptr(),
            signed_blob.len() as DWORD,
            ptr::null_mut(),
            &mut decoded_len,
            ptr::null_mut(),
        ))?;

        let mut decoded = vec![0u8; decoded_len as usize];
        let mut signer_cert: PCCERT_CONTEXT = ptr::null();

        check_bool(|| CryptVerifyMessageSignature(
            &verify_para as *const _ as *const _,
            0,
            signed_blob.as_ptr(),
            signed_blob.len() as DWORD,
            decoded.as_mut_ptr(),
            &mut decoded_len,
            &mut signer_cert,
        ))?;

        decoded.truncate(decoded_len as usize);

        let signer = if signer_cert.is_null() {
            None
        } else {
            Some(Certificate::from_raw(signer_cert))
        };

        Ok(VerifyResult {
            content: decoded,
            signer_cert: signer,
        })
    }
}

// ---------------------------------------------------------------------------
// VerifyResult
// ---------------------------------------------------------------------------

/// Результат проверки подписи.
pub struct VerifyResult {
    /// Подписанные данные.
    pub content: Vec<u8>,
    /// Сертификат подписанта (если найден).
    pub signer_cert: Option<Certificate>,
}

// ---------------------------------------------------------------------------
// Helper builders
// ---------------------------------------------------------------------------

fn build_sign_para(signers: &[Signer<'_>]) -> Result<CRYPT_SIGN_MESSAGE_PARA, CpcspError> {
    if signers.is_empty() {
        return Err(CpcspError::from_raw(0x57));
    }

    let signer = &signers[0]; // пока только 1 подписант

    let hash_oid_cstr = std::ffi::CString::new(signer.hash_oid)
        .map_err(|_| CpcspError::from_raw(0x57))?;

    let para = CRYPT_SIGN_MESSAGE_PARA {
        cb_size: std::mem::size_of::<CRYPT_SIGN_MESSAGE_PARA>() as DWORD,
        dw_msg_encoding_type: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        p_signing_cert: signer.cert.raw_handle(),
        hash_algorithm: cpcsp_ffi_linux::raw_types::CRYPT_ALGORITHM_IDENTIFIER {
            psz_obj_id: hash_oid_cstr.as_ptr() as *mut _,
            parameters: cpcsp_ffi_linux::raw_types::CRYPT_ATTR_BLOB {
                cb_data: 0,
                pb_data: ptr::null_mut(),
            },
        },
        pv_hash_aux_info: ptr::null_mut(),
        c_msg_cert: 0,
        _pad0: [0; 4],
        rgp_msg_cert: ptr::null_mut(),
        c_msg_crl: 0,
        _pad1: [0; 4],
        rgp_msg_crl: ptr::null_mut(),
        c_auth_attr: 0,
        _pad2: [0; 4],
        rg_auth_attr: ptr::null_mut(),
        c_unauth_attr: 0,
        _pad3: [0; 4],
        rg_unauth_attr: ptr::null_mut(),
        dw_flags: 0,
        dw_inner_content_type: 0,
    };

    Ok(para)
}

fn build_verify_para() -> Result<CRYPT_VERIFY_MESSAGE_PARA, CpcspError> {
    Ok(CRYPT_VERIFY_MESSAGE_PARA {
        cb_size: std::mem::size_of::<CRYPT_VERIFY_MESSAGE_PARA>() as DWORD,
        dw_msg_and_cert_encoding_type: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        h_crypt_prov: 0,
        pfn_get_signer_certificate: std::ptr::null_mut(),
        pv_get_arg: ptr::null_mut(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_store::CertStore;
    use crate::key::Key;
    use crate::provider::Provider;
    use cpcsp_ffi_linux::raw_constants::*;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        // Получить сертификат из MY хранилища
        let store = match CertStore::open_system("MY") {
            Ok(s) => s,
            Err(_) => {
                println!("Skipping sign test: MY store not available");
                return;
            }
        };

        let cert = match store.iter().next() {
            Some(c) => c,
            None => {
                println!("Skipping sign test: no certs in MY store");
                return;
            }
        };

        // Создать подписанта
        let signer = Signer::new(&cert, AT_KEYEXCHANGE, szOID_GOST_R3411_2012_256);

        // Подписать
        let data = b"Hello, CryptoPro!";
        let signed = sign_message(&[signer], data, false).unwrap();
        assert!(!signed.is_empty());
        println!("Signed message: {} bytes", signed.len());

        // Проверить подпись
        let result = verify_signature(&signed).unwrap();
        assert_eq!(result.content, data);
        println!("Verified! Content matches.");
        if let Some(signer_cert) = &result.signer_cert {
            println!("Signer: {:?}", signer_cert.subject_name());
        }
    }

    #[test]
    fn test_sign_detached() {
        let store = match CertStore::open_system("MY") {
            Ok(s) => s,
            Err(_) => return,
        };

        let cert = match store.iter().next() {
            Some(c) => c,
            None => return,
        };

        let signer = Signer::new(&cert, AT_KEYEXCHANGE, szOID_GOST_R3411_2012_256);
        let data = b"Detached signature test";
        let signed = sign_message(&[signer], data, true).unwrap();
        assert!(!signed.is_empty());
        println!("Detached signature: {} bytes", signed.len());
    }
}
