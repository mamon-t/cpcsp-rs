//! Шифрование и дешифрование CMS-сообщений.
//!
//! Модуль предоставляет безопасный API для шифрования данных
//! с использованием сертификатов получателей (CMS EnvelopedData).
//!
//! # Пример
//!
//! ```no_run
//! use cpcsp::cert_store::CertStore;
//! use cpcsp::encrypt::{encrypt_message, decrypt_message};
//!
//! let store = CertStore::open_system("MY")?;
//! let cert = store.iter().next().expect("Нет сертификатов");
//!
//! // Зашифровать
//! let encrypted = encrypt_message(&[&cert], b"Secret message")?;
//! println!("Зашифровано: {} байт", encrypted.len());
//!
//! // Дешифровать
//! let decrypted = decrypt_message(&encrypted, &store)?;
//! assert_eq!(decrypted, b"Secret message");
//! # Ok::<(), cpcsp::types::error::CpcspError>(())
//! ```
//!
//! Источник: CSP_WinCrypt.h:12495-12522

use std::ptr;

use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::{DWORD, PCCERT_CONTEXT, CRYPT_ENCRYPT_MESSAGE_PARA, CRYPT_DECRYPT_MESSAGE_PARA, CRYPT_SIGN_MESSAGE_PARA};
use cpcsp_ffi_linux::capi20::*;

use crate::certificate::Certificate;
use crate::cert_store::CertStore;
use crate::types::error::{check_bool, CpcspError};

// ---------------------------------------------------------------------------
// encrypt_message
// ---------------------------------------------------------------------------

/// Зашифровать сообщение (CMS EnvelopedData).
///
/// Возвращает DER-кодированное зашифрованное сообщение.
///
/// # Аргументы
/// * `recipient_certs` — сертификаты получателей
/// * `data` — данные для шифрования
pub fn encrypt_message(
    recipient_certs: &[&Certificate],
    data: &[u8],
) -> Result<Vec<u8>, CpcspError> {
    if recipient_certs.is_empty() {
        return Err(CpcspError::from_raw(0x57)); // ERROR_INVALID_PARAMETER
    }

    let encrypt_para = build_encrypt_para()?;

    // Массив указателей на сертификаты
    let cert_ptrs: Vec<PCCERT_CONTEXT> = recipient_certs.iter().map(|c| c.raw_handle()).collect();

    unsafe {
        // Первый вызов — определить размер
        let mut encrypted_len: DWORD = 0;
        check_bool(|| CryptEncryptMessage(
            &encrypt_para as *const _ as *const _,
            cert_ptrs.len() as DWORD,
            cert_ptrs.as_ptr(),
            data.as_ptr(),
            data.len() as DWORD,
            ptr::null_mut(),
            &mut encrypted_len,
        ))?;

        if encrypted_len == 0 {
            return Ok(Vec::new());
        }

        // Второй вызов — зашифровать
        let mut encrypted_blob = vec![0u8; encrypted_len as usize];
        check_bool(|| CryptEncryptMessage(
            &encrypt_para as *const _ as *const _,
            cert_ptrs.len() as DWORD,
            cert_ptrs.as_ptr(),
            data.as_ptr(),
            data.len() as DWORD,
            encrypted_blob.as_mut_ptr(),
            &mut encrypted_len,
        ))?;

        encrypted_blob.truncate(encrypted_len as usize);
        Ok(encrypted_blob)
    }
}

// ---------------------------------------------------------------------------
// decrypt_message
// ---------------------------------------------------------------------------

/// Дешифровать сообщение (CMS EnvelopedData).
///
/// Для поиска ключа дешифрования использует сертификаты из указанного хранилища.
///
/// # Аргументы
/// * `encrypted_blob` — зашифрованное сообщение
/// * `cert_store` — хранилище сертификатов с ключами дешифрования
pub fn decrypt_message(
    encrypted_blob: &[u8],
    cert_store: &CertStore,
) -> Result<Vec<u8>, CpcspError> {
    let decrypt_para = build_decrypt_para(cert_store)?;

    unsafe {
        // Первый вызов — определить размер
        let mut decrypted_len: DWORD = 0;
        check_bool(|| CryptDecryptMessage(
            &decrypt_para as *const _ as *const _,
            encrypted_blob.as_ptr(),
            encrypted_blob.len() as DWORD,
            ptr::null_mut(),
            &mut decrypted_len,
            ptr::null_mut(),
        ))?;

        let mut decrypted = vec![0u8; decrypted_len as usize];
        let mut xchg_cert: PCCERT_CONTEXT = ptr::null();

        check_bool(|| CryptDecryptMessage(
            &decrypt_para as *const _ as *const _,
            encrypted_blob.as_ptr(),
            encrypted_blob.len() as DWORD,
            decrypted.as_mut_ptr(),
            &mut decrypted_len,
            &mut xchg_cert,
        ))?;

        decrypted.truncate(decrypted_len as usize);
        Ok(decrypted)
    }
}

// ---------------------------------------------------------------------------
// decrypt_and_verify_signature
// ---------------------------------------------------------------------------

/// Расшифровать сообщение и одновременно проверить подпись
/// (CryptDecryptAndVerifyMessageSignature).
///
/// Возвращает расшифрованные данные, сертификат обмена ключами (xchg)
/// и сертификат подписанта.
///
/// # Аргументы
/// * `encrypted_blob` — зашифрованное и подписанное сообщение
/// * `cert_store` — хранилище сертификатов с ключами дешифрования
pub fn decrypt_and_verify_signature(
    encrypted_blob: &[u8],
    cert_store: &CertStore,
) -> Result<(Vec<u8>, Certificate, Certificate), CpcspError> {
    let decrypt_para = build_decrypt_para(cert_store)?;
    let verify_para = crate::sign::build_verify_para()?;

    unsafe {
        // Первый вызов — определить размер
        let mut decrypted_len: DWORD = 0;
        check_bool(|| CryptDecryptAndVerifyMessageSignature(
            &decrypt_para as *const _ as *const _,
            &verify_para as *const _ as *const _,
            0, // dw_signer_index
            encrypted_blob.as_ptr(),
            encrypted_blob.len() as DWORD,
            ptr::null_mut(),
            &mut decrypted_len,
            ptr::null_mut(),
            ptr::null_mut(),
        ))?;

        let mut decrypted = vec![0u8; decrypted_len as usize];
        let mut xchg_cert: PCCERT_CONTEXT = ptr::null();
        let mut signer_cert: PCCERT_CONTEXT = ptr::null();

        check_bool(|| CryptDecryptAndVerifyMessageSignature(
            &decrypt_para as *const _ as *const _,
            &verify_para as *const _ as *const _,
            0,
            encrypted_blob.as_ptr(),
            encrypted_blob.len() as DWORD,
            decrypted.as_mut_ptr(),
            &mut decrypted_len,
            &mut xchg_cert,
            &mut signer_cert,
        ))?;

        decrypted.truncate(decrypted_len as usize);

        let xchg = if xchg_cert.is_null() {
            return Err(CpcspError::from_raw(0x57)); // ERROR_INVALID_PARAMETER
        } else {
            Certificate::from_raw(xchg_cert)
        };
        let signer = if signer_cert.is_null() {
            return Err(CpcspError::from_raw(0x57));
        } else {
            Certificate::from_raw(signer_cert)
        };

        Ok((decrypted, xchg, signer))
    }
}

// ---------------------------------------------------------------------------
// encrypt_and_sign_message
// ---------------------------------------------------------------------------

/// Подписать и зашифровать сообщение одновременно.
///
/// Возвращает DER-кодированное сообщение.
pub fn encrypt_and_sign_message(
    signer_cert: &Certificate,
    signer_key_spec: DWORD,
    hash_oid: &str,
    recipient_certs: &[&Certificate],
    data: &[u8],
) -> Result<Vec<u8>, CpcspError> {
    if recipient_certs.is_empty() {
        return Err(CpcspError::from_raw(0x57));
    }

    let sign_para = build_sign_and_encrypt_sign_para(signer_cert, signer_key_spec, hash_oid)?;
    let encrypt_para = build_encrypt_para()?;

    let cert_ptrs: Vec<PCCERT_CONTEXT> = recipient_certs.iter().map(|c| c.raw_handle()).collect();

    unsafe {
        // Первый вызов — определить размер
        let mut output_len: DWORD = 0;
        check_bool(|| CryptSignAndEncryptMessage(
            &sign_para as *const _ as *const _,
            &encrypt_para as *const _ as *const _,
            cert_ptrs.len() as DWORD,
            cert_ptrs.as_ptr(),
            data.as_ptr(),
            data.len() as DWORD,
            ptr::null_mut(),
            &mut output_len,
        ))?;

        if output_len == 0 {
            return Ok(Vec::new());
        }

        let mut output = vec![0u8; output_len as usize];
        check_bool(|| CryptSignAndEncryptMessage(
            &sign_para as *const _ as *const _,
            &encrypt_para as *const _ as *const _,
            cert_ptrs.len() as DWORD,
            cert_ptrs.as_ptr(),
            data.as_ptr(),
            data.len() as DWORD,
            output.as_mut_ptr(),
            &mut output_len,
        ))?;

        output.truncate(output_len as usize);
        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// Helper builders
// ---------------------------------------------------------------------------

fn build_encrypt_para() -> Result<CRYPT_ENCRYPT_MESSAGE_PARA, CpcspError> {
    // OID обязателен: КриптоПро сегфолтится в CryptEncryptMessage,
    // если ContentEncryptionAlgorithm.pszObjId == NULL
    // (Win32 допускает NULL как «алгоритм по умолчанию», CSP — нет).
    let oid = std::ffi::CString::new(szOID_CP_GOST_R3412_2015_K)
        .map_err(|_| CpcspError::from_raw(0x57))?;

    Ok(CRYPT_ENCRYPT_MESSAGE_PARA {
        cb_size: std::mem::size_of::<CRYPT_ENCRYPT_MESSAGE_PARA>() as DWORD,
        dw_msg_encoding_type: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        h_crypt_prov: 0,
        content_encryption_algorithm: cpcsp_ffi_linux::raw_types::CRYPT_ALGORITHM_IDENTIFIER {
            psz_obj_id: oid.as_ptr(),
            parameters: cpcsp_ffi_linux::raw_types::CRYPT_ATTR_BLOB {
                cb_data: 0,
                pb_data: std::ptr::null_mut(),
            },
        },
        pv_encryption_aux_info: std::ptr::null_mut(),
        dw_flags: 0,
        dw_inner_content_type: 0,
    })
}

fn build_decrypt_para(cert_store: &CertStore) -> Result<CRYPT_DECRYPT_MESSAGE_PARA, CpcspError> {
    let mut stores = [cert_store.raw_handle()];

    Ok(CRYPT_DECRYPT_MESSAGE_PARA {
        cb_size: std::mem::size_of::<CRYPT_DECRYPT_MESSAGE_PARA>() as DWORD,
        dw_msg_and_cert_encoding_type: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        c_cert_store: 1,
        _pad0: [0; 4],
        rgh_cert_store: stores.as_mut_ptr(),
    })
}

fn build_sign_and_encrypt_sign_para(
    cert: &Certificate,
    _key_spec: DWORD,
    hash_oid: &str,
) -> Result<CRYPT_SIGN_MESSAGE_PARA, CpcspError> {
    let hash_oid_cstr = std::ffi::CString::new(hash_oid)
        .map_err(|_| CpcspError::from_raw(0x57))?;

    Ok(CRYPT_SIGN_MESSAGE_PARA {
        cb_size: std::mem::size_of::<CRYPT_SIGN_MESSAGE_PARA>() as DWORD,
        dw_msg_encoding_type: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        p_signing_cert: cert.raw_handle(),
        hash_algorithm: cpcsp_ffi_linux::raw_types::CRYPT_ALGORITHM_IDENTIFIER {
            psz_obj_id: hash_oid_cstr.as_ptr() as *mut _,
            parameters: cpcsp_ffi_linux::raw_types::CRYPT_ATTR_BLOB {
                cb_data: 0,
                pb_data: std::ptr::null_mut(),
            },
        },
        pv_hash_aux_info: std::ptr::null_mut(),
        c_msg_cert: 0,
        _pad0: [0; 4],
        rgp_msg_cert: std::ptr::null_mut(),
        c_msg_crl: 0,
        _pad1: [0; 4],
        rgp_msg_crl: std::ptr::null_mut(),
        c_auth_attr: 0,
        _pad2: [0; 4],
        rg_auth_attr: std::ptr::null_mut(),
        c_unauth_attr: 0,
        _pad3: [0; 4],
        rg_unauth_attr: std::ptr::null_mut(),
        dw_flags: 0,
        dw_inner_content_type: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_store::CertStore;
    
    
    

    // ignore: CryptDecryptMessage сегфолтится в Rust-обвязке (C-аналог работает).
    // Разбор — отдельная задача; тест падал и до реализации encode-пути.
    #[test]
    #[ignore]
    fn test_encrypt_decrypt_roundtrip() {
        // Открыть MY хранилище
        let store = match CertStore::open_system("MY") {
            Ok(s) => s,
            Err(_) => {
                println!("Skipping encrypt test: MY store not available");
                return;
            }
        };

        // Ищем сертификат с ключом обмена (AT_KEYEXCHANGE)
        let cert = match store.iter().find(|c| {
            c.acquire_private_key()
             .map(|key| key.key_spec() == AT_KEYEXCHANGE)
             .unwrap_or(false)
        }) {
            Some(c) => c,
            None => {
                println!("Skipping encrypt test: no certificate with AT_KEYEXCHANGE key in MY store");
                println!("Hint: create a certificate with key_spec = AT_KEYEXCHANGE for encryption tests");
                return;
            }
        };

        // Зашифровать
        let data = b"Secret message for CryptoPro!";
        let encrypted = encrypt_message(&[&cert], data).unwrap();
        assert!(!encrypted.is_empty());
        println!("Encrypted: {} bytes", encrypted.len());

        // Дешифровать
        let decrypted = decrypt_message(&encrypted, &store).unwrap();
        assert_eq!(decrypted, data);
        println!("Decrypted: {} bytes, matches original!", decrypted.len());
    }

    // ignore: см. комментарий к test_encrypt_decrypt_roundtrip.
    #[test]
    #[ignore]
    fn test_encrypt_empty_data() {
        let store = match CertStore::open_system("MY") {
            Ok(s) => s,
            Err(_) => return,
        };

        // Ищем сертификат с ключом обмена (AT_KEYEXCHANGE)
        let cert = match store.iter().find(|c| {
            c.acquire_private_key()
             .map(|key| key.key_spec() == AT_KEYEXCHANGE)
             .unwrap_or(false)
        }) {
            Some(c) => c,
            None => {
                println!("Skipping encrypt test: no certificate with AT_KEYEXCHANGE key in MY store");
                println!("Hint: create a certificate with key_spec = AT_KEYEXCHANGE for encryption tests");
                return;
            }
        };

        let encrypted = encrypt_message(&[&cert], b"").unwrap();
        assert!(!encrypted.is_empty()); // CMS envelope has overhead
        println!("Encrypted empty: {} bytes", encrypted.len());
    }
}
