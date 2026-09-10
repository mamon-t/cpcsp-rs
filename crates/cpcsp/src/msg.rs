//! Safe обёртка над `HCRYPTMSG` — потоковая обработка CMS-сообщений.
//!
//! Модуль предоставляет безопасный API для кодирования/декодирования CMS-сообщений:
//! подпись, шифрование, проверка подписи, дешифрование.
//!
//! # Пример
//!
//! ```no_run
//! use cpcsp::cert_store::CertStore;
//! use cpcsp::msg::CryptMsg;
//! use cpcsp_ffi_linux::raw_constants::*;
//!
//! let store = CertStore::open_system("MY")?;
//! let cert = store.iter().next().expect("Нет сертификатов");
//!
//! // Кодирование (все данные сразу)
//! let data = b"Hello, CryptoPro!";
//! let encoded = CryptMsg::encode_signed(&cert, szOID_GOST_R3411_2012_256, data)?;
//! println!("Закодировано: {} байт", encoded.len());
//!
//! // Декодирование
//! let decoded = CryptMsg::decode(&encoded)?;
//! println!("Раскодировано: {} байт", decoded.len());
//! # Ok::<(), cpcsp::types::error::CpcspError>(())
//! ```
//!
//! Источник: CSP_WinCrypt.h:10440-11615

use std::ptr;
use std::ffi::c_void;

use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::{DWORD, HCRYPTPROV, HCRYPTMSG, PCMSG_STREAM_INFO, TRUE, FALSE};
use cpcsp_ffi_linux::capi20::*;

use crate::types::error::{check_bool, CpcspError};

// ---------------------------------------------------------------------------
// CryptMsg
// ---------------------------------------------------------------------------

/// Потоковая обработка CMS-сообщений.
///
/// Владеет `HCRYPTMSG` и автоматически закрывает его при drop.
/// Соответствует вызову `CryptMsgOpenToEncode` / `CryptMsgOpenToDecode` / `CryptMsgClose`.
pub struct CryptMsg {
    handle: HCRYPTMSG,
    owned: bool,
}

impl CryptMsg {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Открыть сообщение для кодирования.
    ///
    /// # Параметры
    /// - `msg_type` — тип сообщения (`CMSG_SIGNED`, `CMSG_ENVELOPED`, `CMSG_SIGNED_AND_ENVELOPED`).
    /// - `flags` — флаги кодирования (например, `CMSG_DETACHED_FLAG`).
    /// - `encoding_para` — параметры кодирования (указатель на `CMSG_SIGNED_ENCODE_INFO` и т.д.).
    ///
    /// # Безопасность
    /// `encoding_para` должен указывать на валидную структуру, соответствующую `msg_type`.
    pub unsafe fn open_to_encode(
        msg_type: DWORD,
        flags: DWORD,
        encoding_para: *const std::ffi::c_void,
    ) -> Result<Self, CpcspError> {
        let handle = CryptMsgOpenToEncode(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            flags,
            msg_type,
            encoding_para,
            ptr::null_mut(),
            ptr::null_mut(),
        );

        if handle.is_null() {
            return Err(CpcspError::last_os_error());
        }

        Ok(Self { handle, owned: true })
    }

    /// Открыть сообщение для декодирования.
    ///
    /// # Параметры
    /// - `flags` — флаги декодирования.
    /// - `prov` — дескриптор провайдера (`0` = по умолчанию).
    /// - `stream_info` — параметры потока (`NULL` = без потока).
    pub unsafe fn open_to_decode(
        flags: DWORD,
        prov: HCRYPTPROV,
        stream_info: PCMSG_STREAM_INFO,
    ) -> Result<Self, CpcspError> {
        let handle = CryptMsgOpenToDecode(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            flags,
            0, // msg_type определяется автоматически
            prov,
            ptr::null_mut(), // PCERT_INFO (recipient)
            stream_info,
        );

        if handle.is_null() {
            return Err(CpcspError::last_os_error());
        }

        Ok(Self { handle, owned: true })
    }

    /// Обернуть существующий дескриптор (без владения).
    ///
    /// # Safety
    /// `handle` должен быть валидным `HCRYPTMSG`.
    pub unsafe fn from_raw(handle: HCRYPTMSG) -> Self {
        Self { handle, owned: false }
    }

    // -----------------------------------------------------------------------
    // Encode helpers (простые — все данные сразу)
    // -----------------------------------------------------------------------

    /// Кодировать данные в CMS SignedData (все данные сразу, без потока).
    ///
    /// Подписант задаётся сертификатом; приватный ключ добывается через
    /// `CryptAcquireCertificatePrivateKey`. Сертификат подписанта
    /// включается в сообщение.
    ///
    /// Для больших данных используйте `open_to_encode` + `update` + `finish`.
    ///
    /// # Аргументы
    /// * `signer_cert` — сертификат подписанта (с доступным приватным ключом)
    /// * `hash_oid` — OID хеш-алгоритма (например, `szOID_GOST_R3411_2012_256`)
    /// * `data` — подписываемые данные
    pub fn encode_signed(
        signer_cert: &crate::certificate::Certificate,
        hash_oid: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, CpcspError> {
        use cpcsp_ffi_linux::raw_types::{
            CMSG_SIGNER_ENCODE_INFO, CMSG_SIGNED_ENCODE_INFO, CERT_BLOB, CRL_BLOB,
        };

        let oid_cstr = std::ffi::CString::new(hash_oid)
            .map_err(|_| CpcspError::from_raw(0x57))?; // ERROR_INVALID_PARAMETER

        // Приватный ключ подписанта: prov + key_spec.
        let private_key = signer_cert.acquire_private_key()?;

        let signer = CMSG_SIGNER_ENCODE_INFO {
            cb_size: std::mem::size_of::<CMSG_SIGNER_ENCODE_INFO>() as DWORD,
            _pad0: [0; 4],
            p_cert_info: unsafe { (*signer_cert.raw_handle()).p_cert_info },
            h_crypt_prov: private_key.raw_prov() as HCRYPTPROV,
            dw_key_spec: private_key.key_spec(),
            _pad1: [0; 4],
            hash_algorithm: cpcsp_ffi_linux::raw_types::CRYPT_ALGORITHM_IDENTIFIER {
                psz_obj_id: oid_cstr.as_ptr(),
                parameters: cpcsp_ffi_linux::raw_types::DataBlob::new_empty(),
            },
            pv_hash_aux_info: ptr::null_mut(),
            c_auth_attr: 0,
            _pad2: [0; 4],
            rg_auth_attr: ptr::null_mut(),
            c_unauth_attr: 0,
            _pad3: [0; 4],
            rg_unauth_attr: ptr::null_mut(),
        };

        // Сертификат подписанта включаем в сообщение.
        let cert_der = signer_cert.to_der()?;
        let cert_blob = CERT_BLOB {
            cb_data: cert_der.len() as DWORD,
            pb_data: cert_der.as_ptr() as *mut _,
        };
        let cert_blobs = [cert_blob];

        let signed_info = CMSG_SIGNED_ENCODE_INFO {
            cb_size: std::mem::size_of::<CMSG_SIGNED_ENCODE_INFO>() as DWORD,
            c_signers: 1,
            rg_signers: &signer,
            c_cert_encoded: cert_blobs.len() as DWORD,
            _pad1: [0; 4],
            rg_cert_encoded: cert_blobs.as_ptr(),
            c_crl_encoded: 0,
            _pad2: [0; 4],
            rg_crl_encoded: std::ptr::null::<CRL_BLOB>(),
        };

        let mut msg = unsafe {
            Self::open_to_encode(CMSG_SIGNED, 0, &signed_info as *const _ as *const c_void)?
        };

        msg.update(data, true)?;
        msg.finish()
    }

    /// Кодировать данные в CMS EnvelopedData (все данные сразу).
    ///
    /// Получатель задаётся сертификатом (key transport, PKCS #7 v1.5 —
    /// идентификация по Issuer+SerialNumber через `PCERT_INFO`).
    ///
    /// # Аргументы
    /// * `recipient_certs` — сертификаты получателей (минимум 1)
    /// * `enc_oid` — OID алгоритма шифрования контента
    ///   (например, `szOID_CP_GOST_R3412_2015_K`)
    /// * `data` — шифруемые данные
    pub fn encode_enveloped(
        recipient_certs: &[&crate::certificate::Certificate],
        enc_oid: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, CpcspError> {
        use cpcsp_ffi_linux::raw_types::CMSG_ENVELOPED_ENCODE_INFO;

        if recipient_certs.is_empty() {
            return Err(CpcspError::from_raw(0x57));
        }

        let oid_cstr = std::ffi::CString::new(enc_oid)
            .map_err(|_| CpcspError::from_raw(0x57))?;

        // Массив указателей на CERT_INFO получателей.
        let recipient_infos: Vec<*mut cpcsp_ffi_linux::raw_types::CERT_INFO> = recipient_certs
            .iter()
            .map(|c| unsafe { (*c.raw_handle()).p_cert_info })
            .collect();

        let enveloped_info = CMSG_ENVELOPED_ENCODE_INFO {
            cb_size: std::mem::size_of::<CMSG_ENVELOPED_ENCODE_INFO>() as DWORD,
            _pad0: [0; 4],
            h_crypt_prov: 0, // CSP выберет провайдер по алгоритму
            content_encryption_algorithm: cpcsp_ffi_linux::raw_types::CRYPT_ALGORITHM_IDENTIFIER {
                psz_obj_id: oid_cstr.as_ptr(),
                parameters: cpcsp_ffi_linux::raw_types::DataBlob::new_empty(),
            },
            pv_encryption_aux_info: ptr::null_mut(),
            c_recipients: recipient_infos.len() as DWORD,
            _pad1: [0; 4],
            rgp_recipients: recipient_infos.as_ptr() as *mut *mut _,
        };

        let mut msg = unsafe {
            Self::open_to_encode(
                CMSG_ENVELOPED,
                0,
                &enveloped_info as *const _ as *const c_void,
            )?
        };

        msg.update(data, true)?;
        msg.finish()
    }

    // -----------------------------------------------------------------------
    // Decode helpers (простые — все данные сразу)
    // -----------------------------------------------------------------------

    /// Декодировать CMS-сообщение (все данные сразу).
    ///
    /// Возвращает раскодированное содержимое сообщения.
    pub fn decode(encoded: &[u8]) -> Result<Vec<u8>, CpcspError> {
        unsafe {
            let msg = Self::open_to_decode(0, 0, ptr::null_mut())?;

            check_bool(|| {
                CryptMsgUpdate(msg.handle, encoded.as_ptr(), encoded.len() as DWORD, TRUE)
            })?;

            let mut size: DWORD = 0;
            check_bool(|| {
                CryptMsgGetParam(msg.handle, CMSG_CONTENT_PARAM, 0, ptr::null_mut(), &mut size)
            })?;

            let mut buf = vec![0u8; size as usize];
            check_bool(|| {
                CryptMsgGetParam(
                    msg.handle,
                    CMSG_CONTENT_PARAM,
                    0,
                    buf.as_mut_ptr() as *mut c_void,
                    &mut size,
                )
            })?;

            buf.truncate(size as usize);
            Ok(buf)
        }
    }

    /// Получить тип сообщения из закодированных данных.
    pub fn get_type(encoded: &[u8]) -> Result<DWORD, CpcspError> {
        unsafe {
            let msg = Self::open_to_decode(0, 0, ptr::null_mut())?;

            check_bool(|| {
                CryptMsgUpdate(msg.handle, encoded.as_ptr(), encoded.len() as DWORD, TRUE)
            })?;

            let mut msg_type: DWORD = 0;
            let mut size: DWORD = std::mem::size_of::<DWORD>() as DWORD;

            check_bool(|| {
                CryptMsgGetParam(
                    msg.handle,
                    CMSG_TYPE_PARAM,
                    0,
                    &mut msg_type as *mut DWORD as *mut c_void,
                    &mut size,
                )
            })?;

            Ok(msg_type)
        }
    }

    // -----------------------------------------------------------------------
    // Streaming operations
    // -----------------------------------------------------------------------

    /// Добавить данные в сообщение (потоково).
    ///
    /// Можно вызывать несколько раз для обработки данных блоками.
    pub fn update(&mut self, data: &[u8], final_block: bool) -> Result<(), CpcspError> {
        unsafe {
            check_bool(|| {
                CryptMsgUpdate(
                    self.handle,
                    data.as_ptr(),
                    data.len() as DWORD,
                    if final_block { TRUE } else { FALSE },
                )
            })?;
        }
        Ok(())
    }

    /// Получить параметр сообщения.
    ///
    /// # Параметры
    /// - `param_type` — тип параметра (`CMSG_CONTENT_PARAM`, `CMSG_TYPE_PARAM` и т.д.).
    ///
    /// # Возвращает
    /// Байты параметра.
    pub fn get_param(&mut self, param_type: DWORD) -> Result<Vec<u8>, CpcspError> {
        let mut size: DWORD = 0;

        unsafe {
            check_bool(|| {
                CryptMsgGetParam(
                    self.handle,
                    param_type,
                    0,
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
                CryptMsgGetParam(
                    self.handle,
                    param_type,
                    0,
                    buf.as_mut_ptr() as *mut c_void,
                    &mut size,
                )
            })?;
        }

        buf.truncate(size as usize);
        Ok(buf)
    }

    /// Управление сообщением (контроль операций).
    ///
    /// # Параметры
    /// - `control_type` — тип контроля (`CMSG_CTRL_VERIFY_SIGNATURE`, `CMSG_CTRL_DECRYPT` и т.д.).
    /// - `control_para` — параметры контроля.
    pub fn control(
        &mut self,
        control_type: DWORD,
        control_para: *mut std::ffi::c_void,
    ) -> Result<(), CpcspError> {
        unsafe {
            check_bool(|| {
                CryptMsgControl(
                    self.handle,
                    0,
                    control_type,
                    control_para,
                )
            })?;
        }
        Ok(())
    }

    /// Проверить подпись сообщения.
    pub fn verify_signature(&mut self) -> Result<(), CpcspError> {
        self.control(CMSG_CTRL_VERIFY_SIGNATURE, ptr::null_mut())
    }

    // -----------------------------------------------------------------------
    // Finalize
    // -----------------------------------------------------------------------

    /// Завершить формирование сообщения и получить результат.
    ///
    /// Этот метод вызывается после `update` с `final_block=true`.
    pub fn finish(&mut self) -> Result<Vec<u8>, CpcspError> {
        self.get_param(CMSG_CONTENT_PARAM)
    }

    /// Дублировать дескриптор сообщения (увеличен счётчик ссылок).
    pub fn duplicate(&self) -> Self {
        let new_handle = unsafe { CryptMsgDuplicate(self.handle) };
        Self { handle: new_handle, owned: true }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Получить сырой дескриптор сообщения.
    pub fn as_raw(&self) -> HCRYPTMSG {
        self.handle
    }

    /// Проверить, является ли сообщение подписанным.
    pub fn is_signed(&self) -> bool {
        self.try_type() == Ok(CMSG_SIGNED)
            || self.try_type() == Ok(CMSG_SIGNED_AND_ENVELOPED)
    }

    /// Проверить, зашифровано ли сообщение.
    pub fn is_enveloped(&self) -> bool {
        self.try_type() == Ok(CMSG_ENVELOPED)
            || self.try_type() == Ok(CMSG_SIGNED_AND_ENVELOPED)
    }

    /// Прочитать CMSG_TYPE_PARAM текущего сообщения (внутренний хелпер).
    fn try_type(&self) -> Result<DWORD, CpcspError> {
        let mut msg_type: DWORD = 0;
        let mut size: DWORD = std::mem::size_of::<DWORD>() as DWORD;

        unsafe {
            check_bool(|| {
                CryptMsgGetParam(
                    self.handle,
                    CMSG_TYPE_PARAM,
                    0,
                    &mut msg_type as *mut DWORD as *mut c_void,
                    &mut size,
                )
            })?;
        }

        Ok(msg_type)
    }

    /// Количество подписантов в сообщении.
    pub fn signer_count(&self) -> Result<u32, CpcspError> {
        let mut count: DWORD = 0;
        let mut size: DWORD = std::mem::size_of::<DWORD>() as DWORD;

        unsafe {
            check_bool(|| {
                CryptMsgGetParam(
                    self.handle,
                    CMSG_SIGNER_COUNT_PARAM,
                    0,
                    &mut count as *mut DWORD as *mut c_void,
                    &mut size,
                )
            })?;
        }

        Ok(count)
    }
}

impl Drop for CryptMsg {
    fn drop(&mut self) {
        if self.owned && !self.handle.is_null() {
            unsafe {
                CryptMsgClose(self.handle);
            }
            self.handle = ptr::null_mut();
        }
    }
}

impl std::fmt::Debug for CryptMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptMsg")
            .field("signed", &self.is_signed())
            .field("enveloped", &self.is_enveloped())
            .finish()
    }
}
