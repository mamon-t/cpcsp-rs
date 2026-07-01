//! Safe обёртка над `HCRYPTMSG` — потоковая обработка CMS-сообщений.
//!
//! Модуль предоставляет безопасный API для кодирования/декодирования CMS-сообщений:
//! подпись, шифрование, проверка подписи, дешифрование.
//!
//! # Пример
//!
//! ```no_run
//! use cpcsp::msg::CryptMsg;
//! use cpcsp_ffi_linux::raw_constants::*;
//!
//! // Кодирование (все данные сразу)
//! let data = b"Hello, CryptoPro!";
//! let encoded = CryptMsg::encode_signed(data)?;
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
use cpcsp_ffi_linux::raw_types::{BOOL, BYTE, DWORD, HCRYPTPROV, HCRYPTMSG, PCMSG_STREAM_INFO, TRUE, FALSE};
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

    /// Кодировать данные в CMS (все данные сразу, без потока).
    ///
    /// Это упрощённый вариант для кодирования небольших данных.
    /// Для больших данных используйте `open_to_encode` + `update` + `finish`.
    pub fn encode_signed(data: &[u8]) -> Result<Vec<u8>, CpcspError> {
        let mut size: DWORD = 0;

        unsafe {
            // Простое кодирование — данные идут как CMSG_DATA
            let msg = Self::open_to_encode(CMSG_SIGNED, 0, ptr::null())?;

            // Обновить данными
            CryptMsgUpdate(
                msg.handle,
                data.as_ptr(),
                data.len() as DWORD,
                TRUE,
            );

            // Получить размер результата
            CryptMsgGetParam(
                msg.handle,
                CMSG_CONTENT_PARAM,
                0,
                ptr::null_mut(),
                &mut size,
            );

            if size == 0 {
                return Err(CpcspError::from_raw(0x8007000E));
            }

            let mut buf = vec![0u8; size as usize];

            CryptMsgGetParam(
                msg.handle,
                CMSG_CONTENT_PARAM,
                0,
                buf.as_mut_ptr() as *mut c_void,
                &mut size,
            );

            buf.truncate(size as usize);
            Ok(buf)
        }
    }

    /// Кодировать данные в CMS-конверт (все данные сразу).
    pub fn encode_enveloped(data: &[u8]) -> Result<Vec<u8>, CpcspError> {
        let mut size: DWORD = 0;

        unsafe {
            let msg = Self::open_to_encode(CMSG_ENVELOPED, 0, ptr::null())?;

            CryptMsgUpdate(
                msg.handle,
                data.as_ptr(),
                data.len() as DWORD,
                TRUE,
            );

            CryptMsgGetParam(
                msg.handle,
                CMSG_CONTENT_PARAM,
                0,
                ptr::null_mut(),
                &mut size,
            );

            if size == 0 {
                return Err(CpcspError::from_raw(0x8007000E));
            }

            let mut buf = vec![0u8; size as usize];

            CryptMsgGetParam(
                msg.handle,
                CMSG_CONTENT_PARAM,
                0,
                buf.as_mut_ptr() as *mut c_void,
                &mut size,
            );

            buf.truncate(size as usize);
            Ok(buf)
        }
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

            CryptMsgUpdate(
                msg.handle,
                encoded.as_ptr(),
                encoded.len() as DWORD,
                TRUE,
            );

            let mut size: DWORD = 0;
            CryptMsgGetParam(
                msg.handle,
                CMSG_CONTENT_PARAM,
                0,
                ptr::null_mut(),
                &mut size,
            );

            if size == 0 {
                return Err(CpcspError::from_raw(0x8007000E));
            }

            let mut buf = vec![0u8; size as usize];

            CryptMsgGetParam(
                msg.handle,
                CMSG_CONTENT_PARAM,
                0,
                buf.as_mut_ptr() as *mut c_void,
                &mut size,
            );

            buf.truncate(size as usize);
            Ok(buf)
        }
    }

    /// Получить тип сообщения из закодированных данных.
    pub fn get_type(encoded: &[u8]) -> Result<DWORD, CpcspError> {
        unsafe {
            let msg = Self::open_to_decode(0, 0, ptr::null_mut())?;

            CryptMsgUpdate(
                msg.handle,
                encoded.as_ptr(),
                encoded.len() as DWORD,
                TRUE,
            );

            let mut msg_type: DWORD = 0;
            let mut size: DWORD = std::mem::size_of::<DWORD>() as DWORD;

            CryptMsgGetParam(
                msg.handle,
                CMSG_TYPE_PARAM,
                0,
                &mut msg_type as *mut DWORD as *mut c_void,
                &mut size,
            );

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
        let mut msg_type: DWORD = 0;
        let mut size: DWORD = std::mem::size_of::<DWORD>() as DWORD;

        unsafe {
            CryptMsgGetParam(
                self.handle,
                CMSG_TYPE_PARAM,
                0,
                &mut msg_type as *mut DWORD as *mut c_void,
                &mut size,
            );
        }

        msg_type == CMSG_SIGNED || msg_type == CMSG_SIGNED_AND_ENVELOPED
    }

    /// Проверить, зашифровано ли сообщение.
    pub fn is_enveloped(&self) -> bool {
        let mut msg_type: DWORD = 0;
        let mut size: DWORD = std::mem::size_of::<DWORD>() as DWORD;

        unsafe {
            CryptMsgGetParam(
                self.handle,
                CMSG_TYPE_PARAM,
                0,
                &mut msg_type as *mut DWORD as *mut c_void,
                &mut size,
            );
        }

        msg_type == CMSG_ENVELOPED || msg_type == CMSG_SIGNED_AND_ENVELOPED
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
