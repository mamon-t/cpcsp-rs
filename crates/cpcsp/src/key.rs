//! Safe обёртка над `HCRYPTKEY` — криптографический ключ.
//!
//! Модуль предоставляет безопасный API для работы с ключами:
//! генерация, импорт/экспорт, получение параметров, подпись.
//!
//! # Примеры
//!
//! ```no_run
//! use cpcsp::provider::Provider;
//! use cpcsp::key::Key;
//! use cpcsp_ffi_linux::raw_constants::*;
//!
//! let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
//!
//! // Генерация ключа
//! let key = Key::gen(prov.raw_handle(), CALG_GOST_2012_256, CRYPT_EXPORTABLE)?;
//!
//! // Экспорт открытого ключа
//! let blob = key.export_blob(PUBLICKEYBLOB, 0)?;
//! println!("Открытый ключ: {} байт", blob.len());
//! # Ok::<(), cpcsp::types::error::CpcspError>(())
//! ```
//!
//! Источник: CSP_WinCrypt.h:5097-5320

use std::fmt;
use std::ptr;

use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::{ALG_ID, DWORD, HCRYPTKEY, HCRYPTHASH, HCRYPTPROV};
use cpcsp_ffi_linux::capi10::*;

use crate::types::error::{check_bool, CpcspError};

// ---------------------------------------------------------------------------
// Key
// ---------------------------------------------------------------------------

/// Криптографический ключ.
///
/// Владеет дескриптором `HCRYPTKEY` и автоматически освобождает его при drop.
/// Соответствует вызову `CryptGenKey` / `CryptImportKey` / `CryptExportKey`.
///
/// # Типы ключей
///
/// | Алгоритм | Описание |
/// |-----------|----------|
/// | `CALG_GOST_2012_256` | ГОСТ Р 34.10-2012 256-bit |
/// | `CALG_GOST_2012_512` | ГОСТ Р 34.10-2012 512-bit |
/// | `CALG_RSA_SIGN` | RSA для подписи |
/// | `CALG_RSA_KEYX` | RSA для обмена ключами |
///
/// # Пример
///
/// ```no_run
/// use cpcsp::provider::Provider;
/// use cpcsp::key::Key;
/// use cpcsp_ffi_linux::raw_constants::*;
///
/// let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
/// let key = Key::gen(prov.raw_handle(), CALG_GOST_2012_256, CRYPT_EXPORTABLE)?;
/// println!("Размер ключа: {} бит", key.key_len()?);
/// # Ok::<(), cpcsp::types::error::CpcspError>(())
/// ```
pub struct Key {
    handle: HCRYPTKEY,
}

impl Key {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Сгенерировать новый ключ.
    ///
    /// # Аргументы
    /// * `h_prov` — дескриптор провайдера
    /// * `alg_id` — алгоритм (CALG_GOST_2012_256, CALG_GOST_2012_512, CALG_RSA_SIGN, ...)
    /// * `flags` — флаги генерации (CRYPT_EXPORTABLE, размер ключа в младших 16 битах)
    ///
    /// # Безопасность
    /// Ключ помечается как экспортабельный только если передан `CRYPT_EXPORTABLE`.
    pub fn gen(h_prov: HCRYPTPROV, alg_id: ALG_ID, flags: DWORD) -> Result<Self, CpcspError> {
        unsafe {
            let mut h_key: HCRYPTKEY = 0;
            check_bool(|| CryptGenKey(h_prov, alg_id, flags, &mut h_key))?;
            Ok(Self { handle: h_key })
        }
    }

    /// Импортировать ключ из бинарного блоба.
    ///
    /// # Аргументы
    /// * `h_prov` — дескриптор провайдера
    /// * `data` — бинарный блоб (SIMPLEBLOB, PUBLICKEYBLOB, PRIVATEKEYBLOB, ...)
    /// * `h_pub_key` — дескриптор открытого ключа шифрования (0 для шифрования/дешифрования)
    pub fn from_blob(
        h_prov: HCRYPTPROV,
        data: &[u8],
        h_pub_key: HCRYPTKEY,
    ) -> Result<Self, CpcspError> {
        unsafe {
            let mut h_key: HCRYPTKEY = 0;
            check_bool(|| CryptImportKey(
                h_prov,
                data.as_ptr(),
                data.len() as DWORD,
                h_pub_key,
                0,
                &mut h_key,
            ))?;
            Ok(Self { handle: h_key })
        }
    }

    /// Получить ключ пользователя (AT_KEYEXCHANGE или AT_SIGNATURE).
    ///
    /// # Аргументы
    /// * `h_prov` — дескриптор провайдера
    /// * `key_spec` — AT_KEYEXCHANGE (1) или AT_SIGNATURE (2)
    pub fn from_user_key(h_prov: HCRYPTPROV, key_spec: DWORD) -> Result<Self, CpcspError> {
        unsafe {
            let mut h_key: HCRYPTKEY = 0;
            check_bool(|| CryptGetUserKey(h_prov, key_spec, &mut h_key))?;
            Ok(Self { handle: h_key })
        }
    }

    /// Продублировать ключ.
    pub fn duplicate(&self) -> Result<Self, CpcspError> {
        unsafe {
            let mut h_key: HCRYPTKEY = 0;
            check_bool(|| CryptDuplicateKey(self.handle, std::ptr::null_mut(), 0, &mut h_key))?;
            Ok(Self { handle: h_key })
        }
    }

    /// Производный ключ (CryptDeriveKey).
    ///
    /// Создаёт симметричный ключ из хеша базовых данных (пароль/secret).
    ///
    /// # Аргументы
    /// * `prov` — провайдер
    /// * `alg_id` — алгоритм ключа (CALG_GOST28147_89, CALG_MAGMA, ...)
    /// * `base_hash` — хеш базовых данных (обычно из хешированного пароля)
    /// * `flags` — флаги (0)
    pub fn derive(
        prov: &crate::provider::Provider,
        alg_id: ALG_ID,
        base_hash: &crate::hash::Hash,
        flags: DWORD,
    ) -> Result<Self, CpcspError> {
        unsafe {
            let mut h_key: HCRYPTKEY = 0;
            check_bool(|| CryptDeriveKey(
                prov.raw_handle() as HCRYPTPROV,
                alg_id,
                base_hash.raw_handle(),
                flags,
                &mut h_key,
            ))?;
            Ok(Self { handle: h_key })
        }
    }

    // -----------------------------------------------------------------------
    // Symmetric encryption / decryption
    // -----------------------------------------------------------------------

    /// Зашифровать данные (CryptEncrypt).
    ///
    /// Возвращает зашифрованные данные, включая дополнение (padding),
    /// которое учитывается провайдером. Для потокового шифрования передавайте
    /// `final_block = false` для всех блоков кроме последнего (`true`).
    pub fn encrypt(&self, data: &[u8], final_block: bool) -> Result<Vec<u8>, CpcspError> {
        unsafe {
            // Первый вызов — определить требуемый размер буфера вывода.
            let mut size: DWORD = data.len() as DWORD;
            check_bool(|| CryptEncrypt(
                self.handle,
                0,
                if final_block { 1 } else { 0 },
                0,
                ptr::null_mut(),
                &mut size,
                0,
            ))?;

            let mut buf = vec![0u8; size as usize];
            ptr::copy_nonoverlapping(data.as_ptr(), buf.as_mut_ptr(), data.len());

            let mut actual_len: DWORD = data.len() as DWORD;
            check_bool(|| CryptEncrypt(
                self.handle,
                0,
                if final_block { 1 } else { 0 },
                0,
                buf.as_mut_ptr(),
                &mut actual_len,
                size,
            ))?;

            buf.truncate(actual_len as usize);
            Ok(buf)
        }
    }

    /// Расшифровать данные на месте (CryptDecrypt).
    ///
    /// Возвращает реальную длину расшифрованных данных (в начале буфера).
    pub fn decrypt(&self, data: &mut [u8], final_block: bool) -> Result<usize, CpcspError> {
        unsafe {
            let mut size: DWORD = data.len() as DWORD;
            check_bool(|| CryptDecrypt(
                self.handle,
                0,
                if final_block { 1 } else { 0 },
                0,
                data.as_mut_ptr(),
                &mut size,
            ))?;
            Ok(size as usize)
        }
    }

    // -----------------------------------------------------------------------
    // Export
    // -----------------------------------------------------------------------

    /// Экспортировать ключ в бинарный блоб.
    ///
    /// # Аргументы
    /// * `blob_type` — тип блоба (PUBLICKEYBLOB, PRIVATEKEYBLOB, SIMPLEBLOB, ...)
    /// * `h_exp_key` — ключ шифрования для экспорта (0 для SIMPLEBLOB без шифрования)
    pub fn export_blob(&self, blob_type: DWORD, h_exp_key: HCRYPTKEY) -> Result<Vec<u8>, CpcspError> {
        unsafe {
            // Первый вызов — определить размер
            let mut data_len: DWORD = 0;
            check_bool(|| CryptExportKey(
                self.handle,
                h_exp_key,
                blob_type,
                0,
                std::ptr::null_mut(),
                &mut data_len,
            ))?;

            if data_len == 0 {
                return Ok(Vec::new());
            }

            // Второй вызов — экспортировать
            let mut data = vec![0u8; data_len as usize];
            check_bool(|| CryptExportKey(
                self.handle,
                h_exp_key,
                blob_type,
                0,
                data.as_mut_ptr(),
                &mut data_len,
            ))?;

            data.truncate(data_len as usize);
            Ok(data)
        }
    }

    // -----------------------------------------------------------------------
    // Key parameters
    // -----------------------------------------------------------------------

    /// Получить параметр ключа (KP_PERMISSIONS, KP_KEYLEN, KP_ALGID, ...).
    pub fn get_key_param(&self, param: DWORD) -> Result<Vec<u8>, CpcspError> {
        unsafe {
            let mut data_len: DWORD = 0;
            check_bool(|| CryptGetKeyParam(
                self.handle,
                param,
                std::ptr::null_mut(),
                &mut data_len,
                0,
            ))?;

            if data_len == 0 {
                return Ok(Vec::new());
            }

            let mut data = vec![0u8; data_len as usize];
            check_bool(|| CryptGetKeyParam(
                self.handle,
                param,
                data.as_mut_ptr(),
                &mut data_len,
                0,
            ))?;

            data.truncate(data_len as usize);
            Ok(data)
        }
    }

    /// Установить параметр ключа.
    pub fn set_key_param(&self, param: DWORD, data: &[u8]) -> Result<(), CpcspError> {
        unsafe {
            check_bool(|| CryptSetKeyParam(
                self.handle,
                param,
                data.as_ptr(),
                0,
            ))?;
            Ok(())
        }
    }

    /// Получить размер ключа в битах.
    pub fn key_len(&self) -> Result<u32, CpcspError> {
        let data = self.get_key_param(KP_KEYLEN)?;
        if data.len() >= 4 {
            Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        } else {
            Err(CpcspError::from_raw(0x00000001)) // ERROR_INVALID_DATA
        }
    }

    // -----------------------------------------------------------------------
    // Sign / Verify
    // -----------------------------------------------------------------------

    /// Подписать хеш (ANSI, NULL описание).
    pub fn sign_hash(&self, h_hash: HCRYPTHASH, key_spec: DWORD) -> Result<Vec<u8>, CpcspError> {
        unsafe {
            let mut sig_len: DWORD = 0;
            check_bool(|| CryptSignHashA(
                h_hash,
                key_spec,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                &mut sig_len,
            ))?;

            if sig_len == 0 {
                return Ok(Vec::new());
            }

            let mut signature = vec![0u8; sig_len as usize];
            check_bool(|| CryptSignHashA(
                h_hash,
                key_spec,
                std::ptr::null(),
                0,
                signature.as_mut_ptr(),
                &mut sig_len,
            ))?;

            signature.truncate(sig_len as usize);
            Ok(signature)
        }
    }

    /// Проверить подпись (ANSI, NULL описание).
    pub fn verify_signature(
        &self,
        h_hash: HCRYPTHASH,
        signature: &[u8],
        h_pub_key: HCRYPTKEY,
    ) -> Result<(), CpcspError> {
        unsafe {
            check_bool(|| CryptVerifySignatureA(
                h_hash,
                signature.as_ptr(),
                signature.len() as DWORD,
                h_pub_key,
                std::ptr::null(),
                0,
            ))?;
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Сырой дескриптор ключа для FFI.
    pub fn raw_handle(&self) -> HCRYPTKEY {
        self.handle
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            CryptDestroyKey(self.handle);
        }
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key(0x{:x})", self.handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpcsp_ffi_linux::capi10::CryptAcquireContextA;

    fn test_prov() -> HCRYPTPROV {
        unsafe {
            let mut h_prov: HCRYPTPROV = 0;
            CryptAcquireContextA(
                &mut h_prov,
                std::ptr::null(),
                std::ptr::null(),
                PROV_GOST_2012_256,
                CRYPT_VERIFYCONTEXT,
            );
            h_prov
        }
    }

    #[test]
    fn test_key_gen_and_export() {
        let h_prov = test_prov();
        let key = Key::gen(h_prov, CALG_GOST_2012_256, CRYPT_EXPORTABLE).unwrap();
        let blob = key.export_blob(PUBLICKEYBLOB, 0).unwrap();
        assert!(!blob.is_empty());
        // BLOBHEADER: bType(1) + bVersion(1) + reserved(2) + aiKeyBlob(4)
        assert_eq!(blob[0], PUBLICKEYBLOB as u8); // bType
        assert_eq!(blob[1], 2); // bVersion
        assert_eq!(blob[2], 0); // reserved low
        assert_eq!(blob[3], 0); // reserved high
        // aiKeyBlob (little-endian DWORD) = 0x2400 (CALG_GOST_2012_256)
        assert_eq!(blob[4], 0x00);
        assert_eq!(blob[5], 0x24);
    }

    #[test]
    fn test_key_import_export_roundtrip() {
        let h_prov = test_prov();
        let key = Key::gen(h_prov, CALG_GOST_2012_256, CRYPT_EXPORTABLE).unwrap();
        let blob = key.export_blob(PUBLICKEYBLOB, 0).unwrap();
        let key2 = Key::from_blob(h_prov, &blob, 0).unwrap();
        let blob2 = key2.export_blob(PUBLICKEYBLOB, 0).unwrap();
        assert_eq!(blob, blob2);
    }

    #[test]
    fn test_key_debug() {
        let h_prov = test_prov();
        let key = Key::gen(h_prov, CALG_GOST_2012_256, 0).unwrap();
        let debug = format!("{:?}", key);
        assert!(debug.starts_with("Key(0x"));
    }

    #[test]
    fn test_key_key_len() {
        let h_prov = test_prov();
        let key = Key::gen(h_prov, CALG_GOST_2012_256, CRYPT_EXPORTABLE).unwrap();
        let len = key.key_len().unwrap();
        assert!(len > 0);
    }
}
