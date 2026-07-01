//! Safe обёртка над `HCRYPTHASH`.
//!
//! Источник: CSP_WinCrypt.h:5433-5594 (CryptCreateHash, CryptHashData, etc.)

use std::fmt;

use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::{BOOL, ALG_ID, BYTE, DWORD, HCRYPTHASH, HCRYPTKEY, HCRYPTPROV};
use cpcsp_ffi_linux::capi10::*;

use crate::types::error::{check_bool, CpcspError};

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

/// Криптографический хеш-объект.
///
/// Владеет дескриптором `HCRYPTHASH` и автоматически освобождает его при drop.
/// Соответствует вызову `CryptCreateHash` / `CryptHashData` / `CryptGetHashParam`.
pub struct Hash {
    handle: HCRYPTHASH,
}

impl Hash {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Создать хеш-объект.
    ///
    /// # Аргументы
    /// * `h_prov` — дескриптор провайдера
    /// * `alg_id` — алгоритм хеширования (CALG_GOST_34_11, CALG_GOST_34_11_2012_256, CALG_MD5, CALG_SHA1, ...)
    /// * `h_key` — ключ (0 для немаскированных хешей)
    pub fn create(
        h_prov: HCRYPTPROV,
        alg_id: ALG_ID,
        h_key: HCRYPTKEY,
    ) -> Result<Self, CpcspError> {
        unsafe {
            let mut h_hash: HCRYPTHASH = 0;
            check_bool(|| CryptCreateHash(h_prov, alg_id, h_key, 0, &mut h_hash))?;
            Ok(Self { handle: h_hash })
        }
    }

    /// Продублировать хеш.
    pub fn duplicate(&self) -> Result<Self, CpcspError> {
        unsafe {
            let mut h_hash: HCRYPTHASH = 0;
            check_bool(|| CryptDuplicateHash(self.handle, std::ptr::null_mut(), 0, &mut h_hash))?;
            Ok(Self { handle: h_hash })
        }
    }

    // -----------------------------------------------------------------------
    // Data
    // -----------------------------------------------------------------------

    /// Хешировать данные.
    pub fn update(&self, data: &[u8]) -> Result<(), CpcspError> {
        unsafe {
            check_bool(|| CryptHashData(
                self.handle,
                data.as_ptr(),
                data.len() as DWORD,
                0,
            ))?;
            Ok(())
        }
    }

    /// Хешировать ключ сессии.
    pub fn hash_session_key(&self, h_key: HCRYPTKEY) -> Result<(), CpcspError> {
        unsafe {
            check_bool(|| CryptHashSessionKey(self.handle, h_key, 0))?;
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Parameters
    // -----------------------------------------------------------------------

    /// Получить параметр хеша (HP_HASHVAL, HP_HASHSIZE, HP_ALGID, ...).
    pub fn get_hash_param(&self, param: DWORD) -> Result<Vec<u8>, CpcspError> {
        unsafe {
            let mut data_len: DWORD = 0;
            check_bool(|| CryptGetHashParam(
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
            check_bool(|| CryptGetHashParam(
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

    /// Установить параметр хеша.
    pub fn set_hash_param(&self, param: DWORD, data: &[u8]) -> Result<(), CpcspError> {
        unsafe {
            check_bool(|| CryptSetHashParam(
                self.handle,
                param,
                data.as_ptr(),
                0,
            ))?;
            Ok(())
        }
    }

    /// Получить значение хеша.
    pub fn hash_value(&self) -> Result<Vec<u8>, CpcspError> {
        self.get_hash_param(HP_HASHVAL)
    }

    /// Получить размер хеша в байтах.
    pub fn hash_size(&self) -> Result<u32, CpcspError> {
        let data = self.get_hash_param(HP_HASHSIZE)?;
        if data.len() >= 4 {
            Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        } else {
            Err(CpcspError::from_raw(0x00000001)) // ERROR_INVALID_DATA
        }
    }

    // -----------------------------------------------------------------------
    // Sign
    // -----------------------------------------------------------------------

    /// Подписать этот хеш с помощью ключа.
    ///
    /// Удобная обёртка: вызывает `CryptSignHashA` с NULL описанием.
    pub fn sign(&self, key_spec: DWORD) -> Result<Vec<u8>, CpcspError> {
        unsafe {
            let mut sig_len: DWORD = 0;
            check_bool(|| CryptSignHashA(
                self.handle,
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
                self.handle,
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

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Сырой дескриптор хеша для FFI.
    pub fn raw_handle(&self) -> HCRYPTHASH {
        self.handle
    }
}

impl Drop for Hash {
    fn drop(&mut self) {
        unsafe {
            CryptDestroyHash(self.handle);
        }
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash(0x{:x})", self.handle)
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
    fn test_hash_create_and_update() {
        let h_prov = test_prov();
        let hash = Hash::create(h_prov, CALG_GOST_34_11_2012_256, 0).unwrap();
        hash.update(b"Hello, world!").unwrap();
        let value = hash.hash_value().unwrap();
        assert!(!value.is_empty());
    }

    #[test]
    fn test_hash_size() {
        let h_prov = test_prov();
        let hash = Hash::create(h_prov, CALG_GOST_34_11_2012_256, 0).unwrap();
        let size = hash.hash_size().unwrap();
        assert_eq!(size, 32); // GOST R 34.11-2012 256-bit = 32 bytes
    }

    #[test]
    fn test_hash_duplicate() {
        let h_prov = test_prov();
        let hash = Hash::create(h_prov, CALG_GOST_34_11_2012_256, 0).unwrap();
        hash.update(b"test").unwrap();
        let hash2 = hash.duplicate().unwrap();
        let v1 = hash.hash_value().unwrap();
        let v2 = hash2.hash_value().unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_hash_debug() {
        let h_prov = test_prov();
        let hash = Hash::create(h_prov, CALG_GOST_34_11_2012_256, 0).unwrap();
        let debug = format!("{:?}", hash);
        assert!(debug.starts_with("Hash(0x"));
    }
}
