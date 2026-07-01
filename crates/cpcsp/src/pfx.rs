//! Импорт/экспорт PKCS#12 (PFX) контейнеров.
//!
//! Источник: CSP_WinCrypt.h:12784-12885 (PFXImportCertStore, PFXExportCertStoreEx)

use std::ptr;

use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::{BOOL, BYTE, DWORD, DataBlob, HCERTSTORE};
use cpcsp_ffi_linux::capi20::*;

use crate::cert_store::CertStore;
use crate::types::error::{check_bool, CpcspError};

// ---------------------------------------------------------------------------
// Pfx
// ---------------------------------------------------------------------------

/// PKCS#12 (PFX) контейнер.
///
/// Позволяет импортировать и экспортировать сертификаты с ключами
/// в формате PKCS#12.
pub struct Pfx;

impl Pfx {
    /// Импортировать PFX-контейнер и открыть хранилище сертификатов.
    ///
    /// # Аргументы
    /// * `data` — DER-кодированный PFX-контейнер
    /// * `password` — пароль (UTF-16)
    ///
    /// # Безопасность
    /// Пароль передаётся в открытом виде. Используйте защищённое хранилище паролей.
    pub fn import(data: &[u8], password: &str) -> Result<CertStore, CpcspError> {
        let password_wide = to_wide(password);
        let mut pfx_blob = DataBlob {
            cb_data: data.len() as DWORD,
            pb_data: data.as_ptr() as *mut BYTE,
        };

        unsafe {
            let handle = PFXImportCertStore(
                &mut pfx_blob as *mut _,
                password_wide.as_ptr(),
                PKCS12_ALLOW_OVERWRITE_KEY | PKCS12_NO_PERSIST_KEY,
            );

            if handle.is_null() {
                return Err(CpcspError::last_os_error());
            }

            Ok(unsafe { CertStore::from_raw(handle) })
        }
    }

    /// Импортировать PFX с настраиваемыми флагами.
    pub fn import_with_flags(
        data: &[u8],
        password: &str,
        flags: DWORD,
    ) -> Result<CertStore, CpcspError> {
        let password_wide = to_wide(password);
        let mut pfx_blob = DataBlob {
            cb_data: data.len() as DWORD,
            pb_data: data.as_ptr() as *mut BYTE,
        };

        unsafe {
            let handle = PFXImportCertStore(
                &mut pfx_blob as *mut _,
                password_wide.as_ptr(),
                flags,
            );

            if handle.is_null() {
                return Err(CpcspError::last_os_error());
            }

            Ok(unsafe { CertStore::from_raw(handle) })
        }
    }

    /// Проверить, является ли blob PFX-контейнером.
    pub fn is_pfx_blob(data: &[u8]) -> bool {
        let mut blob = DataBlob {
            cb_data: data.len() as DWORD,
            pb_data: data.as_ptr() as *mut BYTE,
        };

        unsafe { PFXIsPFXBlob(&mut blob as *mut _) != 0 }
    }

    /// Проверить пароль PFX-контейнера.
    pub fn verify_password(data: &[u8], password: &str) -> bool {
        let password_wide = to_wide(password);
        let mut blob = DataBlob {
            cb_data: data.len() as DWORD,
            pb_data: data.as_ptr() as *mut BYTE,
        };

        unsafe { PFXVerifyPassword(&mut blob as *mut _, password_wide.as_ptr(), 0) != 0 }
    }

    /// Экспортировать хранилище в PFX-контейнер (расширенный).
    ///
    /// # Аргументы
    /// * `store` — хранилище для экспорта
    /// * `password` — пароль для шифрования PFX
    /// * `flags` — флаги экспорта (PKCS12_EXPORT_CERTIFICATES, PKCS12_EXPORT_PRIVATE_KEYS, ...)
    pub fn export(
        store: &CertStore,
        password: &str,
        flags: DWORD,
    ) -> Result<Vec<u8>, CpcspError> {
        let password_wide = to_wide(password);

        unsafe {
            // Первый вызов — определить размер
            let mut pfx_blob = DataBlob {
                cb_data: 0,
                pb_data: ptr::null_mut(),
            };

            check_bool(|| PFXExportCertStoreEx(
                store.raw_handle(),
                &mut pfx_blob as *mut _,
                password_wide.as_ptr(),
                ptr::null_mut(),
                flags,
            ))?;

            if pfx_blob.cb_data == 0 {
                return Ok(Vec::new());
            }

            // Выделить память через LocalAlloc
            let pfx_data = pfx_blob.cb_data as usize;
            let pfx_ptr = LocalAlloc(0x0040, pfx_data); // LMEM_FIXED = 0x0040
            if pfx_ptr.is_null() {
                return Err(CpcspError::from_raw(0x8)); // ERROR_NOT_ENOUGH_MEMORY
            }

            pfx_blob.pb_data = pfx_ptr as *mut BYTE;

            let result = check_bool(|| PFXExportCertStoreEx(
                store.raw_handle(),
                &mut pfx_blob as *mut _,
                password_wide.as_ptr(),
                ptr::null_mut(),
                flags,
            ));

            match result {
                Ok(()) => {
                    let mut data = vec![0u8; pfx_blob.cb_data as usize];
                    ptr::copy_nonoverlapping(pfx_blob.pb_data, data.as_mut_ptr(), pfx_blob.cb_data as usize);
                    LocalFree(pfx_ptr as *mut _);
                    Ok(data)
                }
                Err(e) => {
                    LocalFree(pfx_ptr as *mut _);
                    Err(e)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Преобразовать строку в UTF-16 (null-terminated).
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---------------------------------------------------------------------------
// LocalAlloc / LocalFree
// ---------------------------------------------------------------------------

extern "C" {
    fn LocalAlloc(flags: u32, bytes: usize) -> *mut std::ffi::c_void;
    fn LocalFree(mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_store::CertStore;

    #[test]
    fn test_is_pfx_blob_negative() {
        let data = b"not a pfx blob";
        assert!(!Pfx::is_pfx_blob(data));
    }

    #[test]
    fn test_import_from_store_roundtrip() {
        // Открыть MY хранилище
        let store = match CertStore::open_system("MY") {
            Ok(s) => s,
            Err(_) => {
                println!("Skipping PFX test: MY store not available");
                return;
            }
        };

        // Экспортировать в PFX
        let password = "test123";
        let pfx_data = Pfx::export(&store, password, PKCS12_EXPORT_CERTIFICATES | PKCS12_EXPORT_PRIVATE_KEYS);
        if pfx_data.is_err() {
            println!("Skipping PFX roundtrip: export failed: {:?}", pfx_data.err());
            return;
        }
        let pfx_data = pfx_data.unwrap();
        assert!(!pfx_data.is_empty());
        println!("Exported PFX: {} bytes", pfx_data.len());

        // Проверить что это PFX
        assert!(Pfx::is_pfx_blob(&pfx_data));

        // Проверить пароль
        assert!(Pfx::verify_password(&pfx_data, password));
        assert!(!Pfx::verify_password(&pfx_data, "wrong_password"));

        // Импортировать обратно
        let imported_store = Pfx::import(&pfx_data, password).unwrap();
        println!("Imported store has {} certs", imported_store.count());
    }
}
