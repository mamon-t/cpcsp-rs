//! RAII-обёртки для дескрипторов CryptoPro CSP.
///
/// Каждый дескриптор (HCRYPTPROV, HCRYPTKEY, HCRYPTHASH) требует
/// вызоваleanup-функции при уничтожении. Rust-ownership модель
/// обеспечивает автоматическое освобождение через `Drop`.
///
/// **Move semantics:** При передаче Handle в функцию, которая вызывает
/// destroy/free, ownership передаётся — handle больше не используется.
///
/// Источники:
/// - HCRYPTPROV: CSP_WinCrypt.h:246
/// - HCRYPTKEY: CSP_WinCrypt.h:247
/// - HCRYPTHASH: CSP_WinCrypt.h:248

use std::marker::PhantomData;

// ---------------------------------------------------------------------------
// ProvHandle — дескриптор провайдера (HCRYPTPROV)
// ---------------------------------------------------------------------------

/// Дескриптор криптографического провайдера.
/// Автоматически вызывает `CryptReleaseContext` при drop.
///
/// Источник: CSP_WinCrypt.h:246
pub struct ProvHandle {
    raw: usize,
}

impl ProvHandle {
    /// Создать из сырого HCRYPTPROV.
    ///
    /// # Safety
    /// `raw` должен быть валидным дескриптором, полученным из
    /// `CryptAcquireContext`.
    pub unsafe fn from_raw(raw: usize) -> Self {
        Self { raw }
    }

    pub fn raw(&self) -> usize {
        self.raw
    }

    pub fn is_null(&self) -> bool {
        self.raw == 0
    }
}

impl Drop for ProvHandle {
    fn drop(&mut self) {
        if self.raw != 0 {
            unsafe {
                cpcsp_ffi_linux::capi10::CryptReleaseContext(self.raw, 0);
            }
        }
    }
}

impl std::fmt::Debug for ProvHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProvHandle(0x{:X})", self.raw)
    }
}

// ---------------------------------------------------------------------------
// KeyHandle — дескриптор ключа (HCRYPTKEY)
// ---------------------------------------------------------------------------

/// Дескриптор криптографического ключа.
/// Автоматически вызывает `CryptDestroyKey` при drop.
///
/// Источник: CSP_WinCrypt.h:247
pub struct KeyHandle {
    raw: usize,
}

impl KeyHandle {
    /// Создать из сырого HCRYPTKEY.
    ///
    /// # Safety
    /// `raw` должен быть валидным дескриптором ключа.
    pub unsafe fn from_raw(raw: usize) -> Self {
        Self { raw }
    }

    pub fn raw(&self) -> usize {
        self.raw
    }

    pub fn is_null(&self) -> bool {
        self.raw == 0
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if self.raw != 0 {
            unsafe {
                cpcsp_ffi_linux::capi10::CryptDestroyKey(self.raw);
            }
        }
    }
}

impl std::fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyHandle(0x{:X})", self.raw)
    }
}

// ---------------------------------------------------------------------------
// HashHandle — дескриптор хеш-объекта (HCRYPTHASH)
// ---------------------------------------------------------------------------

/// Дескриптор хеш-объекта.
/// Автоматически вызывает `CryptDestroyHash` при drop.
///
/// Источник: CSP_WinCrypt.h:248
pub struct HashHandle {
    raw: usize,
}

impl HashHandle {
    /// Создать из сырого HCRYPTHASH.
    ///
    /// # Safety
    /// `raw` должен быть валидным дескриптором хеш-объекта.
    pub unsafe fn from_raw(raw: usize) -> Self {
        Self { raw }
    }

    pub fn raw(&self) -> usize {
        self.raw
    }

    pub fn is_null(&self) -> bool {
        self.raw == 0
    }
}

impl Drop for HashHandle {
    fn drop(&mut self) {
        if self.raw != 0 {
            unsafe {
                cpcsp_ffi_linux::capi10::CryptDestroyHash(self.raw);
            }
        }
    }
}

impl std::fmt::Debug for HashHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HashHandle(0x{:X})", self.raw)
    }
}

// ---------------------------------------------------------------------------
// Handle<T> — generic wrapper (без Drop, для маркерных типов)
// ---------------------------------------------------------------------------

/// Generic handle wrapper для случаев, когда тип дескриптора определяется
/// на уровне приложения. Не реализует Drop — cleanup на совести caller.
pub struct Handle<T> {
    raw: usize,
    _marker: PhantomData<T>,
}

impl<T> Handle<T> {
    pub unsafe fn from_raw(raw: usize) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    pub fn raw(&self) -> usize {
        self.raw
    }

    pub fn is_null(&self) -> bool {
        self.raw == 0
    }
}

impl<T> std::fmt::Debug for Handle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Handle(0x{:X})", self.raw)
    }
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prov_handle_null() {
        let h = unsafe { ProvHandle::from_raw(0) };
        assert!(h.is_null());
    }

    #[test]
    fn test_key_handle_raw() {
        let h = unsafe { KeyHandle::from_raw(0xDEAD) };
        assert_eq!(h.raw(), 0xDEAD);
        assert!(!h.is_null());
        // Prevent Drop from calling CryptDestroyKey on invalid handle
        std::mem::forget(h);
    }

    #[test]
    fn test_hash_handle_raw() {
        let h = unsafe { HashHandle::from_raw(0xBEEF) };
        assert_eq!(h.raw(), 0xBEEF);
        // Prevent Drop from calling CryptDestroyHash on invalid handle
        std::mem::forget(h);
    }
}
