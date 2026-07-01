//! Error type for CryptoPro CSP operations.
///
///大多数 функций CryptoPro возвращают BOOL (FALSE при ошибке),
/// а код ошибки доступен через `GetLastError()`.
///
/// **Внимание:** Как отмечено пользователем, не все ошибки единообразны.
/// Некоторые функции (например, `CryptSetProvParam`) могут вернуть "успех"
/// при фактической ошибке (особенно в контексте ГОСТ 34.12).
/// Поэтому `CpcspError` — это raw-обёртка над кодом ошибки,
/// а не семантический тип.

use std::fmt;

/// Код ошибки CryptoPro / Windows API.
///
/// Значение — это код из `GetLastError()` после неудачного FFI-вызова.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CpcspError {
    code: u32,
}

impl CpcspError {
    /// Создать ошибку из кода.
    pub fn from_raw(code: u32) -> Self {
        Self { code }
    }

    /// Получить ошибку из `GetLastError()`.
    pub fn last_os_error() -> Self {
        unsafe {
            Self {
                code: cpcsp_ffi_linux::capi10::GetLastError(),
            }
        }
    }

    /// Получить код ошибки.
    pub fn code(self) -> u32 {
        self.code
    }

    /// Проверить, является ли код ошибки "успехом" (ERROR_SUCCESS = 0).
    pub fn is_success(self) -> bool {
        self.code == 0
    }

    /// Попытаться получить текстовое описание ошибки.
    /// Использует `FormatMessageA` из системной библиотеки.
    pub fn message(&self) -> Option<String> {
        // FormatMessageA определена в libcapi10.so или libc.so
        // Пока возвращаем код в виде строки
        Some(format!("CryptoPro error code: 0x{:08X}", self.code))
    }
}

impl fmt::Debug for CpcspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CpcspError(0x{:08X})", self.code)
    }
}

impl fmt::Display for CpcspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(msg) => write!(f, "{}", msg),
            None => write!(f, "CryptoPro error 0x{:08X}", self.code),
        }
    }
}

impl std::error::Error for CpcspError {}

/// Result type for CryptoPro operations.
pub type CpcspResult<T> = Result<T, CpcspError>;

/// Хелпер: вызвать FFI-функцию, вернуть Result.
///
/// Паттерн: передаём функцию, которая возвращает BOOL.
/// FALSE → CpcspError::last_os_error(), TRUE → Ok(()).
///
/// **Внимание:** Этот хелпер НЕ подходит для всех функций!
/// Как отмечено, некоторые функции КриптоПро могут возвращать
/// "успех" при фактической ошибке (ГОСТ 34.12 quirky behavior).
/// В таких случаях нужен ручной вызов с дополнительной проверкой.
pub fn check_bool<F: FnOnce() -> cpcsp_ffi_linux::raw_types::BOOL>(
    f: F,
) -> CpcspResult<()> {
    let result = f();
    if result != 0 {
        Ok(())
    } else {
        Err(CpcspError::last_os_error())
    }
}

/// Хелпер: вызвать FFI-функцию и вернуть значение.
/// FALSE → CpcspError, TRUE → Ok(value).
pub fn check_bool_with<T, F: FnOnce() -> (cpcsp_ffi_linux::raw_types::BOOL, T)>(
    f: F,
) -> CpcspResult<T> {
    let (result, value) = f();
    if result != 0 {
        Ok(value)
    } else {
        Err(CpcspError::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_from_code() {
        let err = CpcspError::from_raw(2);
        assert_eq!(err.code(), 2);
        assert!(!err.is_success());
    }

    #[test]
    fn test_success() {
        let err = CpcspError::from_raw(0);
        assert!(err.is_success());
    }
}
