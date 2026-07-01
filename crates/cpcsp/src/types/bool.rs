//! Safe wrapper for Windows BOOL type.
//!
/// Windows `BOOL` — это `int` (4 байта), а не Rust `bool`.
/// TRUE = 1, FALSE = 0. Любое другое значение тоже считается "истиной",
/// но для предсказуемости мы нормализуем в TRUE/FALSE.
///
/// Источник: CSP_WinDef.h:157 — `typedef int BOOL;`

use cpcsp_ffi_linux::raw_types as ffi;

/// Типобезопасная обёртка над C `BOOL` (`int`).
///
/// Гарантирует, что значение всегда 0 или 1.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BOOL(i32);

impl BOOL {
    /// Истинное значение (1).
    pub const TRUE: Self = Self(1);

    /// Ложное значение (0).
    pub const FALSE: Self = Self(0);

    /// Создать BOOL из числа (нормализует: 0 → FALSE, всё остальное → TRUE).
    pub fn from_raw(value: ffi::BOOL) -> Self {
        Self(if value == 0 { 0 } else { 1 })
    }

    /// Получить сырое C-значение (0 или 1).
    pub fn as_raw(self) -> ffi::BOOL {
        self.0
    }

    /// Проверить на TRUE.
    pub fn is_true(self) -> bool {
        self.0 != 0
    }

    /// Проверить на FALSE.
    pub fn is_false(self) -> bool {
        self.0 == 0
    }
}

impl From<bool> for BOOL {
    fn from(b: bool) -> Self {
        if b { Self::TRUE } else { Self::FALSE }
    }
}

impl From<BOOL> for bool {
    fn from(b: BOOL) -> Self {
        b.is_true()
    }
}

impl From<ffi::BOOL> for BOOL {
    fn from(raw: ffi::BOOL) -> Self {
        Self::from_raw(raw)
    }
}

impl From<BOOL> for ffi::BOOL {
    fn from(b: BOOL) -> Self {
        b.as_raw()
    }
}

impl Default for BOOL {
    fn default() -> Self {
        Self::FALSE
    }
}

impl std::fmt::Display for BOOL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_true() {
            write!(f, "TRUE")
        } else {
            write!(f, "FALSE")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bool_true() {
        let b = BOOL::from_raw(1);
        assert!(b.is_true());
        assert!(!b.is_false());
        assert_eq!(b.as_raw(), 1);
    }

    #[test]
    fn test_bool_false() {
        let b = BOOL::from_raw(0);
        assert!(!b.is_true());
        assert!(b.is_false());
        assert_eq!(b.as_raw(), 0);
    }

    #[test]
    fn test_bool_nonstandard_true() {
        // Любое значение != 0 считается TRUE
        let b = BOOL::from_raw(42);
        assert!(b.is_true());
        assert_eq!(b.as_raw(), 1); // нормализуется
    }

    #[test]
    fn test_bool_from_rust_bool() {
        assert_eq!(BOOL::from(true), BOOL::TRUE);
        assert_eq!(BOOL::from(false), BOOL::FALSE);
    }

    #[test]
    fn test_bool_into_rust_bool() {
        assert!(bool::from(BOOL::TRUE));
        assert!(!bool::from(BOOL::FALSE));
    }
}
