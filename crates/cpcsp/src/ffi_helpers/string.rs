//! Конвертация строк между Rust и C (UTF-8 ↔ UTF-16).
///
/// CryptoPro CSP использует:
/// - ANSI-строки (LPCSTR) — UTF-8 на Linux
/// - Unicode-строки (LPCWSTR) — UTF-16LE
///
/// Большинство функций имеют A/W варианты.
/// На Linux UTF-8 → ANSI простая конвертация (LPCSTR = *const c_char).
/// LPCWSTR = *const u16 (UTF-16).

use std::ffi::CStr;

use zeroize::Zeroizing;

/// Конвертировать &str в null-terminated UTF-16 строку (LPCWSTR).
///
/// Возвращает Vec<u16> с нулевым терминатором.
/// Используется для передачи строк в W-варианты функций.
///
/// # Пример
/// ```ignore
/// let wide = to_wide("Контейнер");
/// let ptr = wide.as_ptr(); // LPCWSTR
/// ```
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Конвертировать &str в null-terminated UTF-16 строку (LPCWSTR)
/// с занулением буфера при drop.
///
/// Используется для паролей и иных чувствительных данных.
/// Исходный `&str` вызывающего при этом не затрагивается.
pub fn to_wide_secure(s: &str) -> Zeroizing<Vec<u16>> {
    Zeroizing::new(s.encode_utf16().chain(std::iter::once(0)).collect())
}

/// Конвертировать null-terminated UTF-16 строку (LPCWSTR) в String.
///
/// # Safety
/// `ptr` должен указывать на валидную null-terminated UTF-16 строку.
pub unsafe fn from_wide(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16(slice).ok()
}

/// Конвертировать &str в null-terminated UTF-8 строку (LPCSTR).
///
/// Просто добавляет нулевой терминатор.
pub fn to_ansi(s: &str) -> Vec<u8> {
    s.bytes().chain(std::iter::once(0)).collect()
}

/// Конвертировать null-terminated UTF-8 строку (LPCSTR) в String.
///
/// # Safety
/// `ptr` должен указывать на валидную null-terminated UTF-8 строку.
pub unsafe fn from_ansi(ptr: *const std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let cstr = CStr::from_ptr(ptr);
    cstr.to_str().ok().map(|s| s.to_owned())
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_wide_ascii() {
        let wide = to_wide("Hello");
        assert_eq!(wide, vec![b'H' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16, 0]);
    }

    #[test]
    fn test_to_wide_unicode() {
        let wide = to_wide("Привет");
        assert_eq!(wide.len(), 7); // 6 chars + null
        assert_eq!(wide[6], 0); // null terminator
    }

    #[test]
    fn test_to_ansi_ascii() {
        let ansi = to_ansi("Hello");
        assert_eq!(ansi, vec![b'H', b'e', b'l', b'l', b'o', 0]);
    }
}
