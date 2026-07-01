/// Safe Rust wrapper for CryptoPro CSP 5.0.
///
/// Этот crate предоставляет идиоматический Rust API для работы с
/// КриптоПро CSP через FFI-обёртку.
///
/// Основные модули:
/// - `types` — безопасные Rust-типы (BOOL, Handle, Blob, Error)
/// - `ffi_helpers` — хелперы для FFI-вызовов (двойной вызов, строки)

#[cfg(target_os = "linux")]
pub extern crate cpcsp_ffi_linux;

pub mod types;
pub mod ffi_helpers;
