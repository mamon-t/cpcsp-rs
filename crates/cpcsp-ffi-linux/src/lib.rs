//! Raw FFI bindings for CryptoPro CSP 5.0 on Linux.
//!
//! Этот crate содержит:
//! - `raw_types` — `#[repr(C)]` структуры, точные аналоги C-типов
//! - `raw_constants` — все `#define` константы
//! - `capi10` — `extern "C"` функции из `libcapi10.so`
//! - `capi20` — `extern "C"` функции из `libcapi20.so`
//!
//! Все типы и константы ссылаются на исходные заголовки КриптоПро:
//! `/opt/cprocsp/include/cpcsp/`

pub mod raw_types;
pub mod raw_constants;
pub mod capi10;
pub mod capi20;
