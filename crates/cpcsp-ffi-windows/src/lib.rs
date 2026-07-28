#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
//! Windows FFI bindings to CryptoPro CSP
//! 
//! Unlike Linux, where CryptoPro implements the entire CAPI, on Windows
//! the basic CAPI functions are in system DLLs (advapi32.dll, crypt32.dll)
//! and CryptoPro acts as a cryptographic service provider.

pub mod raw_types;
pub mod capi10;
pub mod capi20;

pub use capi10::*;
pub use capi20::*;
pub use raw_types::*;
