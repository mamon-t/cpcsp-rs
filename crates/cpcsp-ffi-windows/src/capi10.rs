//! CryptoAPI 1.0 functions
//! On Windows these are in advapi32.dll and crypt32.dll.

use crate::raw_types::*;

extern "system" {
    pub fn CryptAcquireContextW(
        phProv: *mut HCRYPTPROV,
        szContainer: LPCWSTR,
        szProvider: LPCWSTR,
        dwProvType: DWORD,
        dwFlags: DWORD,
    ) -> BOOL;

    pub fn CryptReleaseContext(
        hProv: HCRYPTPROV,
        dwFlags: DWORD,
    ) -> BOOL;

    pub fn CryptGenKey(
        hProv: HCRYPTPROV,
        Algid: DWORD,
        dwFlags: DWORD,
        phKey: *mut HCRYPTKEY,
    ) -> BOOL;

    pub fn CryptDestroyKey(hKey: HCRYPTKEY) -> BOOL;

    pub fn CryptCreateHash(
        hProv: HCRYPTPROV,
        Algid: DWORD,
        hKey: HCRYPTKEY,
        dwFlags: DWORD,
        phHash: *mut HCRYPTHASH,
    ) -> BOOL;

    pub fn CryptDestroyHash(hHash: HCRYPTHASH) -> BOOL;

    pub fn CryptHashData(
        hHash: HCRYPTHASH,
        pbData: *const BYTE,
        dwDataLen: DWORD,
        dwFlags: DWORD,
    ) -> BOOL;

    pub fn CryptGetHashParam(
        hHash: HCRYPTHASH,
        dwParam: DWORD,
        pbData: *mut BYTE,
        pdwDataLen: *mut DWORD,
        dwFlags: DWORD,
    ) -> BOOL;

    pub fn CryptSignHashW(
        hHash: HCRYPTHASH,
        dwKeySpec: DWORD,
        szDescription: LPCWSTR,
        dwFlags: DWORD,
        pbSignature: *mut BYTE,
        pdwSigLen: *mut DWORD,
    ) -> BOOL;

    pub fn CryptVerifySignatureW(
        hHash: HCRYPTHASH,
        pbSignature: *const BYTE,
        dwSigLen: DWORD,
        hPubKey: HCRYPTKEY,
        szDescription: LPCWSTR,
        dwFlags: DWORD,
    ) -> BOOL;
}

pub const PROV_GOST_DEF: DWORD = 75;
pub const PROV_GOST_2012_256: DWORD = 80;
pub const PROV_GOST_2012_512: DWORD = 81;

pub const CRYPT_VERIFYCONTEXT: DWORD = 0xF0000000;
pub const CRYPT_NEWKEYSET: DWORD = 0x00000008;

pub const CALG_GR3411: DWORD = 0x00006E80;
pub const CALG_GR3411_2012_256: DWORD = 0x00006F80;
pub const CALG_GR3411_2012_512: DWORD = 0x00006F81;
pub const CALG_GR3410: DWORD = 0x00006E81;
pub const CALG_GR3410_2012_256: DWORD = 0x00006F82;
pub const CALG_GR3410_2012_512: DWORD = 0x00006F83;