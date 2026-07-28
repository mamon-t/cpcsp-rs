//! CryptoAPI 2.0 extensions specific to CryptoPro
//! On Windows these are in cpcsp.dll or capilite.dll.

use crate::raw_types::*;

extern "system" {
    pub fn CPCryptInstallCertificate(
        hCertStore: HCERTSTORE,
        pCertContext: PCCERT_CONTEXT,
        dwFlags: DWORD,
    ) -> BOOL;

    pub fn CPGetDefaultGostHashAlgId(
        phHashAlgId: *mut DWORD,
    ) -> BOOL;

    pub fn CPCryptGetProvParam(
        hProv: HCRYPTPROV,
        dwParam: DWORD,
        pbData: *mut BYTE,
        pdwDataLen: *mut DWORD,
        dwFlags: DWORD,
    ) -> BOOL;
}

pub const PP_CLIENT_HWND: DWORD = 1;
pub const PP_KEYSET_SEC_DESCR: DWORD = 8;
pub const PP_SIGNATURE_KEY: DWORD = 11;
pub const PP_KEYEXCHANGE_KEY: DWORD = 12;