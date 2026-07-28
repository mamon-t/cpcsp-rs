//! Raw C types used in CryptoPro CSP API
//! Идентичны linux-версии, но без внешних зависимостей.

pub type DWORD = u32;
pub type BOOL = i32;
pub type BYTE = u8;
pub type LPSTR = *mut i8;
pub type LPCSTR = *const i8;
pub type LPWSTR = *mut u16;
pub type LPCWSTR = *const u16;

pub type HCRYPTPROV = *mut std::ffi::c_void;
pub type HCRYPTKEY = *mut std::ffi::c_void;
pub type HCRYPTHASH = *mut std::ffi::c_void;
pub type HCRYPTMSG = *mut std::ffi::c_void;
pub type HCERTSTORE = *mut std::ffi::c_void;
pub type PCCERT_CONTEXT = *const CERT_CONTEXT;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CERT_CONTEXT {
    pub dwCertEncodingType: DWORD,
    pub pbCertEncoded: *mut BYTE,
    pub cbCertEncoded: DWORD,
    pub pCertInfo: *mut CERT_INFO,
    pub hCertStore: HCERTSTORE,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CERT_INFO {
    pub dwVersion: DWORD,
    pub SerialNumber: CRYPT_INTEGER_BLOB,
    pub SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub Issuer: CERT_NAME_BLOB,
    pub NotBefore: FILETIME,
    pub NotAfter: FILETIME,
    pub Subject: CERT_NAME_BLOB,
    pub SubjectPublicKeyInfo: CERT_PUBLIC_KEY_INFO,
    pub IssuerUniqueId: CRYPT_DATA_BLOB,
    pub SubjectUniqueId: CRYPT_DATA_BLOB,
    pub cExtension: DWORD,
    pub rgExtension: *mut CERT_EXTENSION,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CRYPT_ALGORITHM_IDENTIFIER {
    pub pszObjId: LPSTR,
    pub Parameters: CRYPT_OBJID_BLOB,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CERT_PUBLIC_KEY_INFO {
    pub Algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub PublicKey: CRYPT_DATA_BLOB,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CRYPT_OBJID_BLOB {
    pub cbData: DWORD,
    pub pbData: *mut BYTE,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CRYPT_DATA_BLOB {
    pub cbData: DWORD,
    pub pbData: *mut BYTE,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CRYPT_INTEGER_BLOB {
    pub cbData: DWORD,
    pub pbData: *mut BYTE,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CERT_NAME_BLOB {
    pub cbData: DWORD,
    pub pbData: *mut BYTE,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CERT_EXTENSION {
    pub pszObjId: LPSTR,
    pub fCritical: BOOL,
    pub Value: CRYPT_OBJID_BLOB,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FILETIME {
    pub dwLowDateTime: DWORD,
    pub dwHighDateTime: DWORD,
}