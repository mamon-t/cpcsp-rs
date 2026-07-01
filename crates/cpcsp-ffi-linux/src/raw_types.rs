//! Raw FFI type definitions for CryptoPro CSP 5.0 on Linux.
//!
//! Эти типы являются точными маппингами C-типов из:
//! - `cpcsp/CSP_WinDef.h` — базовые Windows-типы
//! - `cpcsp/CSP_WinCrypt.h` — криптографические структуры
//! - `cpcsp/CSP_WinBase.h` — FILETIME, SYSTEMTIME
//! - `cpcsp/cspvtable.h` — VTABLEPROVSTRUC
//!
//! Все структуры используют `#[repr(C)]` для guarantees layout-совместимости с C.
//! Размеры и смещения полей проверены тестами (см. `tests/layout_tests.rs`).

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use std::os::raw::{c_char, c_int, c_void};

// ---------------------------------------------------------------------------
// Скалярные типы (CSP_WinDef.h)
// ---------------------------------------------------------------------------

/// Windows BOOL — это `int` (4 байта), **не** `bool`.
/// TRUE = 1, FALSE = 0.
/// Источник: CSP_WinDef.h:157 — `typedef int BOOL;`
pub type BOOL = c_int;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

/// unsigned long (4 bytes).
/// Источник: CSP_WinDef.h:150 — `typedef unsigned int DWORD;`
pub type DWORD = u32;

/// unsigned int (4 bytes).
/// Источник: CSP_WinDef.h:156 — `typedef unsigned int UINT;`
pub type UINT = u32;

/// unsigned short (2 bytes).
/// Источник: CSP_WinDef.h:159 — `typedef unsigned short WORD;`
pub type WORD = u16;

/// unsigned char (1 byte).
/// Источник: CSP_WinDef.h:158 — `typedef unsigned char BYTE;`
pub type BYTE = u8;

/// int (4 bytes).
/// Источник: CSP_WinDef.h:149 — `typedef int LONG;`
pub type LONG = i32;

/// Algorithm identifier (4 bytes).
/// Источник: CSP_WinCrypt.h:199 — `typedef unsigned int ALG_ID;`
pub type ALG_ID = u32;

/// HRESULT — код возврата (4 bytes).
/// Источник: CSP_WinDef.h:153 — `typedef LONG HRESULT;`
pub type HRESULT = LONG;

/// Размер указателя. На amd64 = 8, на x86 = 4.
/// Источник: CSP_WinDef.h:283 — `typedef unsigned long long ULONG_PTR;`
pub type ULONG_PTR = usize;

/// Аналогично ULONG_PTR.
/// Источник: CSP_WinDef.h:293 — `typedef ULONG_PTR DWORD_PTR;`
pub type DWORD_PTR = usize;

/// SIZE_T — размер объекта в памяти.
/// Источник: CSP_WinDef.h:509 — `typedef ULONG_PTR SIZE_T;`
pub type SIZE_T = usize;

// ---------------------------------------------------------------------------
// Указатели и строки (CSP_WinDef.h)
// ---------------------------------------------------------------------------

/// Указатель на DWORD.
pub type PDWORD = *mut DWORD;

/// Указатель на BYTE.
pub type PBYTE = *mut BYTE;

/// Указатель на const BYTE.
pub type LPCBYTE = *const BYTE;

/// Указатель на void.
pub type LPVOID = *mut c_void;

/// Const void pointer.
pub type LPCVOID = *const c_void;

/// LPSTR — mutable указатель на ANSI-строку.
/// Источник: CSP_WinDef.h:321 — `typedef CHAR *LPSTR;`
pub type LPSTR = *mut c_char;

/// LPCSTR — указатель на ANSI-строку (const).
/// Источник: CSP_WinDef.h:318 — `typedef CONST CHAR *LPCSTR;`
pub type LPCSTR = *const c_char;

/// LPCWSTR — указатель на Unicode (UTF-16) строку (const).
/// Источник: CSP_WinDef.h:226 — `typedef CONST wchar_t *LPCWSTR;`
pub type LPCWSTR = *const u16;

/// LPWSTR — mutable указатель на Unicode строку.
/// Источник: CSP_WinDef.h:323 — `typedef WCHAR *LPWSTR;`
pub type LPWSTR = *mut u16;

// ---------------------------------------------------------------------------
// Дескрипторы (HCRYPTPROV, HCRYPTKEY, HCRYPTHASH)
// ---------------------------------------------------------------------------

/// Дескриптор криптографического провайдера.
/// Источник: CSP_WinCrypt.h:246 — `typedef ULONG_PTR HCRYPTPROV;`
pub type HCRYPTPROV = ULONG_PTR;

/// Дескриптор криптографического ключа.
/// Источник: CSP_WinCrypt.h:247 — `typedef ULONG_PTR HCRYPTKEY;`
pub type HCRYPTKEY = ULONG_PTR;

/// Дескриптор хеш-объекта.
/// Источник: CSP_WinCrypt.h:248 — `typedef ULONG_PTR HCRYPTHASH;`
pub type HCRYPTHASH = ULONG_PTR;

/// Дескриптор хранилища сертификатов (opaque void*).
/// Источник: CSP_WinCrypt.h:2290 — `typedef void *HCERTSTORE;`
pub type HCERTSTORE = *mut c_void;

/// Дескриптор криптографического сообщения (opaque void*).
/// Источник: CSP_WinCrypt.h:2289 — `typedef void *HCRYPTMSG;`
pub type HCRYPTMSG = *mut c_void;

/// HWND — дескриптор окна (не используется на Linux, но нужен для layout).
/// Источник: CSP_WinDef.h:264 — `DECLARE_HANDLE(HWND);`
pub type HWND = *mut c_void;

/// HMODULE — дескриптор модуля.
/// Источник: CSP_WinDef.h:265 — `typedef HINSTANCE HMODULE;`
pub type HMODULE = *mut c_void;

/// HLOCAL — дескриптор локальной памяти.
/// Источник: CSP_WinDef.h:680 — `typedef void *HLOCAL;`
pub type HLOCAL = *mut c_void;

/// Дескриптор движка цепочки сертификатов.
/// Источник: CSP_WinCrypt.h:8218 — `DECLARE_HANDLE(HCERTCHAINENGINE);`
pub type HCERTCHAINENGINE = *mut c_void;

/// Дескриптор серверного OCSP-ответа.
/// Источник: CSP_WinCrypt.h:12960 — `DECLARE_HANDLE(HCERT_SERVER_OCSP_RESPONSE);`
pub type HCERT_SERVER_OCSP_RESPONSE = *mut c_void;

/// Набор функций OID (opaque).
/// Источник: CSP_WinCrypt.h:3225 — `DECLARE_HANDLE(HCRYPTOIDFUNCSET);`
pub type HCRYPTOIDFUNCSET = *mut c_void;

/// Адрес функции OID (opaque).
/// Источник: CSP_WinCrypt.h:3226 — `DECLARE_HANDLE(HCRYPTOIDFUNCADDR);`
pub type HCRYPTOIDFUNCADDR = *mut c_void;

// ---------------------------------------------------------------------------
// Opaque pointer typedefs для функций capi20
// ---------------------------------------------------------------------------

/// PCERT_NAME_BLOB = `CERT_NAME_BLOB *` (DataBlob).
pub type PCERT_NAME_BLOB = *mut DataBlob;

/// PCERT_RDN_VALUE_BLOB = `CERT_RDN_VALUE_BLOB *` (DataBlob).
pub type PCERT_RDN_VALUE_BLOB = *mut DataBlob;

/// PCERT_NAME_INFO = `CERT_NAME_INFO *`.
pub type PCERT_NAME_INFO = *mut CERT_NAME_INFO;

/// PCERT_ENHKEY_USAGE = `CERT_ENHKEY_USAGE *`.
pub type PCERT_ENHKEY_USAGE = *mut CERT_ENHKEY_USAGE;

/// PCRL_INFO = `CRL_INFO *`.
pub type PCRL_INFO = *mut CRL_INFO;

/// PCRYPT_PIN_CALLBACK — callback для PIN-кода (CryptoPro extension).
/// Источник: StoreUtil.h:96
pub type CRYPT_PIN_CALLBACK = extern "C" fn(pin: *mut i8, len: usize, arg: *mut c_void) -> BOOL;

/// PCCRYPT_OID_INFO — const pointer на CRYPT_OID_INFO.
pub type PCCRYPT_OID_INFO = *const CRYPT_OID_INFO;

/// PCRYPT_URL_ARRAY.
pub type PCRYPT_URL_ARRAY = *mut CRYPT_URL_ARRAY;

/// PCRYPT_URL_INFO.
pub type PCRYPT_URL_INFO = *mut CRYPT_URL_INFO;

/// PCRYPT_ENCODE_PARA (opaque).
pub type PCRYPT_ENCODE_PARA = *const c_void;

/// PCRYPT_DECODE_PARA (opaque).
pub type PCRYPT_DECODE_PARA = *mut c_void;

// ---------------------------------------------------------------------------
// Структуры времени (CSP_WinBase.h)
// ---------------------------------------------------------------------------

/// Windows FILETIME — 100-наносекундные интервалы с 1 января 1601.
/// Источник: CSP_WinBase.h:27-31
/// Layout: { dwLowDateTime: DWORD, dwHighDateTime: DWORD } = 8 bytes
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FILETIME {
    pub dw_low_date_time: DWORD,
    pub dw_high_date_time: DWORD,
}

/// Windows SYSTEMTIME — календарное время.
/// Источник: CSP_WinBase.h:43-52
/// Layout: { wYear..wMilliseconds: WORD * 8 } = 16 bytes
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SYSTEMTIME {
    pub w_year: WORD,
    pub w_month: WORD,
    pub w_day_of_week: WORD,
    pub w_day: WORD,
    pub w_hour: WORD,
    pub w_minute: WORD,
    pub w_second: WORD,
    pub w_milliseconds: WORD,
}

// ---------------------------------------------------------------------------
// Blob-типы (CSP_WinCrypt.h:1233-1252)
// ---------------------------------------------------------------------------

/// Универсальный бинарный блоб.
/// Используется как основа для всех blob-типов:
/// `CRYPT_INTEGER_BLOB`, `CRYPT_DATA_BLOB`, `CRYPT_HASH_BLOB`,
/// `CRYPT_DER_BLOB`, `CRYPT_ATTR_BLOB`, `CERT_NAME_BLOB`, и т.д.
///
/// Источник: CSP_WinCrypt.h:1233-1252
/// Layout: { cbData: DWORD(4) + pad(4), pbData: *mut BYTE(8) } = 16 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct DataBlob {
    pub cb_data: DWORD,
    pub pb_data: *mut BYTE,
}

impl DataBlob {
    pub fn new_empty() -> Self {
        Self {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        }
    }
}

/// Алиасы для разных用途 (все маппятся на ту же структуру).
///
/// Источник: CSP_WinCrypt.h:1240-1252
pub type CRYPT_INTEGER_BLOB = DataBlob;
pub type CRYPT_UINT_BLOB = DataBlob;
pub type CRYPT_OBJID_BLOB = DataBlob;
pub type CERT_NAME_BLOB = DataBlob;
pub type CERT_RDN_VALUE_BLOB = DataBlob;
pub type CERT_BLOB = DataBlob;
pub type CRL_BLOB = DataBlob;
pub type DATA_BLOB = DataBlob;
pub type CRYPT_DATA_BLOB = DataBlob;
pub type CRYPT_HASH_BLOB = DataBlob;
pub type CRYPT_DIGEST_BLOB = DataBlob;
pub type CRYPT_DER_BLOB = DataBlob;
pub type CRYPT_ATTR_BLOB = DataBlob;

// ---------------------------------------------------------------------------
// CRYPT_BIT_BLOB (CSP_WinCrypt.h:1267-1271)
// ---------------------------------------------------------------------------

/// Бинарный блоб с информацией о неиспользованных битах.
/// Используется для UniqueId в сертификатах и Signature.
///
/// Источник: CSP_WinCrypt.h:1267-1271
/// Layout: { cbData: DWORD(4) + pad(4), pbData: *mut BYTE(8), cUnusedBits: DWORD(4) + pad(4) } = 24 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_BIT_BLOB {
    pub cb_data: DWORD,
    pub pb_data: *mut BYTE,
    pub c_unused_bits: DWORD,
}

// ---------------------------------------------------------------------------
// CRYPT_ALGORITHM_IDENTIFIER (CSP_WinCrypt.h:1279-1282)
// ---------------------------------------------------------------------------

/// Идентификатор алгоритма: OID + опциональные параметры (ASN.1 encoded).
///
/// Источник: CSP_WinCrypt.h:1279-1282
/// Layout: { pszObjId: *const c_char(8), Parameters: DataBlob(16) } = 24 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_ALGORITHM_IDENTIFIER {
    pub psz_obj_id: LPCSTR,
    pub parameters: DataBlob,
}

// ---------------------------------------------------------------------------
// BLOBHEADER / PUBLICKEYSTRUC (CSP_WinCrypt.h:1180-1212)
// ---------------------------------------------------------------------------

/// Заголовок ключевого блоба.
/// Описывает тип ключа (PUBLICKEYBLOB, PRIVATEKEYBLOB, SIMPLEBLOB)
/// и алгоритм.
///
/// Источник: CSP_WinCrypt.h:1180-1212
/// Layout: { bType: BYTE(1), bVersion: BYTE(1), reserved: WORD(2), aiKeyAlg: ALG_ID(4) } = 8 bytes
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BLOBHEADER {
    pub b_type: BYTE,
    pub b_version: BYTE,
    pub reserved: WORD,
    pub ai_key_alg: ALG_ID,
}

// ---------------------------------------------------------------------------
// RSAPUBKEY (CSP_WinCrypt.h:1158-1163)
// ---------------------------------------------------------------------------

/// Заголовок публичного RSA-ключа.
/// После этой структуры в памяти идёт модуль (modulus).
///
/// Источник: CSP_WinCrypt.h:1158-1163
/// Layout: { magic: DWORD(4), bitlen: DWORD(4), pubexp: DWORD(4) } = 12 bytes
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RSAPUBKEY {
    pub magic: DWORD,
    pub bitlen: DWORD,
    pub pubexp: DWORD,
}

// ---------------------------------------------------------------------------
// DHPUBKEY / DSSPUBKEY (CSP_WinCrypt.h:1214-1217)
// ---------------------------------------------------------------------------

/// Заголовок публичного DH/DSS/KEA/TEK ключа.
///
/// Источник: CSP_WinCrypt.h:1214-1217
/// Layout: { magic: DWORD(4), bitlen: DWORD(4) } = 8 bytes
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DH_DSS_PUBKEY {
    pub magic: DWORD,
    pub bitlen: DWORD,
}

// ---------------------------------------------------------------------------
// HMAC_Info (CSP_WinCrypt.h:1115-1121)
// ---------------------------------------------------------------------------

/// Информация для HMAC.
///
/// Источник: CSP_WinCrypt.h:1115-1121
/// Layout: { HashAlgid: ALG_ID(4) + pad(4), pbInnerString: *mut BYTE(8),
///           cbInnerString: DWORD(4) + pad(4), pbOuterString: *mut BYTE(8),
///           cbOuterString: DWORD(4) + pad(4) } = 40 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct HMAC_INFO {
    pub hash_alg_id: ALG_ID,
    pub pb_inner_string: *mut BYTE,
    pub cb_inner_string: DWORD,
    pub pb_outer_string: *mut BYTE,
    pub cb_outer_string: DWORD,
}

// ---------------------------------------------------------------------------
// SCHANNEL_ALG (CSP_WinCrypt.h:1124-1130)
// ---------------------------------------------------------------------------

/// Алгоритм для Secure Channel.
///
/// Источник: CSP_WinCrypt.h:1124-1130
/// Layout: { dwStrength: DWORD(4), algId: ALG_ID(4), dwFlags: DWORD(4) } = 12 bytes
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SCHANNEL_ALG {
    pub dw_strength: DWORD,
    pub alg_id: ALG_ID,
    pub dw_flags: DWORD,
}

// ---------------------------------------------------------------------------
// PROV_ENUMALGS (CSP_WinCrypt.h:1139-1144)
// ---------------------------------------------------------------------------

/// Информация об алгоритме при перечислении провайдера.
///
/// Источник: CSP_WinCrypt.h:1139-1144
/// Layout: { aiAlgid: DWORD(4), dwBitLen: DWORD(4), dwNameLen: DWORD(4),
///           szName: [c_char; 20] } = 32 bytes
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PROV_ENUMALGS {
    pub ai_algid: ALG_ID,
    pub dw_bit_len: DWORD,
    pub dw_name_len: DWORD,
    pub sz_name: [c_char; 20],
}

// ---------------------------------------------------------------------------
// PROV_ENUMALGS_EX (CSP_WinCrypt.h:1146-1156)
// ---------------------------------------------------------------------------

/// Расширенная информация об алгоритме.
///
/// Источник: CSP_WinCrypt.h:1146-1156
/// Layout: { aiAlgid: DWORD(4), dwDefaultLen: DWORD(4), dwMinLen: DWORD(4),
///           dwMaxLen: DWORD(4), dwProtocols: DWORD(4), dwNameLen: DWORD(4),
///           szName: [c_char; 20], dwLongNameLen: DWORD(4),
///           szLongName: [c_char; 40] } = 88 bytes
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PROV_ENUMALGS_EX {
    pub ai_algid: ALG_ID,
    pub dw_default_len: DWORD,
    pub dw_min_len: DWORD,
    pub dw_max_len: DWORD,
    pub dw_protocols: DWORD,
    pub dw_name_len: DWORD,
    pub sz_name: [c_char; 20],
    pub dw_long_name_len: DWORD,
    pub sz_long_name: [c_char; 40],
}

// ---------------------------------------------------------------------------
// CMS_DH_KEY_INFO (CSP_WinCrypt.h:1255-1261)
// ---------------------------------------------------------------------------

/// Информация о DH-ключе для CMS.
///
/// Источник: CSP_WinCrypt.h:1255-1261
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CMS_DH_KEY_INFO {
    pub dw_version: DWORD,
    pub alg_id: ALG_ID,
    pub psz_content_enc_obj_id: LPCSTR,
    pub pub_info: DataBlob,
    pub p_reserved: *mut c_void,
}

// ---------------------------------------------------------------------------
// CERT_EXTENSION (CSP_WinCrypt.h:1499-1514)
// ---------------------------------------------------------------------------

/// Расширение сертификата (X.509 extension).
///
/// Источник: CSP_WinCrypt.h:1499-1514
/// Layout: { pszObjId: LPCSTR(8), fCritical: BOOL(4) + pad(4),
///           Value: DataBlob(16) } = 32 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_EXTENSION {
    pub psz_obj_id: LPCSTR,
    pub f_critical: BOOL,
    pub value: DataBlob,
}

// ---------------------------------------------------------------------------
// CERT_EXTENSIONS (CSP_WinCrypt.h:2270-2273)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CRYPT_ATTRIBUTE (CSP_WinCrypt.h:1531-1535)
// ---------------------------------------------------------------------------

/// ASN.1 атрибут (OID + значения).
///
/// Источник: CSP_WinCrypt.h:1531-1535
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_ATTRIBUTE {
    pub psz_obj_id: LPCSTR,
    pub c_value: DWORD,
    pub rg_value: *mut DataBlob,
}

// ---------------------------------------------------------------------------
// CRYPT_ATTRIBUTES (CSP_WinCrypt.h:1537-1540)
// ---------------------------------------------------------------------------

/// Коллекция атрибутов.
///
/// Источник: CSP_WinCrypt.h:1537-1540
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_ATTRIBUTES {
    pub c_attr: DWORD,
    pub rg_attr: *mut CRYPT_ATTRIBUTE,
}

// ---------------------------------------------------------------------------
// CRYPT_ATTRIBUTE_TYPE_VALUE (CSP_WinCrypt.h:1521-1524)
// ---------------------------------------------------------------------------

/// ASN.1 атрибут с decoded значением.
///
/// Источник: CSP_WinCrypt.h:1521-1524
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_ATTRIBUTE_TYPE_VALUE {
    pub psz_obj_id: LPCSTR,
    pub c_value: DWORD,
    pub rg_value: *mut DataBlob,
}

// ---------------------------------------------------------------------------
// CERT_RDN_ATTR (CSP_WinCrypt.h:1548-1552)
// ---------------------------------------------------------------------------

/// Атрибут Relative Distinguished Name.
///
/// Источник: CSP_WinCrypt.h:1548-1552
/// Layout: { pszObjId: LPCSTR(8), dwValueType: DWORD(4) + pad(4),
///           Value: DataBlob(16) } = 32 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_RDN_ATTR {
    pub psz_obj_id: LPCSTR,
    pub dw_value_type: DWORD,
    pub value: DataBlob,
}

// Типы значений CERT_RDN_ATTR
/// Источник: CSP_WinCrypt.h
pub const CERT_RDN_NUMERIC_STRING: DWORD = 3;
pub const CERT_RDN_PRINTABLE_STRING: DWORD = 4;
pub const CERT_RDN_TELETEX_STRING: DWORD = 5;
pub const CERT_RDN_T61_STRING: DWORD = 5;
pub const CERT_RDN_VIDEOTEX_STRING: DWORD = 6;
pub const CERT_RDN_IA5_STRING: DWORD = 7;
pub const CERT_RDN_GRAPHIC_STRING: DWORD = 8;
pub const CERT_RDN_VISIBLE_STRING: DWORD = 9;
pub const CERT_RDN_ISO646_STRING: DWORD = 9;
pub const CERT_RDN_BMP_STRING: DWORD = 10;
pub const CERT_RDN_UTF8_STRING: DWORD = 12;
pub const CERT_RDN_ENCODED_BLOB: DWORD = 1;
pub const CERT_RDN_OCTET_STRING: DWORD = 2;

// ---------------------------------------------------------------------------
// CERT_RDN (CSP_WinCrypt.h:1737-1740)
// ---------------------------------------------------------------------------

/// Relative Distinguished Name — набор атрибутов.
///
/// Источник: CSP_WinCrypt.h:1737-1740
/// Layout: { cRDNAttr: DWORD(4) + pad(4), prgRDNAttr: *mut CERT_RDN_ATTR(8) } = 16 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_RDN {
    pub c_rdn_attr: DWORD,
    pub prg_rdn_attr: *mut CERT_RDN_ATTR,
}

// ---------------------------------------------------------------------------
// CERT_NAME_INFO (CSP_WinCrypt.h:1746-1749)
// ---------------------------------------------------------------------------

/// Decoded X.500 имя.
///
/// Источник: CSP_WinCrypt.h:1746-1749
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_NAME_INFO {
    pub c_rdn: DWORD,
    pub rg_rdn: *mut CERT_RDN,
}

// ---------------------------------------------------------------------------
// CERT_NAME_VALUE (CSP_WinCrypt.h:1757-1760)
// ---------------------------------------------------------------------------

/// Decoded X.500 NameValue.
///
/// Источник: CSP_WinCrypt.h:1757-1760
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_NAME_VALUE {
    pub dw_value_type: DWORD,
    pub value: DataBlob,
}

// ---------------------------------------------------------------------------
// CERT_PUBLIC_KEY_INFO (CSP_WinCrypt.h:1768-1771)
// ---------------------------------------------------------------------------

/// Публичный ключ сертификата.
///
/// Источник: CSP_WinCrypt.h:1768-1771
/// Layout: { Algorithm: CRYPT_ALGORITHM_IDENTIFIER(24), PublicKey: CRYPT_BIT_BLOB(24) } = 48 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_PUBLIC_KEY_INFO {
    pub algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub public_key: CRYPT_BIT_BLOB,
}

// ---------------------------------------------------------------------------
// CERT_RDN_VALUE_BLOB aliases (CSP_WinCrypt.h)
// ---------------------------------------------------------------------------

// Уже определены как алиасы DataBlob выше.

// ---------------------------------------------------------------------------
// CERT_INFO (CSP_WinCrypt.h:2228-2241)
// ---------------------------------------------------------------------------

/// Decoded information stored in a certificate.
///
/// Источник: CSP_WinCrypt.h:2228-2241
/// Layout (208 bytes): проверено тестом.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_INFO {
    pub dw_version: DWORD,
    _pad0: [u8; 4], // padding after dwVersion (offset 4→8)
    pub serial_number: CRYPT_INTEGER_BLOB,
    pub signature_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub issuer: CERT_NAME_BLOB,
    pub not_before: FILETIME,
    pub not_after: FILETIME,
    pub subject: CERT_NAME_BLOB,
    pub subject_public_key_info: CERT_PUBLIC_KEY_INFO,
    pub issuer_unique_id: CRYPT_BIT_BLOB,
    pub subject_unique_id: CRYPT_BIT_BLOB,
    pub c_extension: DWORD,
    _pad1: [u8; 4], // padding before rgExtension (offset 196→200)
    pub rg_extension: *mut CERT_EXTENSION,
}

// ---------------------------------------------------------------------------
// CERT_SIGNED_CONTENT_INFO (CSP_WinCrypt.h:2282-2286)
// ---------------------------------------------------------------------------

/// Подписанное ASN.1 содержимое (certificate, CRL, request).
///
/// Источник: CSP_WinCrypt.h:2282-2286
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_SIGNED_CONTENT_INFO {
    pub to_be_signed: DataBlob,
    pub signature_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub signature: CRYPT_BIT_BLOB,
}

// ---------------------------------------------------------------------------
// CERT_CONTEXT (CSP_WinCrypt.h:2301-2308)
// ---------------------------------------------------------------------------

/// Контекст сертификата — основная единица работы с сертификатами.
/// Возвращается функциями CertFindCertificateInStore и т.д.
/// Должен освобождаться через `CertFreeCertificateContext`.
///
/// Источник: CSP_WinCrypt.h:2301-2308
/// Layout (40 bytes): проверено тестом.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_CONTEXT {
    pub dw_cert_encoding_type: DWORD,
    _pad0: [u8; 4], // padding (offset 4→8)
    pub pb_cert_encoded: *mut BYTE,
    pub cb_cert_encoded: DWORD,
    _pad1: [u8; 4], // padding (offset 20→24)
    pub p_cert_info: *mut CERT_INFO,
    pub h_cert_store: HCERTSTORE,
}

/// Const version — для возврата из функций.
pub type PCCERT_CONTEXT = *const CERT_CONTEXT;

/// Mutable version — для внутреннего использования.
pub type PCERT_CONTEXT = *mut CERT_CONTEXT;

// ---------------------------------------------------------------------------
// CERT_REQUEST_INFO (CSP_WinCrypt.h:2316-2322)
// ---------------------------------------------------------------------------

/// Информация о запросе на сертификат (CSR).
///
/// Источник: CSP_WinCrypt.h:2316-2322
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_REQUEST_INFO {
    pub dw_version: DWORD,
    _pad0: [u8; 4],
    pub subject: CERT_NAME_BLOB,
    pub subject_public_key_info: CERT_PUBLIC_KEY_INFO,
    pub c_attribute: DWORD,
    _pad1: [u8; 4],
    pub rg_attribute: *mut CRYPT_ATTRIBUTE,
}

// ---------------------------------------------------------------------------
// CRL_ENTRY (CSP_WinCrypt.h:2334-2339)
// ---------------------------------------------------------------------------

/// Запись в CRL (Certificate Revocation List).
///
/// Источник: CSP_WinCrypt.h:2334-2339
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRL_ENTRY {
    pub serial_number: CRYPT_INTEGER_BLOB,
    pub revocation_date: FILETIME,
    pub c_extension: DWORD,
    _pad0: [u8; 4],
    pub rg_extension: *mut CERT_EXTENSION,
}

// ---------------------------------------------------------------------------
// CRL_INFO (CSP_WinCrypt.h:2347-2357)
// ---------------------------------------------------------------------------

/// Decoded CRL information.
///
/// Источник: CSP_WinCrypt.h:2347-2357
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRL_INFO {
    pub dw_version: DWORD,
    _pad0: [u8; 4],
    pub signature_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub issuer: CERT_NAME_BLOB,
    pub this_update: FILETIME,
    pub next_update: FILETIME,
    pub c_crl_entry: DWORD,
    _pad1: [u8; 4],
    pub rg_crl_entry: *mut CRL_ENTRY,
    pub c_extension: DWORD,
    _pad2: [u8; 4],
    pub rg_extension: *mut CERT_EXTENSION,
}

// ---------------------------------------------------------------------------
// CRL_CONTEXT (CSP_WinCrypt.h:2374-2381)
// ---------------------------------------------------------------------------

/// Контекст CRL.
///
/// Источник: CSP_WinCrypt.h:2374-2381
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRL_CONTEXT {
    pub dw_cert_encoding_type: DWORD,
    _pad0: [u8; 4],
    pub pb_crl_encoded: *mut BYTE,
    pub cb_crl_encoded: DWORD,
    _pad1: [u8; 4],
    pub p_crl_info: *mut CRL_INFO,
    pub h_cert_store: HCERTSTORE,
}

pub type PCCRL_CONTEXT = *const CRL_CONTEXT;

// ---------------------------------------------------------------------------
// CTL_USAGE / CERT_ENHKEY_USAGE (CSP_WinCrypt.h:2390-2394)
// ---------------------------------------------------------------------------

/// Usage of a CTL or Enhanced Key Usage extension.
///
/// Источник: CSP_WinCrypt.h:2390-2394
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CTL_USAGE {
    pub c_usage_identifier: DWORD,
    _pad0: [u8; 4],
    pub rgpsz_usage_identifier: *mut LPCSTR,
}

pub type CERT_ENHKEY_USAGE = CTL_USAGE;

// ---------------------------------------------------------------------------
// CTL_ENTRY (CSP_WinCrypt.h:2399-2403)
// ---------------------------------------------------------------------------

/// Запись в CTL.
///
/// Источник: CSP_WinCrypt.h:2399-2403
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CTL_ENTRY {
    pub subject_identifier: DataBlob,
    pub c_attribute: DWORD,
    _pad0: [u8; 4],
    pub rg_attribute: *mut CRYPT_ATTRIBUTE,
}

// ---------------------------------------------------------------------------
// CTL_INFO (CSP_WinCrypt.h:2408-2420)
// ---------------------------------------------------------------------------

/// Decoded CTL information.
///
/// Источник: CSP_WinCrypt.h:2408-2420
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CTL_INFO {
    pub dw_version: DWORD,
    _pad0: [u8; 4],
    pub subject_usage: CTL_USAGE,
    pub list_identifier: DataBlob,
    pub sequence_number: CRYPT_INTEGER_BLOB,
    pub this_update: FILETIME,
    pub next_update: FILETIME,
    pub subject_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub c_ctl_entry: DWORD,
    _pad1: [u8; 4],
    pub rg_ctl_entry: *mut CTL_ENTRY,
    pub c_extension: DWORD,
    _pad2: [u8; 4],
    pub rg_extension: *mut CERT_EXTENSION,
}

// ---------------------------------------------------------------------------
// CTL_CONTEXT (CSP_WinCrypt.h:2438-2448)
// ---------------------------------------------------------------------------

/// Контекст CTL.
///
/// Источник: CSP_WinCrypt.h:2438-2448
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CTL_CONTEXT {
    pub dw_msg_and_cert_encoding_type: DWORD,
    _pad0: [u8; 4],
    pub pb_ctl_encoded: *mut BYTE,
    pub cb_ctl_encoded: DWORD,
    _pad1: [u8; 4],
    pub p_ctl_info: *mut CTL_INFO,
    pub h_cert_store: HCERTSTORE,
    pub h_crypt_msg: HCRYPTMSG,
    pub pb_ctl_content: *mut BYTE,
    pub cb_ctl_content: DWORD,
    _pad2: [u8; 4],
}

// ---------------------------------------------------------------------------
// CRYPT_KEY_PROV_PARAM (CSP_WinCrypt.h:3182-3187)
// ---------------------------------------------------------------------------

/// Параметр провайдера ключа.
///
/// Источник: CSP_WinCrypt.h:3182-3187
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_KEY_PROV_PARAM {
    pub dw_param: DWORD,
    pub pb_data: *mut BYTE,
    pub cb_data: DWORD,
    pub dw_flags: DWORD,
}

// ---------------------------------------------------------------------------
// CRYPT_KEY_PROV_INFO (CSP_WinCrypt.h:3189-3197)
// ---------------------------------------------------------------------------

/// Информация о провайдере ключа (для CERT_KEY_PROV_INFO_PROP_ID).
/// Поля передаются в `CryptAcquireContext` для получения HCRYPTPROV.
///
/// Источник: CSP_WinCrypt.h:3189-3197
/// Layout (48 bytes): проверено тестом.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_KEY_PROV_INFO {
    pub pwsz_container_name: LPWSTR,
    pub pwsz_prov_name: LPWSTR,
    pub dw_prov_type: DWORD,
    pub dw_flags: DWORD,
    pub c_prov_param: DWORD,
    _pad0: [u8; 4],
    pub rg_prov_param: *mut CRYPT_KEY_PROV_PARAM,
    pub dw_key_spec: DWORD,
    _pad1: [u8; 4],
}

// ---------------------------------------------------------------------------
// VTABLEPROVSTRUC (cspvtable.h:79-87)
// ---------------------------------------------------------------------------

/// VTable для callback-ов провайдера.
///
/// Источник: cspvtable.h:79-87
#[repr(C)]
#[derive(Clone, Debug)]
pub struct VTABLEPROVSTRUC {
    pub version: DWORD,
    pub func_verify_image: *const c_void,    // CRYPT_VERIFY_IMAGE_A
    pub func_return_hwnd: *const c_void,     // CRYPT_RETURN_HWND
    pub dw_prov_type: DWORD,
    _pad0: [u8; 4],
    pub pb_context_info: *mut BYTE,
    pub cb_context_info: DWORD,
    _pad1: [u8; 4],
    pub psz_prov_name: LPSTR,
}

// ---------------------------------------------------------------------------
// CRYPT_PRIVATE_KEY_INFO (CSP_WinCrypt.h:1776-1790)
// ---------------------------------------------------------------------------

/// Decoded private key information.
///
/// Источник: CSP_WinCrypt.h:1776-1790
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_PRIVATE_KEY_INFO {
    pub version: DWORD,
    _pad0: [u8; 4],
    pub algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub private_key: DataBlob,
    pub p_attributes: *mut CRYPT_ATTRIBUTES,
}

// ---------------------------------------------------------------------------
// CERT_BASIC_CONSTRAINTS2_INFO (CSP_WinCrypt.h:1790-1794)
// ---------------------------------------------------------------------------

/// Decoded basic constraints extension.
///
/// Источник: CSP_WinCrypt.h:1790-1794
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CERT_BASIC_CONSTRAINTS2_INFO {
    pub f_ca: BOOL,
    pub path_length_constraint: DWORD,
}

// ---------------------------------------------------------------------------
// Типы callback-функций
// ---------------------------------------------------------------------------

/// Callback для CertEnumSystemStore.
/// Источник: CSP_WinCrypt.h:7113
pub type PFN_CERT_ENUM_SYSTEM_STORE =
    *const c_void; // функция: extern "C" fn(*mut c_void, DWORD, *const u16, DWORD, *mut c_void, *mut c_void) -> BOOL

/// Callback для CertEnumPhysicalStore.
/// Источник: CSP_WinCrypt.h:7143
pub type PFN_CERT_ENUM_PHYSICAL_STORE = *const c_void;

/// Callback для CertEnumSystemStoreLocation.
/// Источник: CSP_WinCrypt.h:7081
pub type PFN_CERT_ENUM_SYSTEM_STORE_LOCATION = *const c_void;

/// Callback для CryptMsg stream output.
/// Источник: CSP_WinCrypt.h:10502
pub type PFN_CMSG_STREAM_OUTPUT =
    *const c_void; // extern "C" fn(*const c_void, *mut BYTE, DWORD, BOOL) -> BOOL

/// Callback для получения сертификата подписанта.
/// Источник: CSP_WinCrypt.h:12064
pub type PFN_CRYPT_GET_SIGNER_CERTIFICATE = *const c_void;

// ---------------------------------------------------------------------------
// Pointer type aliases для capi20 функций
// ---------------------------------------------------------------------------

/// PCCERT_EXTENSIONS = `const CERT_EXTENSIONS *`
pub type PCERT_EXTENSIONS = *const CERT_EXTENSIONS;

/// PCERT_CHAIN_PARA = `const CERT_CHAIN_PARA *`
pub type PCERT_CHAIN_PARA = *const CERT_CHAIN_PARA;

/// PCERT_REVOCATION_PARA = `const CERT_REVOCATION_PARA *`
pub type PCERT_REVOCATION_PARA = *const CERT_REVOCATION_PARA;

/// PCERT_REVOCATION_STATUS = `CERT_REVOCATION_STATUS *`
pub type PCERT_REVOCATION_STATUS = *mut CERT_REVOCATION_STATUS;

/// PCERT_CHAIN_POLICY_PARA = `const CERT_CHAIN_POLICY_PARA *`
pub type PCERT_CHAIN_POLICY_PARA = *const CERT_CHAIN_POLICY_PARA;

/// PCERT_CHAIN_POLICY_STATUS = `CERT_CHAIN_POLICY_STATUS *`
pub type PCERT_CHAIN_POLICY_STATUS = *mut CERT_CHAIN_POLICY_STATUS;

/// PCMSG_STREAM_INFO = `const CMSG_STREAM_INFO *`
pub type PCMSG_STREAM_INFO = *const CMSG_STREAM_INFO;

/// PCRYPT_OID_FUNC_ENTRY = `const CRYPT_OID_FUNC_ENTRY *`
pub type PCRYPT_OID_FUNC_ENTRY = *const CRYPT_OID_FUNC_ENTRY;

// ---------------------------------------------------------------------------
// CERT_USAGE_MATCH (CSP_WinCrypt.h:7912-7916)
// ---------------------------------------------------------------------------

/// Тип использования сертификата.
///
/// Источник: CSP_WinCrypt.h:7912-7916
/// Layout: { dwType: DWORD(4) + pad(4), Usage: CTL_USAGE(16) } = 24 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_USAGE_MATCH {
    pub dw_type: DWORD,
    _pad0: [u8; 4],
    pub usage: CTL_USAGE,
}

// ---------------------------------------------------------------------------
// CERT_EXTENSIONS (CSP_WinCrypt.h:2270-2273)
// ---------------------------------------------------------------------------

/// Набор расширений сертификата.
///
/// Источник: CSP_WinCrypt.h:2270-2273
/// Layout: { cExtension: DWORD(4) + pad(4), rgExtension: *mut CERT_EXTENSION(8) } = 16 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_EXTENSIONS {
    pub c_extension: DWORD,
    _pad0: [u8; 4],
    pub rg_extension: *mut CERT_EXTENSION,
}

// ---------------------------------------------------------------------------
// CERT_CHAIN_PARA (CSP_WinCrypt.h:7926-7949)
// ---------------------------------------------------------------------------

/// Параметры построения цепочки сертификатов.
///
/// Источник: CSP_WinCrypt.h:7926-7949
/// Layout: { cbSize: DWORD(4) + pad(4), RequestedUsage: CERT_USAGE_MATCH(24) } = 32 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_CHAIN_PARA {
    pub cb_size: DWORD,
    _pad0: [u8; 4],
    pub requested_usage: CERT_USAGE_MATCH,
}

// ---------------------------------------------------------------------------
// CERT_CHAIN_POLICY_PARA (CSP_WinCrypt.h:8223-8227)
// ---------------------------------------------------------------------------

/// Параметры политики цепочки сертификатов.
///
/// Источник: CSP_WinCrypt.h:8223-8227
/// Layout: { cbSize: DWORD(4), dwFlags: DWORD(4), pvExtraPolicyPara: *mut c_void(8) } = 16 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_CHAIN_POLICY_PARA {
    pub cb_size: DWORD,
    pub dw_flags: DWORD,
    pub pv_extra_policy_para: *mut c_void,
}

// ---------------------------------------------------------------------------
// CERT_CHAIN_POLICY_STATUS (CSP_WinCrypt.h:8234-8240)
// ---------------------------------------------------------------------------

/// Статус политики цепочки сертификатов.
///
/// Источник: CSP_WinCrypt.h:8234-8240
/// Layout: { cbSize, dwError, lChainIndex, lElementIndex: DWORD*4=16, pvExtraPolicyStatus: ptr(8) } = 24 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_CHAIN_POLICY_STATUS {
    pub cb_size: DWORD,
    pub dw_error: DWORD,
    pub l_chain_index: LONG,
    pub l_element_index: LONG,
    pub pv_extra_policy_status: *mut c_void,
}

// ---------------------------------------------------------------------------
// CERT_REVOCATION_PARA (CSP_WinCrypt.h:7374-7417)
// ---------------------------------------------------------------------------

/// Параметры проверки отозванности.
///
/// Источник: CSP_WinCrypt.h:7374-7417
/// Layout: { cbSize(4)+pad(4), pIssuerCert(8), cCertStore(4)+pad(4), rgCertStore(8),
///           hCrlStore(8), pftTimeToUse(8) } = 48 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_REVOCATION_PARA {
    pub cb_size: DWORD,
    _pad0: [u8; 4],
    pub p_issuer_cert: *const CERT_CONTEXT,
    pub c_cert_store: DWORD,
    _pad1: [u8; 4],
    pub rg_cert_store: *mut HCERTSTORE,
    pub h_crl_store: HCERTSTORE,
    pub pft_time_to_use: *mut FILETIME,
}

// ---------------------------------------------------------------------------
// CERT_REVOCATION_STATUS (CSP_WinCrypt.h:7434-7450)
// ---------------------------------------------------------------------------

/// Статус проверки отозванности.
///
/// Источник: CSP_WinCrypt.h:7434-7450
/// Layout: { cbSize, dwIndex, dwError, dwReason, fHasFreshnessTime, dwFreshnessTime } = 24 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_REVOCATION_STATUS {
    pub cb_size: DWORD,
    pub dw_index: DWORD,
    pub dw_error: DWORD,
    pub dw_reason: DWORD,
    pub f_has_freshness_time: BOOL,
    pub dw_freshness_time: DWORD,
}

// ---------------------------------------------------------------------------
// CERT_REVOCATION_CRL_INFO (CSP_WinCrypt.h:7333-7341)
// ---------------------------------------------------------------------------

/// CRL-информация для проверки отозванности.
///
/// Источник: CSP_WinCrypt.h:7333-7341
/// Layout: { cbSize(4)+pad(4), pBaseCrlContext(8), pDeltaCrlContext(8),
///           pCrlEntry(8), fDeltaCrlEntry(4)+pad(4) } = 40 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CERT_REVOCATION_CRL_INFO {
    pub cb_size: DWORD,
    _pad0: [u8; 4],
    pub p_base_crl_context: *const c_void, // PCCRL_CONTEXT
    pub p_delta_crl_context: *const c_void, // PCCRL_CONTEXT
    pub p_crl_entry: *mut c_void,           // PCRL_ENTRY
    pub f_delta_crl_entry: BOOL,
    _pad1: [u8; 4],
}

// ---------------------------------------------------------------------------
// CRYPT_SIGN_MESSAGE_PARA (CSP_WinCrypt.h:12123-12144)
// ---------------------------------------------------------------------------

/// Параметры подписи CMS-сообщения.
///
/// Источник: CSP_WinCrypt.h:12123-12144
/// Layout (базовая, без HAS_CMS_FIELDS): 120 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_SIGN_MESSAGE_PARA {
    pub cb_size: DWORD,
    pub dw_msg_encoding_type: DWORD,
    pub p_signing_cert: *const CERT_CONTEXT,
    pub hash_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub pv_hash_aux_info: *mut c_void,
    pub c_msg_cert: DWORD,
    pub _pad0: [u8; 4],
    pub rgp_msg_cert: *mut *const CERT_CONTEXT,
    pub c_msg_crl: DWORD,
    pub _pad1: [u8; 4],
    pub rgp_msg_crl: *mut *const c_void, // PCCRL_CONTEXT
    pub c_auth_attr: DWORD,
    pub _pad2: [u8; 4],
    pub rg_auth_attr: *mut CRYPT_ATTRIBUTE,
    pub c_unauth_attr: DWORD,
    pub _pad3: [u8; 4],
    pub rg_unauth_attr: *mut CRYPT_ATTRIBUTE,
    pub dw_flags: DWORD,
    pub dw_inner_content_type: DWORD,
}

// ---------------------------------------------------------------------------
// CRYPT_VERIFY_MESSAGE_PARA (CSP_WinCrypt.h:12174-12180)
// ---------------------------------------------------------------------------

/// Параметры проверки CMS-сообщения.
///
/// Источник: CSP_WinCrypt.h:12174-12180
/// Layout: 32 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_VERIFY_MESSAGE_PARA {
    pub cb_size: DWORD,
    pub dw_msg_and_cert_encoding_type: DWORD,
    pub h_crypt_prov: HCRYPTPROV,
    pub pfn_get_signer_certificate: PFN_CRYPT_GET_SIGNER_CERTIFICATE,
    pub pv_get_arg: *mut c_void,
}

// ---------------------------------------------------------------------------
// CRYPT_ENCRYPT_MESSAGE_PARA (CSP_WinCrypt.h:12221-12229)
// ---------------------------------------------------------------------------

/// Параметры шифрования CMS-сообщения.
///
/// Источник: CSP_WinCrypt.h:12221-12229
/// Layout: 56 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_ENCRYPT_MESSAGE_PARA {
    pub cb_size: DWORD,
    pub dw_msg_encoding_type: DWORD,
    pub h_crypt_prov: HCRYPTPROV,
    pub content_encryption_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub pv_encryption_aux_info: *mut c_void,
    pub dw_flags: DWORD,
    pub dw_inner_content_type: DWORD,
}

// ---------------------------------------------------------------------------
// CRYPT_DECRYPT_MESSAGE_PARA (CSP_WinCrypt.h:12255-12269)
// ---------------------------------------------------------------------------

/// Параметры дешифрования CMS-сообщения.
///
/// Источник: CSP_WinCrypt.h:12255-12269
/// Layout (базовая): 24 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_DECRYPT_MESSAGE_PARA {
    pub cb_size: DWORD,
    pub dw_msg_and_cert_encoding_type: DWORD,
    pub c_cert_store: DWORD,
    pub _pad0: [u8; 4],
    pub rgh_cert_store: *mut HCERTSTORE,
}

// ---------------------------------------------------------------------------
// CRYPT_OID_INFO (CSP_WinCrypt.h:2969-2977)
// ---------------------------------------------------------------------------

/// Информация об OID.
///
/// Источник: CSP_WinCrypt.h:2969-2977
/// Layout: 48 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_OID_INFO {
    pub cb_size: DWORD,
    _pad0: [u8; 4],
    pub psz_oid: *const c_char,
    pub pwsz_name: *const u16,
    pub dw_group_id: DWORD,
    pub alg_id: ALG_ID,
    pub extra_info: DataBlob,
}

// ---------------------------------------------------------------------------
// CRYPT_OID_FUNC_ENTRY (CSP_WinCrypt.h:2915-2918)
// ---------------------------------------------------------------------------

/// Запись функции OID.
///
/// Источник: CSP_WinCrypt.h:2915-2918
/// Layout: { pszOID: *const c_char(8), pvFuncAddr: *mut c_void(8) } = 16 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_OID_FUNC_ENTRY {
    pub psz_oid: *const c_char,
    pub pv_func_addr: *mut c_void,
}

// ---------------------------------------------------------------------------
// CMSG_STREAM_INFO (CSP_WinCrypt.h:10511-10515)
// ---------------------------------------------------------------------------

/// Параметры потока CMS-сообщения.
///
/// Источник: CSP_WinCrypt.h:10511-10515
/// Layout: { cbContent(4)+pad(4), pfnStreamOutput(8), pvArg(8) } = 24 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CMSG_STREAM_INFO {
    pub cb_content: DWORD,
    _pad0: [u8; 4],
    pub pfn_stream_output: PFN_CMSG_STREAM_OUTPUT,
    pub pv_arg: *mut c_void,
}

// ---------------------------------------------------------------------------
// CRYPT_URL_ARRAY (CSP_WinCrypt.h:12334-12337)
// ---------------------------------------------------------------------------

/// Массив URL.
///
/// Источник: CSP_WinCrypt.h:12334-12337
/// Layout: { cUrl(4)+pad(4), rgwszUrl(8) } = 16 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_URL_ARRAY {
    pub c_url: DWORD,
    _pad0: [u8; 4],
    pub rgwsz_url: *mut *mut u16,
}

// ---------------------------------------------------------------------------
// CRYPT_URL_INFO (CSP_WinCrypt.h:12339-12344)
// ---------------------------------------------------------------------------

/// Информация URL.
///
/// Источник: CSP_WinCrypt.h:12339-12344
/// Layout: { cbSize(4), dwSyncDeltaTime(4), cGroup(4)+pad(4), rgcGroupEntry(8) } = 24 bytes
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CRYPT_URL_INFO {
    pub cb_size: DWORD,
    pub dw_sync_delta_time: DWORD,
    pub c_group: DWORD,
    _pad0: [u8; 4],
    pub rgc_group_entry: *mut DWORD,
}
