//! FFI-объявления для libcapi20.so — CryptoAPI Extensions.
//!
//! Содержит 162 функции из расширенного CryptoAPI (Cert*, CryptMsg*, Crypt*,
//! CryptEncode*/CryptDecode*, CryptString*/CryptBinary*, PFX*, CPCrypt*/CPGet*,
//! LocalAlloc/LocalFree).
//!
//! Источники:
//! - `/opt/cprocsp/include/cpcsp/CSP_WinCrypt.h` — Cert*, CryptMsg*, Crypt*
//! - `/opt/cprocsp/include/cpcsp/CSP_WinDef.h` — LocalAlloc/LocalFree
//! - `/opt/cprocsp/include/capilite/CPCrypt.h` — CPCrypt*/CPGet*
//! - `/opt/cprocsp/include/capilite/StoreUtil.h` — CPCryptGetPinCallback, etc.
//!
//! Все функции используют `extern "C"` (cdecl на x86_64 Linux).
//! На x86_64 Linux WINAPI = macro() (пустой макрос), так что __stdcall
//! и cdecl идентичны.

use std::ffi::c_void;
use std::os::raw::{c_char, c_int, c_long};

use crate::raw_types::*;

// ---------------------------------------------------------------------------
// Opaque pointer types для параметров capi20 функций
// ---------------------------------------------------------------------------

/// PCCERT_CONTEXT = `const CERT_CONTEXT *`
pub type PCCERT_CONTEXT = *const CERT_CONTEXT;

/// PCCRL_CONTEXT = `const CRL_CONTEXT *`
pub type PCCRL_CONTEXT = *const CRL_CONTEXT;

/// PCERT_INFO = `CERT_INFO *`
pub type PCERT_INFO = *mut CERT_INFO;

/// PCCERT_CHAIN_CONTEXT (opaque — структура не определена в заголовках).
pub type PCCERT_CHAIN_CONTEXT = *const c_void;

/// PCERT_CHAIN_ENGINE_CONFIG (opaque).
pub type PCERT_CHAIN_ENGINE_CONFIG = *const c_void;

/// PCCERT_SERVER_OCSP_RESPONSE_CONTEXT (opaque).
pub type PCCERT_SERVER_OCSP_RESPONSE_CONTEXT = *const c_void;

/// PCMSG_SIGNER_ENCODE_INFO (opaque).
pub type PCMSG_SIGNER_ENCODE_INFO = *const c_void;

// ===========================================================================
// Cert* функции — работа с хранилищем сертификатов
// ===========================================================================

/// Открыть хранилище сертификатов.
///
/// Источник: CSP_WinCrypt.h:4132
extern "C" {
    pub fn CertOpenStore(
        lpsz_store_provider: *const c_char,
        dw_encoding_type: DWORD,
        h_crypt_prov: HCRYPTPROV,
        dw_flags: DWORD,
        pv_para: *const c_void,
    ) -> HCERTSTORE;
}

/// Открыть системное хранилище (ANSI-имя).
///
/// Источник: CSP_WinCrypt.h:4143
extern "C" {
    pub fn CertOpenSystemStoreA(
        h_prov: HCRYPTPROV,
        psz_subsystem_protocol: *const c_char,
    ) -> HCERTSTORE;
}

/// Открыть системное хранилище (Unicode-имя).
///
/// Источник: CSP_WinCrypt.h:4151
extern "C" {
    pub fn CertOpenSystemStoreW(
        h_prov: HCRYPTPROV,
        psz_subsystem_protocol: *const u16,
    ) -> HCERTSTORE;
}

/// Закрыть хранилище сертификатов.
///
/// Источник: CSP_WinCrypt.h:4753
extern "C" {
    pub fn CertCloseStore(h_cert_store: HCERTSTORE, dw_flags: DWORD) -> BOOL;
}

/// Дублировать дескриптор хранилища.
///
/// Источник: CSP_WinCrypt.h:4643
extern "C" {
    pub fn CertDuplicateStore(h_cert_store: HCERTSTORE) -> HCERTSTORE;
}

/// Управление хранилищем (lock/unlock).
///
/// Источник: CSP_WinCrypt.h:6584
extern "C" {
    pub fn CertControlStore(
        h_cert_store: HCERTSTORE,
        dw_flags: DWORD,
        dw_ctrl_type: DWORD,
        pv_ctrl_para: *const c_void,
    ) -> BOOL;
}

/// Сохранить хранилище на диск.
///
/// Источник: CSP_WinCrypt.h:4711
extern "C" {
    pub fn CertSaveStore(
        h_cert_store: HCERTSTORE,
        dw_encoding_type: DWORD,
        dw_save_as: DWORD,
        dw_save_to: DWORD,
        pv_save_to_para: *mut c_void,
        dw_flags: DWORD,
    ) -> BOOL;
}

/// Перечислить системные хранилища.
///
/// Источник: CSP_WinCrypt.h:7133
extern "C" {
    pub fn CertEnumSystemStore(
        dw_flags: DWORD,
        pv_system_store_location_para: *mut c_void,
        pv_arg: *mut c_void,
        pfn_enum: PFN_CERT_ENUM_SYSTEM_STORE,
    ) -> BOOL;
}

/// Перечислить физические хранилища.
///
/// Источник: CSP_WinCrypt.h:7159
extern "C" {
    pub fn CertEnumPhysicalStore(
        pv_system_store: *const c_void,
        dw_flags: DWORD,
        pv_arg: *mut c_void,
        pfn_enum: PFN_CERT_ENUM_PHYSICAL_STORE,
    ) -> BOOL;
}

/// Перечислить локации системных хранилищ.
///
/// Источник: CSP_WinCrypt.h:7093
extern "C" {
    pub fn CertEnumSystemStoreLocation(
        dw_flags: DWORD,
        pv_arg: *mut c_void,
        pfn_enum: PFN_CERT_ENUM_SYSTEM_STORE_LOCATION,
    ) -> BOOL;
}

/// Добавить хранилище в коллекцию.
///
/// Источник: CSP_WinCrypt.h:6565
extern "C" {
    pub fn CertAddStoreToCollection(
        h_collection_store: HCERTSTORE,
        h_sibling_store: HCERTSTORE,
        dw_update_flags: DWORD,
        dw_priority: DWORD,
    ) -> BOOL;
}

/// Удалить хранилище из коллекции.
///
/// Источник: CSP_WinCrypt.h:6575
extern "C" {
    pub fn CertRemoveStoreFromCollection(
        h_collection_store: HCERTSTORE,
        h_sibling_store: HCERTSTORE,
    );
}

// ---------------------------------------------------------------------------
// Cert* — сертификаты
// ---------------------------------------------------------------------------

/// Создать контекст сертификата из закодированного blobs.
///
/// Источник: CSP_WinCrypt.h:5239
extern "C" {
    pub fn CertCreateCertificateContext(
        dw_cert_encoding_type: DWORD,
        pb_cert_encoded: *const BYTE,
        cb_cert_encoded: DWORD,
    ) -> PCCERT_CONTEXT;
}

/// Дублировать контекст сертификата.
///
/// Источник: CSP_WinCrypt.h:5218
extern "C" {
    pub fn CertDuplicateCertificateContext(p_cert_context: PCCERT_CONTEXT) -> PCCERT_CONTEXT;
}

/// Освободить контекст сертификата.
///
/// Источник: CSP_WinCrypt.h:5254
extern "C" {
    pub fn CertFreeCertificateContext(p_cert_context: PCCERT_CONTEXT) -> BOOL;
}

/// Удалить сертификат из хранилища.
///
/// Источник: CSP_WinCrypt.h:6059
extern "C" {
    pub fn CertDeleteCertificateFromStore(p_cert_context: PCCERT_CONTEXT) -> BOOL;
}

/// Найти сертификат в хранилище.
///
/// Источник: CSP_WinCrypt.h:4831
extern "C" {
    pub fn CertFindCertificateInStore(
        h_cert_store: HCERTSTORE,
        dw_cert_encoding_type: DWORD,
        dw_find_flags: DWORD,
        dw_find_type: DWORD,
        pv_find_para: *const c_void,
        p_prev_cert_context: PCCERT_CONTEXT,
    ) -> PCCERT_CONTEXT;
}

/// Перечислить сертификаты в хранилище.
///
/// Источник: CSP_WinCrypt.h:4799
extern "C" {
    pub fn CertEnumCertificatesInStore(
        h_cert_store: HCERTSTORE,
        p_prev_cert_context: PCCERT_CONTEXT,
    ) -> PCCERT_CONTEXT;
}

/// Получить сертификат субъекта из хранилища.
///
/// Источник: CSP_WinCrypt.h:4773
extern "C" {
    pub fn CertGetSubjectCertificateFromStore(
        h_cert_store: HCERTSTORE,
        dw_cert_encoding_type: DWORD,
        p_cert_id: PCERT_INFO,
    ) -> PCCERT_CONTEXT;
}

/// Получить сертификат издателя из хранилища.
///
/// Источник: CSP_WinCrypt.h:5186
extern "C" {
    pub fn CertGetIssuerCertificateFromStore(
        h_cert_store: HCERTSTORE,
        p_subject_context: PCCERT_CONTEXT,
        p_prev_issuer_context: PCCERT_CONTEXT,
        pdw_flags: *mut DWORD,
    ) -> PCCERT_CONTEXT;
}

/// Добавить закодированный сертификат в хранилище.
///
/// Источник: CSP_WinCrypt.h:5907
extern "C" {
    pub fn CertAddEncodedCertificateToStore(
        h_cert_store: HCERTSTORE,
        dw_cert_encoding_type: DWORD,
        pb_cert_encoded: *const BYTE,
        cb_cert_encoded: DWORD,
        dw_add_disposition: DWORD,
        pp_store_context: *mut PCCERT_CONTEXT,
    ) -> BOOL;
}

/// Добавить контекст сертификата в хранилище.
///
/// Источник: CSP_WinCrypt.h:5976
extern "C" {
    pub fn CertAddCertificateContextToStore(
        h_cert_store: HCERTSTORE,
        p_cert_context: PCCERT_CONTEXT,
        dw_add_disposition: DWORD,
        pp_store_context: *mut PCCERT_CONTEXT,
    ) -> BOOL;
}

/// Добавить линк на сертификат в хранилище.
///
/// Источник: CSP_WinCrypt.h:6535
extern "C" {
    pub fn CertAddCertificateLinkToStore(
        h_cert_store: HCERTSTORE,
        p_cert_context: PCCERT_CONTEXT,
        dw_add_disposition: DWORD,
        pp_store_context: *mut PCCERT_CONTEXT,
    ) -> BOOL;
}

/// Добавить закодированный сертификат в системное хранилище (ANSI).
///
/// Источник: CSP_WinCrypt.h:4165
extern "C" {
    pub fn CertAddEncodedCertificateToSystemStoreA(
        sz_cert_store_name: *const c_char,
        pb_cert_encoded: *const BYTE,
        cb_cert_encoded: DWORD,
    ) -> BOOL;
}

/// Добавить закодированный сертификат в системное хранилище (Unicode).
///
/// Источник: CSP_WinCrypt.h:4174
extern "C" {
    pub fn CertAddEncodedCertificateToSystemStoreW(
        sz_cert_store_name: *const u16,
        pb_cert_encoded: *const BYTE,
        cb_cert_encoded: DWORD,
    ) -> BOOL;
}

/// Сериализовать элемент хранилища (сертификат).
///
/// Источник: CSP_WinCrypt.h:6147
extern "C" {
    pub fn CertSerializeCertificateStoreElement(
        p_cert_context: PCCERT_CONTEXT,
        dw_flags: DWORD,
        pb_element: *mut BYTE,
        pcb_element: *mut DWORD,
    ) -> BOOL;
}

/// Проверить контекст сертификата.
///
/// Источник: CSP_WinCrypt.h:5206
extern "C" {
    pub fn CertVerifySubjectCertificateContext(
        p_subject: PCCERT_CONTEXT,
        p_issuer: PCCERT_CONTEXT,
        pdw_flags: *mut DWORD,
    ) -> BOOL;
}

/// Проверить валидность времени сертификата.
///
/// Источник: CSP_WinCrypt.h:9067
extern "C" {
    pub fn CertVerifyTimeValidity(
        p_time_to_verify: *mut FILETIME,
        p_cert_info: PCERT_INFO,
    ) -> c_long;
}

/// Проверить вложенность валидности.
///
/// Источник: CSP_WinCrypt.h:9081
extern "C" {
    pub fn CertVerifyValidityNesting(
        p_subject_info: PCERT_INFO,
        p_issuer_info: PCERT_INFO,
    ) -> BOOL;
}

/// Сравнить два сертификата.
///
/// Источник: CSP_WinCrypt.h:12031
extern "C" {
    pub fn CertCompareCertificate(
        dw_cert_encoding_type: DWORD,
        p_cert_id1: PCERT_INFO,
        p_cert_id2: PCERT_INFO,
    ) -> BOOL;
}

/// Сравнить имена сертификатов.
///
/// Источник: CSP_WinCrypt.h:8876
extern "C" {
    pub fn CertCompareCertificateName(
        dw_cert_encoding_type: DWORD,
        p_cert_name1: PCERT_NAME_BLOB,
        p_cert_name2: PCERT_NAME_BLOB,
    ) -> BOOL;
}

/// Сравнить целочисленные блобы.
///
/// Источник: CSP_WinCrypt.h:12015
extern "C" {
    pub fn CertCompareIntegerBlob(
        p_int1: *const DataBlob,
        p_int2: *const DataBlob,
    ) -> BOOL;
}

/// Сравнить публичные ключи.
///
/// Источник: CSP_WinCrypt.h:12602
extern "C" {
    pub fn CertComparePublicKeyInfo(
        dw_cert_encoding_type: DWORD,
        p_public_key1: *const CERT_PUBLIC_KEY_INFO,
        p_public_key2: *const CERT_PUBLIC_KEY_INFO,
    ) -> BOOL;
}

/// Получить свойство контекста сертификата.
///
/// Источник: CSP_WinCrypt.h:5420
extern "C" {
    pub fn CertGetCertificateContextProperty(
        p_cert_context: PCCERT_CONTEXT,
        dw_prop_id: DWORD,
        pv_data: *mut c_void,
        pcb_data: *mut DWORD,
    ) -> BOOL;
}

/// Установить свойство контекста сертификата.
///
/// Источник: CSP_WinCrypt.h:5357
extern "C" {
    pub fn CertSetCertificateContextProperty(
        p_cert_context: PCCERT_CONTEXT,
        dw_prop_id: DWORD,
        dw_flags: DWORD,
        pv_data: *const c_void,
    ) -> BOOL;
}

/// Перечислить свойства контекста сертификата.
///
/// Источник: CSP_WinCrypt.h:5444
extern "C" {
    pub fn CertEnumCertificateContextProperties(
        p_cert_context: PCCERT_CONTEXT,
        dw_prop_id: DWORD,
    ) -> DWORD;
}

/// Добавить сериализованный элемент в хранилище.
///
/// Источник: CSP_WinCrypt.h:6030
extern "C" {
    pub fn CertAddSerializedElementToStore(
        h_cert_store: HCERTSTORE,
        pb_element: *const BYTE,
        cb_element: DWORD,
        dw_add_disposition: DWORD,
        dw_flags: DWORD,
        dw_context_type_flags: DWORD,
        pdw_context_type: *mut DWORD,
        ppv_context: *mut *mut c_void,
    ) -> BOOL;
}

/// Найти расширение по OID.
///
/// Источник: CSP_WinCrypt.h:2679
extern "C" {
    pub fn CertFindExtension(
        psz_obj_id: *const c_char,
        c_extensions: DWORD,
        rg_extensions: *mut CERT_EXTENSION,
    ) -> *mut CERT_EXTENSION;
}

/// Найти атрибут по OID.
///
/// Источник: CSP_WinCrypt.h:2693
extern "C" {
    pub fn CertFindAttribute(
        psz_obj_id: *const c_char,
        c_attr: DWORD,
        rg_attr: *mut CRYPT_ATTRIBUTE,
    ) -> *mut CRYPT_ATTRIBUTE;
}

/// Найти RDN-атрибут в имени.
///
/// Источник: CSP_WinCrypt.h:8743
extern "C" {
    pub fn CertFindRDNAttr(
        psz_obj_id: *const c_char,
        p_name: PCERT_NAME_INFO,
    ) -> *mut CERT_RDN_ATTR;
}

/// Проверить наличие RDN-атрибутов в имени сертификата.
///
/// Источник: CSP_WinCrypt.h:5012
extern "C" {
    pub fn CertIsRDNAttrsInCertificateName(
        dw_cert_encoding_type: DWORD,
        dw_flags: DWORD,
        p_cert_name: PCERT_NAME_BLOB,
        p_rdn: *const CERT_RDN,
    ) -> BOOL;
}

/// Преобразовать AlgId в строку OID.
///
/// Источник: CSP_WinCrypt.h:3129
extern "C" {
    pub fn CertAlgIdToOID(dw_alg_id: DWORD) -> *const c_char;
}

/// Преобразовать строку OID в AlgId.
///
/// Источник: CSP_WinCrypt.h:3141
extern "C" {
    pub fn CertOIDToAlgId(psz_obj_id: *const c_char) -> DWORD;
}

/// Получить длину публичного ключа.
///
/// Источник: CSP_WinCrypt.h:12617
extern "C" {
    pub fn CertGetPublicKeyLength(
        dw_cert_encoding_type: DWORD,
        p_public_key: *const CERT_PUBLIC_KEY_INFO,
    ) -> DWORD;
}

/// Преобразовать имя в строку (ANSI).
///
/// Источник: CSP_WinCrypt.h:8546
extern "C" {
    pub fn CertNameToStrA(
        dw_cert_encoding_type: DWORD,
        p_name: PCERT_NAME_BLOB,
        dw_str_type: DWORD,
        psz: *mut c_char,
        csz: DWORD,
    ) -> DWORD;
}

/// Преобразовать имя в строку (Unicode).
///
/// Источник: CSP_WinCrypt.h:8558
extern "C" {
    pub fn CertNameToStrW(
        dw_cert_encoding_type: DWORD,
        p_name: PCERT_NAME_BLOB,
        dw_str_type: DWORD,
        psz: *mut u16,
        csz: DWORD,
    ) -> DWORD;
}

/// Преобразовать значение RDN в строку (ANSI).
///
/// Источник: CSP_WinCrypt.h:8770
extern "C" {
    pub fn CertRDNValueToStrA(
        dw_value_type: DWORD,
        p_value: PCERT_RDN_VALUE_BLOB,
        psz: *mut c_char,
        csz: DWORD,
    ) -> DWORD;
}

/// Преобразовать значение RDN в строку (Unicode).
///
/// Источник: CSP_WinCrypt.h:8780
extern "C" {
    pub fn CertRDNValueToStrW(
        dw_value_type: DWORD,
        p_value: PCERT_RDN_VALUE_BLOB,
        psz: *mut u16,
        csz: DWORD,
    ) -> DWORD;
}

/// Преобразовать строку X.500 в encoded name (ANSI).
///
/// Источник: CSP_WinCrypt.h:8710
extern "C" {
    pub fn CertStrToNameA(
        dw_cert_encoding_type: DWORD,
        psz_x500: *const c_char,
        dw_str_type: DWORD,
        pv_reserved: *mut c_void,
        pb_encoded: *mut BYTE,
        pcb_encoded: *mut DWORD,
        ppsz_error: *mut *const c_char,
    ) -> BOOL;
}

/// Преобразовать строку X.500 в encoded name (Unicode).
///
/// Источник: CSP_WinCrypt.h:8724
extern "C" {
    pub fn CertStrToNameW(
        dw_cert_encoding_type: DWORD,
        psz_x500: *const u16,
        dw_str_type: DWORD,
        pv_reserved: *mut c_void,
        pb_encoded: *mut BYTE,
        pcb_encoded: *mut DWORD,
        ppsz_error: *mut *const u16,
    ) -> BOOL;
}

/// Получить enhanced key usage сертификата.
///
/// Источник: CSP_WinCrypt.h:7223
extern "C" {
    pub fn CertGetEnhancedKeyUsage(
        p_cert_context: PCCERT_CONTEXT,
        dw_flags: DWORD,
        p_usage: PCERT_ENHKEY_USAGE,
        pcb_usage: *mut DWORD,
    ) -> BOOL;
}

/// Получить intended key usage сертификата.
///
/// Источник: CSP_WinCrypt.h:2710
extern "C" {
    pub fn CertGetIntendedKeyUsage(
        dw_cert_encoding_type: DWORD,
        p_cert_info: PCERT_INFO,
        pb_key_usage: *mut BYTE,
        cb_key_usage: DWORD,
    ) -> BOOL;
}

/// Получить допустимые usage.
///
/// Источник: CSP_WinCrypt.h:7276
extern "C" {
    pub fn CertGetValidUsages(
        c_certs: DWORD,
        rgh_certs: *const PCCERT_CONTEXT,
        c_num_oids: *mut c_int,
        rgh_oids: *mut *mut c_char,
        pcb_oids: *mut DWORD,
    ) -> BOOL;
}

/// Получить имя сертификата (ANSI).
///
/// Источник: CSP_WinCrypt.h:8810
extern "C" {
    pub fn CertGetNameStringA(
        p_cert_context: PCCERT_CONTEXT,
        dw_type: DWORD,
        dw_flags: DWORD,
        pv_type_para: *mut c_void,
        psz_name_string: *mut c_char,
        cch_name_string: DWORD,
    ) -> DWORD;
}

/// Получить имя сертификата (Unicode).
///
/// Источник: CSP_WinCrypt.h:8799
extern "C" {
    pub fn CertGetNameStringW(
        p_cert_context: PCCERT_CONTEXT,
        dw_type: DWORD,
        dw_flags: DWORD,
        pv_type_para: *mut c_void,
        psz_name_string: *mut u16,
        cch_name_string: DWORD,
    ) -> DWORD;
}

// ---------------------------------------------------------------------------
// Cert* — CRL (Certificate Revocation List)
// ---------------------------------------------------------------------------

/// Создать контекст CRL из закодированного blobs.
///
/// Источник: CSP_WinCrypt.h:5730
extern "C" {
    pub fn CertCreateCRLContext(
        dw_cert_encoding_type: DWORD,
        pb_crl_encoded: *const BYTE,
        cb_crl_encoded: DWORD,
    ) -> PCCRL_CONTEXT;
}

/// Дублировать контекст CRL.
///
/// Источник: CSP_WinCrypt.h:5709
extern "C" {
    pub fn CertDuplicateCRLContext(p_crl_context: PCCRL_CONTEXT) -> PCCRL_CONTEXT;
}

/// Освободить контекст CRL.
///
/// Источник: CSP_WinCrypt.h:5745
extern "C" {
    pub fn CertFreeCRLContext(p_crl_context: PCCRL_CONTEXT) -> BOOL;
}

/// Удалить CRL из хранилища.
///
/// Источник: CSP_WinCrypt.h:6136
extern "C" {
    pub fn CertDeleteCRLFromStore(p_crl_context: PCCRL_CONTEXT) -> BOOL;
}

/// Найти CRL в хранилище.
///
/// Источник: CSP_WinCrypt.h:5615
extern "C" {
    pub fn CertFindCRLInStore(
        h_cert_store: HCERTSTORE,
        dw_cert_encoding_type: DWORD,
        dw_find_flags: DWORD,
        dw_find_type: DWORD,
        pv_find_para: *const c_void,
        p_prev_crl_context: PCCRL_CONTEXT,
    ) -> PCCRL_CONTEXT;
}

/// Перечислить CRL в хранилище.
///
/// Источник: CSP_WinCrypt.h:5584
extern "C" {
    pub fn CertEnumCRLsInStore(
        h_cert_store: HCERTSTORE,
        p_prev_crl_context: PCCRL_CONTEXT,
    ) -> PCCRL_CONTEXT;
}

/// Получить CRL из хранилища.
///
/// Источник: CSP_WinCrypt.h:5558
extern "C" {
    pub fn CertGetCRLFromStore(
        h_cert_store: HCERTSTORE,
        p_issuer_context: PCCERT_CONTEXT,
        p_prev_crl_context: PCCRL_CONTEXT,
        pdw_flags: *mut DWORD,
    ) -> PCCRL_CONTEXT;
}

/// Добавить закодированную CRL в хранилище.
///
/// Источник: CSP_WinCrypt.h:6082
extern "C" {
    pub fn CertAddEncodedCRLToStore(
        h_cert_store: HCERTSTORE,
        dw_cert_encoding_type: DWORD,
        pb_crl_encoded: *const BYTE,
        cb_crl_encoded: DWORD,
        dw_add_disposition: DWORD,
        pp_crl_context: *mut PCCRL_CONTEXT,
    ) -> BOOL;
}

/// Добавить контекст CRL в хранилище.
///
/// Источник: CSP_WinCrypt.h:6114
extern "C" {
    pub fn CertAddCRLContextToStore(
        h_cert_store: HCERTSTORE,
        p_crl_context: PCCRL_CONTEXT,
        dw_add_disposition: DWORD,
        pp_store_context: *mut PCCRL_CONTEXT,
    ) -> BOOL;
}

/// Добавить линк на CRL в хранилище.
///
/// Источник: CSP_WinCrypt.h:6545
extern "C" {
    pub fn CertAddCRLLinkToStore(
        h_cert_store: HCERTSTORE,
        p_crl_context: PCCRL_CONTEXT,
        dw_add_disposition: DWORD,
        pp_store_context: *mut PCCRL_CONTEXT,
    ) -> BOOL;
}

/// Сериализовать элемент CRL.
///
/// Источник: CSP_WinCrypt.h:6161
extern "C" {
    pub fn CertSerializeCRLStoreElement(
        p_crl_context: PCCRL_CONTEXT,
        dw_flags: DWORD,
        pb_element: *mut BYTE,
        pcb_element: *mut DWORD,
    ) -> BOOL;
}

/// Получить свойство контекста CRL.
///
/// Источник: CSP_WinCrypt.h:5775
extern "C" {
    pub fn CertGetCRLContextProperty(
        p_crl_context: PCCRL_CONTEXT,
        dw_prop_id: DWORD,
        pv_data: *mut c_void,
        pcb_data: *mut DWORD,
    ) -> BOOL;
}

/// Установить свойство контекста CRL.
///
/// Источник: CSP_WinCrypt.h:5757
extern "C" {
    pub fn CertSetCRLContextProperty(
        p_crl_context: PCCRL_CONTEXT,
        dw_prop_id: DWORD,
        dw_flags: DWORD,
        pv_data: *const c_void,
    ) -> BOOL;
}

/// Перечислить свойства контекста CRL.
///
/// Источник: CSP_WinCrypt.h:5795
extern "C" {
    pub fn CertEnumCRLContextProperties(
        p_crl_context: PCCRL_CONTEXT,
        dw_prop_id: DWORD,
    ) -> DWORD;
}

/// Найти сертификат в CRL.
///
/// Источник: CSP_WinCrypt.h:5816
extern "C" {
    pub fn CertFindCertificateInCRL(
        p_cert: PCCERT_CONTEXT,
        p_crl_context: PCCRL_CONTEXT,
        dw_flags: DWORD,
        pv_reserved: *mut c_void,
        pp_crl_entry: *mut *mut c_void, // *mut CRL_ENTRY
    ) -> BOOL;
}

/// Проверить, является ли CRL валидной для сертификата.
///
/// Источник: CSP_WinCrypt.h:5839
extern "C" {
    pub fn CertIsValidCRLForCertificate(
        p_cert: PCCERT_CONTEXT,
        p_crl: PCCRL_CONTEXT,
        dw_flags: DWORD,
        pv_reserved: *mut c_void,
    ) -> BOOL;
}

/// Проверить отозванность по CRL.
///
/// Источник: CSP_WinCrypt.h:9094
extern "C" {
    pub fn CertVerifyCRLRevocation(
        dw_cert_encoding_type: DWORD,
        p_cert_id: PCERT_INFO,
        c_crl_info: DWORD,
        rgp_crl_info: *mut PCRL_INFO,
    ) -> BOOL;
}

/// Проверить валидность времени CRL.
///
/// Источник: CSP_WinCrypt.h:7287
extern "C" {
    pub fn CertVerifyCRLTimeValidity(
        p_time_to_verify: *mut FILETIME,
        p_crl_info: PCRL_INFO,
    ) -> c_long;
}

// ---------------------------------------------------------------------------
// Cert* — цепочки сертификатов
// ---------------------------------------------------------------------------

/// Создать движок цепочки сертификатов.
///
/// Источник: CSP_WinCrypt.h:7665
extern "C" {
    pub fn CertCreateCertificateChainEngine(
        p_config: PCERT_CHAIN_ENGINE_CONFIG,
        ph_chain_engine: *mut HCERTCHAINENGINE,
    ) -> BOOL;
}

/// Освободить движок цепочки.
///
/// Источник: CSP_WinCrypt.h:7677
extern "C" {
    pub fn CertFreeCertificateChainEngine(h_chain_engine: HCERTCHAINENGINE);
}

/// Пересинхронизировать движок цепочки.
///
/// Источник: CSP_WinCrypt.h:7688
extern "C" {
    pub fn CertResyncCertificateChainEngine(h_chain_engine: HCERTCHAINENGINE) -> BOOL;
}

/// Получить цепочку сертификатов.
///
/// Источник: CSP_WinCrypt.h:8830
extern "C" {
    pub fn CertGetCertificateChain(
        h_chain_engine: HCERTCHAINENGINE,
        p_cert_context: PCCERT_CONTEXT,
        p_time: *mut FILETIME,
        h_additional_store: HCERTSTORE,
        p_chain_para: PCERT_CHAIN_PARA,
        dw_flags: DWORD,
        pv_reserved: *mut c_void,
        pp_chain_context: *mut PCCERT_CHAIN_CONTEXT,
    ) -> BOOL;
}

/// Освободить цепочку сертификатов.
///
/// Источник: CSP_WinCrypt.h:8850
extern "C" {
    pub fn CertFreeCertificateChain(p_chain_context: PCCERT_CHAIN_CONTEXT);
}

/// Дублировать цепочку сертификатов.
///
/// Источник: CSP_WinCrypt.h:8840
extern "C" {
    pub fn CertDuplicateCertificateChain(
        p_chain_context: PCCERT_CHAIN_CONTEXT,
    ) -> PCCERT_CHAIN_CONTEXT;
}

/// Найти цепочку в хранилище.
///
/// Источник: CSP_WinCrypt.h:8073
extern "C" {
    pub fn CertFindChainInStore(
        h_cert_store: HCERTSTORE,
        dw_cert_encoding_type: DWORD,
        dw_find_flags: DWORD,
        dw_find_type: DWORD,
        pv_find_para: *const c_void,
        p_prev_chain_context: PCCERT_CHAIN_CONTEXT,
    ) -> PCCERT_CHAIN_CONTEXT;
}

/// Проверить политику цепочки сертификатов.
///
/// Источник: CSP_WinCrypt.h:8302
extern "C" {
    pub fn CertVerifyCertificateChainPolicy(
        psz_policy_oid: *const c_char,
        p_chain_context: PCCERT_CHAIN_CONTEXT,
        p_policy_para: PCERT_CHAIN_POLICY_PARA,
        p_policy_status: PCERT_CHAIN_POLICY_STATUS,
    ) -> BOOL;
}

/// Проверить отозванность.
///
/// Источник: CSP_WinCrypt.h:7570
extern "C" {
    pub fn CertVerifyRevocation(
        dw_encoding_type: DWORD,
        dw_rev_type: DWORD,
        c_context: DWORD,
        rgpv_context: *const *const c_void,
        dw_flags: DWORD,
        p_rev_para: PCERT_REVOCATION_PARA,
        p_rev_status: PCERT_REVOCATION_STATUS,
    ) -> BOOL;
}

// ---------------------------------------------------------------------------
// Cert* — OCSP
// ---------------------------------------------------------------------------

/// Открыть OCSP-ответ сервера.
///
/// Источник: CSP_WinCrypt.h:12977
extern "C" {
    pub fn CertOpenServerOcspResponse(
        p_chain_context: PCCERT_CHAIN_CONTEXT,
        dw_flags: DWORD,
        pv_reserved: *mut c_void,
    ) -> HCERT_SERVER_OCSP_RESPONSE;
}

/// Закрыть OCSP-ответ сервера.
///
/// Источник: CSP_WinCrypt.h:13009
extern "C" {
    pub fn CertCloseServerOcspResponse(
        h_server_ocsp_response: HCERT_SERVER_OCSP_RESPONSE,
        dw_flags: DWORD,
    );
}

/// Получить контекст OCSP-ответа.
///
/// Источник: CSP_WinCrypt.h:13045
extern "C" {
    pub fn CertGetServerOcspResponseContext(
        h_server_ocsp_response: HCERT_SERVER_OCSP_RESPONSE,
        dw_flags: DWORD,
        pv_reserved: *mut c_void,
    ) -> PCCERT_SERVER_OCSP_RESPONSE_CONTEXT;
}

/// Освободить контекст OCSP-ответа.
///
/// Источник: CSP_WinCrypt.h:13071
extern "C" {
    pub fn CertFreeServerOcspResponseContext(
        p_server_ocsp_response_context: PCCERT_SERVER_OCSP_RESPONSE_CONTEXT,
    );
}

// ---------------------------------------------------------------------------
// Cert* — Self-Signed Certificate
// ---------------------------------------------------------------------------

/// Создать самоподписанный сертификат.
///
/// Источник: CSP_WinCrypt.h:9979 (только на UNIX/CryptoPro)
extern "C" {
    pub fn CertCreateSelfSignCertificate(
        h_crypt_prov: HCRYPTPROV,
        p_subject_issuer_blob: PCERT_NAME_BLOB,
        dw_flags: DWORD,
        p_key_prov_info: *const CRYPT_KEY_PROV_INFO,
        p_signature_algorithm: *const CRYPT_ALGORITHM_IDENTIFIER,
        p_start_time: *mut SYSTEMTIME,
        p_end_time: *mut SYSTEMTIME,
        p_extensions: *mut CERT_EXTENSIONS,
    ) -> PCCERT_CONTEXT;
}

// ===========================================================================
// CryptMsg* функции — кодирование/декодирование CMS-сообщений
// ===========================================================================

/// Открыть сообщение для кодирования.
///
/// Источник: CSP_WinCrypt.h:10551
extern "C" {
    pub fn CryptMsgOpenToEncode(
        dw_msg_encoding_type: DWORD,
        dw_flags: DWORD,
        dw_msg_type: DWORD,
        pv_msg_encode_info: *const c_void,
        psz_inner_content_obj_id: *mut c_char,
        p_stream_info: PCMSG_STREAM_INFO,
    ) -> HCRYPTMSG;
}

/// Рассчитать длину закодированного сообщения.
///
/// Источник: CSP_WinCrypt.h:10571
extern "C" {
    pub fn CryptMsgCalculateEncodedLength(
        dw_msg_encoding_type: DWORD,
        dw_flags: DWORD,
        dw_msg_type: DWORD,
        pv_msg_encode_info: *const c_void,
        psz_inner_content_obj_id: *mut c_char,
        cb_data: DWORD,
    ) -> DWORD;
}

/// Открыть сообщение для декодирования.
///
/// Источник: CSP_WinCrypt.h:10595
extern "C" {
    pub fn CryptMsgOpenToDecode(
        dw_msg_encoding_type: DWORD,
        dw_flags: DWORD,
        dw_msg_type: DWORD,
        h_crypt_prov: HCRYPTPROV,
        p_recipient_info: PCERT_INFO,
        p_stream_info: PCMSG_STREAM_INFO,
    ) -> HCRYPTMSG;
}

/// Дублировать дескриптор сообщения.
///
/// Источник: CSP_WinCrypt.h:10610
extern "C" {
    pub fn CryptMsgDuplicate(h_crypt_msg: HCRYPTMSG) -> HCRYPTMSG;
}

/// Закрыть сообщение.
///
/// Источник: CSP_WinCrypt.h:10622
extern "C" {
    pub fn CryptMsgClose(h_crypt_msg: HCRYPTMSG) -> BOOL;
}

/// Обновить (данные) сообщение.
///
/// Источник: CSP_WinCrypt.h:10638
extern "C" {
    pub fn CryptMsgUpdate(
        h_crypt_msg: HCRYPTMSG,
        pb_data: *const BYTE,
        cb_data: DWORD,
        f_final: BOOL,
    ) -> BOOL;
}

/// Получить параметр сообщения.
///
/// Источник: CSP_WinCrypt.h:10672
extern "C" {
    pub fn CryptMsgGetParam(
        h_crypt_msg: HCRYPTMSG,
        dw_param_type: DWORD,
        dw_index: DWORD,
        pv_data: *mut c_void,
        pcb_data: *mut DWORD,
    ) -> BOOL;
}

/// Получить и проверить подписанта.
///
/// Источник: CSP_WinCrypt.h:11036
extern "C" {
    pub fn CryptMsgGetAndVerifySigner(
        h_crypt_msg: HCRYPTMSG,
        c_signer_store: DWORD,
        rgh_signer_store: *mut HCERTSTORE,
        dw_flags: DWORD,
        pp_signer: *mut PCCERT_CONTEXT,
        pdw_signer_index: *mut DWORD,
    ) -> BOOL;
}

/// Управление сообщением (контроль).
///
/// Источник: CSP_WinCrypt.h:11194
extern "C" {
    pub fn CryptMsgControl(
        h_crypt_msg: HCRYPTMSG,
        dw_flags: DWORD,
        dw_ctrl_type: DWORD,
        pv_ctrl_para: *const c_void,
    ) -> BOOL;
}

/// Контр подписи сообщения.
///
/// Источник: CSP_WinCrypt.h:11209
extern "C" {
    pub fn CryptMsgCountersign(
        h_crypt_msg: HCRYPTMSG,
        dw_index: DWORD,
        c_countersigners: DWORD,
        rg_countersigners: PCMSG_SIGNER_ENCODE_INFO,
    ) -> BOOL;
}

/// Контр подписи (закодированный).
///
/// Источник: CSP_WinCrypt.h:11225
extern "C" {
    pub fn CryptMsgCountersignEncoded(
        dw_encoding_type: DWORD,
        pb_signer_info: *mut BYTE,
        cb_signer_info: DWORD,
        c_countersigners: DWORD,
        rg_countersigners: PCMSG_SIGNER_ENCODE_INFO,
        pb_countersignature: *mut BYTE,
        pcb_countersignature: *mut DWORD,
    ) -> BOOL;
}

/// Проверить контр подписи.
///
/// Источник: CSP_WinCrypt.h:11592
extern "C" {
    pub fn CryptMsgVerifyCountersignatureEncoded(
        h_crypt_prov: HCRYPTPROV,
        dw_encoding_type: DWORD,
        pb_signer_info: *mut BYTE,
        cb_signer_info: DWORD,
        pb_signer_info_countersignature: *mut BYTE,
        cb_signer_info_countersignature: DWORD,
        pci_countersigner: PCERT_INFO,
    ) -> BOOL;
}

/// Проверить контр подписи (расширенная).
///
/// Источник: CSP_WinCrypt.h:11615
extern "C" {
    pub fn CryptMsgVerifyCountersignatureEncodedEx(
        h_crypt_prov: HCRYPTPROV,
        dw_encoding_type: DWORD,
        pb_signer_info: *mut BYTE,
        cb_signer_info: DWORD,
        pb_signer_info_countersignature: *mut BYTE,
        cb_signer_info_countersignature: DWORD,
        dw_signer_type: DWORD,
        pv_signer: *mut c_void,
        dw_flags: DWORD,
        pv_reserved: *mut c_void,
    ) -> BOOL;
}

// ===========================================================================
// CryptEncode*/CryptDecode* функции
// ===========================================================================

/// Закодировать объект.
///
/// Источник: CSP_WinCrypt.h:801
extern "C" {
    pub fn CryptEncodeObject(
        dw_cert_encoding_type: DWORD,
        lpsz_struct_type: *const c_char,
        pv_struct_info: *const c_void,
        pb_encoded: *mut BYTE,
        pcb_encoded: *mut DWORD,
    ) -> BOOL;
}

/// Закодировать объект (расширенный).
///
/// Источник: CSP_WinCrypt.h:788
extern "C" {
    pub fn CryptEncodeObjectEx(
        dw_cert_encoding_type: DWORD,
        lpsz_struct_type: *const c_char,
        pv_struct_info: *const c_void,
        dw_flags: DWORD,
        p_encode_para: PCRYPT_ENCODE_PARA,
        pv_encoded: *mut c_void,
        pcb_encoded: *mut DWORD,
    ) -> BOOL;
}

/// Декодировать объект.
///
/// Источник: CSP_WinCrypt.h:880
extern "C" {
    pub fn CryptDecodeObject(
        dw_cert_encoding_type: DWORD,
        lpsz_struct_type: *const c_char,
        pb_encoded: *const BYTE,
        cb_encoded: DWORD,
        dw_flags: DWORD,
        pv_struct_info: *mut c_void,
        pcb_struct_info: *mut DWORD,
    ) -> BOOL;
}

/// Декодировать объект (расширенный).
///
/// Источник: CSP_WinCrypt.h:865
extern "C" {
    pub fn CryptDecodeObjectEx(
        dw_cert_encoding_type: DWORD,
        lpsz_struct_type: *const c_char,
        pb_encoded: *const BYTE,
        cb_encoded: DWORD,
        dw_flags: DWORD,
        p_decode_para: PCRYPT_DECODE_PARA,
        pv_struct_info: *mut c_void,
        pcb_struct_info: *mut DWORD,
    ) -> BOOL;
}

/// Форматировать закодированный объект.
///
/// Источник: CSP_WinCrypt.h:752
extern "C" {
    pub fn CryptFormatObject(
        dw_cert_encoding_type: DWORD,
        dw_format_type: DWORD,
        dw_format_str_type: DWORD,
        p_format_struct: *const c_void,
        lpsz_struct_type: *const c_char,
        pb_encoded: *const BYTE,
        cb_encoded: DWORD,
        pb_format: *mut c_void,
        pcb_format: *mut DWORD,
    ) -> BOOL;
}

// ===========================================================================
// CryptString*/CryptBinary* — кодирование Base64/Hex
// ===========================================================================

/// Декодировать строку в двоичные данные (ANSI).
///
/// Источник: CSP_WinCrypt.h:12636
extern "C" {
    pub fn CryptStringToBinaryA(
        psz_string: *const c_char,
        cch_string: DWORD,
        dw_flags: DWORD,
        pb_binary: *mut BYTE,
        pcb_binary: *mut DWORD,
        pdw_skip: *mut DWORD,
        pdw_flags: *mut DWORD,
    ) -> BOOL;
}

/// Декодировать строку в двоичные данные (Unicode).
///
/// Источник: CSP_WinCrypt.h:12657
extern "C" {
    pub fn CryptStringToBinaryW(
        psz_string: *const u16,
        cch_string: DWORD,
        dw_flags: DWORD,
        pb_binary: *mut BYTE,
        pcb_binary: *mut DWORD,
        pdw_skip: *mut DWORD,
        pdw_flags: *mut DWORD,
    ) -> BOOL;
}

/// Закодировать двоичные данные в строку (ANSI).
///
/// Источник: CSP_WinCrypt.h:12681
extern "C" {
    pub fn CryptBinaryToStringA(
        pb_binary: *const BYTE,
        cb_binary: DWORD,
        dw_flags: DWORD,
        psz_string: *mut c_char,
        pcch_string: *mut DWORD,
    ) -> BOOL;
}

/// Закодировать двоичные данные в строку (Unicode).
///
/// Источник: CSP_WinCrypt.h:12697
extern "C" {
    pub fn CryptBinaryToStringW(
        pb_binary: *const BYTE,
        cb_binary: DWORD,
        dw_flags: DWORD,
        psz_string: *mut u16,
        pcch_string: *mut DWORD,
    ) -> BOOL;
}

// ===========================================================================
// CryptSign*/CryptVerify* — подпись и проверка
// ===========================================================================

/// Подписать и закодировать сертификат/CRL/OTC.
///
/// Источник: CSP_WinCrypt.h:9044
extern "C" {
    pub fn CryptSignAndEncodeCertificate(
        h_crypt_prov: HCRYPTPROV,
        dw_key_spec: DWORD,
        dw_cert_encoding_type: DWORD,
        lpsz_struct_type: *const c_char,
        pv_struct_info: *const c_void,
        p_signature_algorithm: *const CRYPT_ALGORITHM_IDENTIFIER,
        pv_hash_aux_info: *const c_void,
        pb_encoded: *mut BYTE,
        pcb_encoded: *mut DWORD,
    ) -> BOOL;
}

/// Подписать сертификат.
///
/// Источник: CSP_WinCrypt.h:9017
extern "C" {
    pub fn CryptSignCertificate(
        h_crypt_prov: HCRYPTPROV,
        dw_key_spec: DWORD,
        dw_cert_encoding_type: DWORD,
        pb_encoded_to_be_signed: *const BYTE,
        cb_encoded_to_be_signed: DWORD,
        p_signature_algorithm: *const CRYPT_ALGORITHM_IDENTIFIER,
        pv_hash_aux_info: *const c_void,
        pb_signature: *mut BYTE,
        pcb_signature: *mut DWORD,
    ) -> BOOL;
}

/// Экспортировать публичный ключ.
///
/// Источник: CSP_WinCrypt.h:2727
extern "C" {
    pub fn CryptExportPublicKeyInfo(
        h_crypt_prov: HCRYPTPROV,
        dw_key_spec: DWORD,
        dw_cert_encoding_type: DWORD,
        p_info: *mut CERT_PUBLIC_KEY_INFO,
        pcb_info: *mut DWORD,
    ) -> BOOL;
}

/// Экспортировать публичный ключ (расширенный).
///
/// Источник: CSP_WinCrypt.h:2753
extern "C" {
    pub fn CryptExportPublicKeyInfoEx(
        h_crypt_prov: HCRYPTPROV,
        dw_key_spec: DWORD,
        dw_cert_encoding_type: DWORD,
        psz_public_key_obj_id: *mut c_char,
        dw_flags: DWORD,
        pv_aux_info: *mut c_void,
        p_info: *mut CERT_PUBLIC_KEY_INFO,
        pcb_info: *mut DWORD,
    ) -> BOOL;
}

/// Импортировать публичный ключ.
///
/// Источник: CSP_WinCrypt.h:2774
extern "C" {
    pub fn CryptImportPublicKeyInfo(
        h_crypt_prov: HCRYPTPROV,
        dw_cert_encoding_type: DWORD,
        p_info: *const CERT_PUBLIC_KEY_INFO,
        ph_key: *mut HCRYPTKEY,
    ) -> BOOL;
}

/// Импортировать публичный ключ (расширенный).
///
/// Источник: CSP_WinCrypt.h:2801
extern "C" {
    pub fn CryptImportPublicKeyInfoEx(
        h_crypt_prov: HCRYPTPROV,
        dw_cert_encoding_type: DWORD,
        p_info: *const CERT_PUBLIC_KEY_INFO,
        ai_key_alg: ALG_ID,
        dw_flags: DWORD,
        pv_aux_info: *mut c_void,
        ph_key: *mut HCRYPTKEY,
    ) -> BOOL;
}

/// Хешировать сертификат.
///
/// Источник: CSP_WinCrypt.h:8993
extern "C" {
    pub fn CryptHashCertificate(
        h_crypt_prov: HCRYPTPROV,
        alg_id: ALG_ID,
        dw_flags: DWORD,
        pb_encoded: *const BYTE,
        cb_encoded: DWORD,
        pb_computed_hash: *mut BYTE,
        pcb_computed_hash: *mut DWORD,
    ) -> BOOL;
}

/// Хешировать публичный ключ.
///
/// Источник: CSP_WinCrypt.h:8756
extern "C" {
    pub fn CryptHashPublicKeyInfo(
        h_crypt_prov: HCRYPTPROV,
        alg_id: ALG_ID,
        dw_flags: DWORD,
        dw_cert_encoding_type: DWORD,
        p_info: *const CERT_PUBLIC_KEY_INFO,
        pb_computed_hash: *mut BYTE,
        pcb_computed_hash: *mut DWORD,
    ) -> BOOL;
}

/// Хешировать ToBeSigned данные.
///
/// Источник: CSP_WinCrypt.h:8972
extern "C" {
    pub fn CryptHashToBeSigned(
        h_crypt_prov: HCRYPTPROV,
        dw_cert_encoding_type: DWORD,
        pb_encoded: *const BYTE,
        cb_encoded: DWORD,
        pb_computed_hash: *mut BYTE,
        pcb_computed_hash: *mut DWORD,
    ) -> BOOL;
}

/// Проверить подпись сертификата.
///
/// Источник: CSP_WinCrypt.h:8894
extern "C" {
    pub fn CryptVerifyCertificateSignature(
        h_crypt_prov: HCRYPTPROV,
        dw_cert_encoding_type: DWORD,
        pb_encoded: *const BYTE,
        cb_encoded: DWORD,
        p_public_key: *const CERT_PUBLIC_KEY_INFO,
    ) -> BOOL;
}

/// Проверить подпись сертификата (расширенная).
///
/// Источник: CSP_WinCrypt.h:8930
extern "C" {
    pub fn CryptVerifyCertificateSignatureEx(
        h_crypt_prov: HCRYPTPROV,
        dw_cert_encoding_type: DWORD,
        dw_subject_type: DWORD,
        pv_subject: *mut c_void,
        dw_issuer_type: DWORD,
        pv_issuer: *mut c_void,
        dw_flags: DWORD,
        pv_reserved: *mut c_void,
    ) -> BOOL;
}

/// Найти информацию о провайдере ключа по сертификату.
///
/// Источник: CSP_WinCrypt.h:2897
extern "C" {
    pub fn CryptFindCertificateKeyProvInfo(
        p_cert: PCCERT_CONTEXT,
        dw_flags: DWORD,
        pv_reserved: *mut c_void,
    ) -> BOOL;
}

/// Получить приватный ключ сертификата.
///
/// Источник: CSP_WinCrypt.h:3362
extern "C" {
    pub fn CryptAcquireCertificatePrivateKey(
        p_cert: PCCERT_CONTEXT,
        dw_flags: DWORD,
        pv_reserved: *mut c_void,
        ph_crypt_prov: *mut HCRYPTPROV,
        pdw_key_spec: *mut DWORD,
        pf_caller_free_prov: *mut BOOL,
    ) -> BOOL;
}

// ===========================================================================
// Crypt* — подпись/шифрование сообщений
// ===========================================================================

/// Подписать сообщение.
///
/// Источник: CSP_WinCrypt.h:12383
extern "C" {
    pub fn CryptSignMessage(
        p_sign_para: *const c_void,
        f_detached_signature: BOOL,
        c_to_be_signed: DWORD,
        rgpb_to_be_signed: *const *const BYTE,
        rgcb_to_be_signed: *const DWORD,
        pb_signed_blob: *mut BYTE,
        pcb_signed_blob: *mut DWORD,
    ) -> BOOL;
}

/// Подписать и зашифровать сообщение.
///
/// Источник: CSP_WinCrypt.h:12541
extern "C" {
    pub fn CryptSignAndEncryptMessage(
        p_sign_para: *const c_void,
        p_encrypt_para: *const c_void,
        c_recipient_cert: DWORD,
        rgp_recipient_cert: *const PCCERT_CONTEXT,
        pb_to_be_signed_and_encrypted: *const BYTE,
        cb_to_be_signed_and_encrypted: DWORD,
        pb_signed_and_encrypted_blob: *mut BYTE,
        pcb_signed_and_encrypted_blob: *mut DWORD,
    ) -> BOOL;
}

/// Зашифровать сообщение.
///
/// Источник: CSP_WinCrypt.h:12495
extern "C" {
    pub fn CryptEncryptMessage(
        p_encrypt_para: *const c_void,
        c_recipient_cert: DWORD,
        rgp_recipient_cert: *const PCCERT_CONTEXT,
        pb_to_be_encrypted: *const BYTE,
        cb_to_be_encrypted: DWORD,
        pb_encrypted_blob: *mut BYTE,
        pcb_encrypted_blob: *mut DWORD,
    ) -> BOOL;
}

/// Дешифровать сообщение.
///
/// Источник: CSP_WinCrypt.h:12522
extern "C" {
    pub fn CryptDecryptMessage(
        p_decrypt_para: *const c_void,
        pb_encrypted_blob: *const BYTE,
        cb_encrypted_blob: DWORD,
        pb_decrypted: *mut BYTE,
        pcb_decrypted: *mut DWORD,
        pp_xchg_cert: *mut PCCERT_CONTEXT,
    ) -> BOOL;
}

/// Дешифровать и проверить подпись сообщения.
///
/// Источник: CSP_WinCrypt.h:12582
extern "C" {
    pub fn CryptDecryptAndVerifyMessageSignature(
        p_decrypt_para: *const c_void,
        p_verify_para: *const c_void,
        dw_signer_index: DWORD,
        pb_encrypted_blob: *const BYTE,
        cb_encrypted_blob: DWORD,
        pb_decrypted: *mut BYTE,
        pcb_decrypted: *mut DWORD,
        pp_xchg_cert: *mut PCCERT_CONTEXT,
        pp_signer_cert: *mut PCCERT_CONTEXT,
    ) -> BOOL;
}

/// Проверить подпись сообщения.
///
/// Источник: CSP_WinCrypt.h:12432
extern "C" {
    pub fn CryptVerifyMessageSignature(
        p_verify_para: *const c_void,
        dw_signer_index: DWORD,
        pb_signed_blob: *const BYTE,
        cb_signed_blob: DWORD,
        pb_decoded: *mut BYTE,
        pcb_decoded: *mut DWORD,
        pp_signer_cert: *mut PCCERT_CONTEXT,
    ) -> BOOL;
}

/// Проверить отсоединенную подпись сообщения.
///
/// Источник: CSP_WinCrypt.h:12478
extern "C" {
    pub fn CryptVerifyDetachedMessageSignature(
        p_verify_para: *const c_void,
        dw_signer_index: DWORD,
        pb_detached_sign_blob: *const BYTE,
        cb_detached_sign_blob: DWORD,
        c_to_be_signed: DWORD,
        rgpb_to_be_signed: *const *const BYTE,
        rgcb_to_be_signed: *const DWORD,
        pp_signer_cert: *mut PCCERT_CONTEXT,
    ) -> BOOL;
}

/// Получить количество подписантов сообщения.
///
/// Источник: CSP_WinCrypt.h:12449
extern "C" {
    pub fn CryptGetMessageSignerCount(
        dw_msg_encoding_type: DWORD,
        pb_signed_blob: *const BYTE,
        cb_signed_blob: DWORD,
    ) -> c_long;
}

/// Получить хранилище сертификатов сообщения.
///
/// Источник: CSP_WinCrypt.h:12462
extern "C" {
    pub fn CryptGetMessageCertificates(
        dw_msg_and_cert_encoding_type: DWORD,
        h_crypt_prov: HCRYPTPROV,
        dw_flags: DWORD,
        pb_signed_blob: *const BYTE,
        cb_signed_blob: DWORD,
    ) -> HCERTSTORE;
}

// ===========================================================================
// CryptQuery* — запрос типа объекта
// ===========================================================================

/// Запросить тип и параметры объекта (сертификат/CRL/сообщение).
///
/// Источник: CSP_WinCrypt.h:4191
extern "C" {
    pub fn CryptQueryObject(
        dw_object_type: DWORD,
        pv_object: *const c_void,
        dw_expected_content_type_flags: DWORD,
        dw_expected_format_type_flags: DWORD,
        dw_flags: DWORD,
        pdw_msg_and_cert_encoding_type: *mut DWORD,
        pdw_content_type: *mut DWORD,
        pdw_format_type: *mut DWORD,
        ph_cert_store: *mut HCERTSTORE,
        ph_msg: *mut HCRYPTMSG,
        ppv_context: *mut *const c_void,
    ) -> BOOL;
}

// ===========================================================================
// Crypt* — OID функции
// ===========================================================================

/// Инициализировать набор функций OID.
///
/// Источник: CSP_WinCrypt.h:3249
extern "C" {
    pub fn CryptInitOIDFunctionSet(
        psz_func_name: *const c_char,
        dw_flags: DWORD,
    ) -> HCRYPTOIDFUNCSET;
}

/// Получить адрес функции OID.
///
/// Источник: CSP_WinCrypt.h:3275
extern "C" {
    pub fn CryptGetOIDFunctionAddress(
        h_func_set: HCRYPTOIDFUNCSET,
        dw_encoding_type: DWORD,
        psz_oid: *const c_char,
        dw_flags: DWORD,
        ppv_func_addr: *mut *mut c_void,
        ph_func_addr: *mut HCRYPTOIDFUNCADDR,
    ) -> BOOL;
}

/// Получить адрес функции по умолчанию.
///
/// Источник: CSP_WinCrypt.h:3312
extern "C" {
    pub fn CryptGetDefaultOIDFunctionAddress(
        h_func_set: HCRYPTOIDFUNCSET,
        dw_encoding_type: DWORD,
        pwsz_dll: *const u16,
        dw_flags: DWORD,
        ppv_func_addr: *mut *mut c_void,
        ph_func_addr: *mut HCRYPTOIDFUNCADDR,
    ) -> BOOL;
}

/// Освободить адрес функции OID.
///
/// Источник: CSP_WinCrypt.h:3336
extern "C" {
    pub fn CryptFreeOIDFunctionAddress(
        h_func_addr: HCRYPTOIDFUNCADDR,
        dw_flags: DWORD,
    ) -> BOOL;
}

/// Установить адреса функций OID.
///
/// Источник: CSP_WinCrypt.h:2940
extern "C" {
    pub fn CryptInstallOIDFunctionAddress(
        h_module: HMODULE,
        dw_encoding_type: DWORD,
        psz_func_name: *const c_char,
        c_func_entry: DWORD,
        rg_func_entry: *const c_void, // *const CRYPT_OID_FUNC_ENTRY
        dw_flags: DWORD,
    ) -> BOOL;
}

/// Получить URL объекта.
///
/// Источник: CSP_WinCrypt.h:12363
extern "C" {
    pub fn CryptGetObjectUrl(
        psz_url_oid: *const c_char,
        pv_para: *mut c_void,
        dw_flags: DWORD,
        p_url_array: PCRYPT_URL_ARRAY,
        pcb_url_array: *mut DWORD,
        p_url_info: PCRYPT_URL_INFO,
        pcb_url_info: *mut DWORD,
        pv_reserved: *mut c_void,
    ) -> BOOL;
}

// ===========================================================================
// CryptMem* — память
// ===========================================================================

/// Выделить память через CryptoAPI.
///
/// Источник: CSP_WinCrypt.h:4276
extern "C" {
    pub fn CryptMemAlloc(cb_size: DWORD) -> *mut c_void;
}

/// Освободить память CryptoAPI.
///
/// Источник: CSP_WinCrypt.h:4291
extern "C" {
    pub fn CryptMemFree(pv: *mut c_void);
}

// ===========================================================================
// PFX* — PKCS#12
// ===========================================================================

/// Импортировать PKCS#12 хранилище.
///
/// Источник: CSP_WinCrypt.h:12784
extern "C" {
    pub fn PFXImportCertStore(
        p_pfx: *mut DataBlob,
        sz_password: *const u16,
        dw_flags: DWORD,
    ) -> HCERTSTORE;
}

/// Проверить, является ли blob PKCS#12.
///
/// Источник: CSP_WinCrypt.h:12809
extern "C" {
    pub fn PFXIsPFXBlob(p_pfx: *mut DataBlob) -> BOOL;
}

/// Проверить пароль PKCS#12.
///
/// Источник: CSP_WinCrypt.h:12826
extern "C" {
    pub fn PFXVerifyPassword(
        p_pfx: *mut DataBlob,
        sz_password: *const u16,
        dw_flags: DWORD,
    ) -> BOOL;
}

/// Экспортировать хранилище в PKCS#12 (расширенный).
///
/// Источник: CSP_WinCrypt.h:12860
extern "C" {
    pub fn PFXExportCertStoreEx(
        h_store: HCERTSTORE,
        p_pfx: *mut DataBlob,
        sz_password: *const u16,
        pv_reserved: *mut c_void,
        dw_flags: DWORD,
    ) -> BOOL;
}

/// Экспортировать хранилище в PKCS#12.
///
/// Источник: CSP_WinCrypt.h:12885
extern "C" {
    pub fn PFXExportCertStore(
        h_store: HCERTSTORE,
        p_pfx: *mut DataBlob,
        sz_password: *const u16,
        dw_flags: DWORD,
    ) -> BOOL;
}

// ===========================================================================
// LocalAlloc / LocalFree — память Windows
// ===========================================================================

/// Выделить локальную память.
///
/// Источник: CSP_WinDef.h:682
extern "C" {
    pub fn LocalAlloc(u_flags: UINT, u_bytes: usize) -> HLOCAL;
}

/// Освободить локальную память.
///
/// Источник: CSP_WinDef.h:687
extern "C" {
    pub fn LocalFree(h_mem: HLOCAL) -> HLOCAL;
}

// ===========================================================================
// CPCrypt* / CPGet* — CryptoPro-расширения
// ===========================================================================

/// Установить сертификат (CryptoPro extension).
///
/// Источник: capilite/CPCrypt.h:8
extern "C" {
    pub fn CPCryptInstallCertificate(
        h_prov: HCRYPTPROV,
        dw_key_spec: DWORD,
        pb_certificate: *const BYTE,
        cb_certificate: DWORD,
        pwsz_store_name: *const u16,
        dw_store_flags: DWORD,
        f_install_to_container: BOOL,
        pdw_install_to_container_status: *mut DWORD,
    ) -> BOOL;
}

/// Установить шаблон (CryptoPro extension).
///
/// Источник: capilite/CPCrypt.h:17
extern "C" {
    pub fn CPCryptInstallTemplate(
        h_prov: HCRYPTPROV,
        dw_key_spec: DWORD,
        dw_cert_encoding_type: DWORD,
        p_cert_request: *mut c_void, // *mut CERT_REQUEST_INFO
        pwsz_store_name: *const u16,
        dw_store_flags: DWORD,
    ) -> BOOL;
}

/// Получить OID информации о хеше по умолчанию.
///
/// Источник: capilite/CPCrypt.h:44
extern "C" {
    pub fn CPCryptGetDefaultHashOIDInfo(sz_pub_key_oid: *const c_char) -> PCCRYPT_OID_INFO;
}

/// Получить AlgId хеша провайдера.
///
/// Источник: capilite/CPCrypt.h:47
extern "C" {
    pub fn CPCryptGetProviderHashAlgId(
        h_crypt_prov: HCRYPTPROV,
        pub_key_obj_id: *const c_char,
    ) -> ALG_ID;
}

/// Получить AlgId хеша ГОСТ по умолчанию.
///
/// Источник: capilite/CPCrypt.h:50
extern "C" {
    pub fn CPGetDefaultGostHashAlgId(sz_pub_key_oid: *const c_char) -> ALG_ID;
}

/// Получить OID информации о подписи по умолчанию.
///
/// Источник: capilite/CPCrypt.h:52
extern "C" {
    pub fn CPCryptGetDefaultSignatureOIDInfo(
        sz_pub_key_oid: *const c_char,
    ) -> PCCRYPT_OID_INFO;
}

/// Получить OID информации о подписи.
///
/// Источник: capilite/CPCrypt.h:55
extern "C" {
    pub fn CPCryptGetSignatureOIDInfo(
        sz_pub_key_oid: *const c_char,
        sz_hash_oid: *const c_char,
    ) -> PCCRYPT_OID_INFO;
}

/// Получить OID информации о публичном ключе.
///
/// Источник: capilite/CPCrypt.h:58
extern "C" {
    pub fn CPCryptGetPublicKeyOIDInfo(
        sz_pub_key_oid: *const c_char,
        dw_key_spec: DWORD,
    ) -> PCCRYPT_OID_INFO;
}

/// Получить PIN через callback.
///
/// Источник: capilite/StoreUtil.h:96
extern "C" {
    pub fn CPCryptGetPinFromCallback(pin: *mut c_char, len: usize) -> BOOL;
}

/// Установить callback для PIN.
///
/// Источник: capilite/StoreUtil.h:97
extern "C" {
    pub fn CPCryptSetPinCallback(func: CRYPT_PIN_CALLBACK, arg: *mut c_void);
}

/// Получить callback для PIN.
///
/// Источник: capilite/StoreUtil.h:98
extern "C" {
    pub fn CPCryptGetPinCallback(func: *mut CRYPT_PIN_CALLBACK, arg: *mut *mut c_void);
}

// ===========================================================================
// SendPKIRequest — undocumented CryptoPro extension
// ===========================================================================

/// Отправить PKI-запрос.
///
/// **ВНИМАНИЕ:** Функция не задокументирована. Подпись является
/// предположительной и требует проверки.
///
/// Источник: nm -D libcapi20.so (экспортируемый символ без объявления в .h)
extern "C" {
    pub fn SendPKIRequest() -> DWORD;
}
