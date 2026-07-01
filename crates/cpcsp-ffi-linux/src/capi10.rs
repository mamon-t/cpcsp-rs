//! Raw FFI bindings for `libcapi10.so` — CryptoPro CSP core CryptoAPI.
//!
//! Эти функции составляют основной application-level API:
//! `CryptAcquireContext`, `CryptGenKey`, `CryptEncrypt`, `CryptSignHash` и т.д.
//!
/// Источник: `nm -D /opt/cprocsp/lib/amd64/libcapi10.so | grep ' T '`
/// Документация: CSP_WinCrypt.h, WinCryptEx.h

use std::ffi::c_void;

use crate::raw_types::*;

// ===========================================================================
// libcapi10.so — Core CryptoAPI functions
// ===========================================================================

#[link(name = "capi10")]
extern "C" {
    // -----------------------------------------------------------------------
    // Provider management
    // -----------------------------------------------------------------------

    /// Получить дескриптор криптографического провайдера.
    ///
    /// Источник: CSP_WinCrypt.h (CryptAcquireContext)
    /// See: <https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta>
    pub fn CryptAcquireContextA(
        ph_prov: *mut HCRYPTPROV,
        psz_container: LPCSTR,
        psz_provider: LPCSTR,
        dw_prov_type: DWORD,
        dw_flags: DWORD,
    ) -> BOOL;

    /// Unicode-версия CryptAcquireContext.
    pub fn CryptAcquireContextW(
        ph_prov: *mut HCRYPTPROV,
        pwsz_container: LPCWSTR,
        pwsz_provider: LPCWSTR,
        dw_prov_type: DWORD,
        dw_flags: DWORD,
    ) -> BOOL;

    /// Освободить дескриптор провайдера.
    pub fn CryptReleaseContext(h_prov: HCRYPTPROV, dw_flags: DWORD) -> BOOL;

    /// Увеличить счётчик ссылок на провайдер.
    pub fn CryptContextAddRef(h_prov: HCRYPTPROV, pdw_reserved: *mut DWORD, dw_flags: DWORD) -> BOOL;

    // -----------------------------------------------------------------------
    // Provider parameters
    // -----------------------------------------------------------------------

    /// Получить параметр провайдера.
    pub fn CryptGetProvParam(
        h_prov: HCRYPTPROV,
        dw_param: DWORD,
        pb_data: PBYTE,
        pdw_data_len: PDWORD,
        dw_flags: DWORD,
    ) -> BOOL;

    /// Установить параметр провайдера.
    pub fn CryptSetProvParam(
        h_prov: HCRYPTPROV,
        dw_param: DWORD,
        pb_data: *const BYTE,
        dw_flags: DWORD,
    ) -> BOOL;

    /// Перечислить провайдеры (ANSI).
    pub fn CryptEnumProvidersA(
        pdw_index: PDWORD,
        pdw_reserved: *mut DWORD,
        dw_flags: DWORD,
        pdw_prov_type: PDWORD,
        psz_prov_name: LPSTR,
        pcb_prov_name: PDWORD,
    ) -> BOOL;

    /// Перечислить провайдеры (Unicode).
    pub fn CryptEnumProvidersW(
        pdw_index: PDWORD,
        pdw_reserved: *mut DWORD,
        dw_flags: DWORD,
        pdw_prov_type: PDWORD,
        pwsz_prov_name: LPWSTR,
        pcb_prov_name: PDWORD,
    ) -> BOOL;

    /// Установить провайдер по умолчанию (ANSI).
    pub fn CryptSetProviderExA(
        psz_prov_name: LPCSTR,
        pdw_prov_type: PDWORD,
        pdw_reserved: *mut DWORD,
        dw_flags: DWORD,
    ) -> BOOL;

    /// Установить провайдер по умолчанию (Unicode).
    pub fn CryptSetProviderExW(
        pwsz_prov_name: LPCWSTR,
        pdw_prov_type: PDWORD,
        pdw_reserved: *mut DWORD,
        dw_flags: DWORD,
    ) -> BOOL;

    /// Получить провайдер по умолчанию (ANSI).
    pub fn CryptGetDefaultProviderA(
        dw_prov_type: DWORD,
        pdw_reserved: *mut DWORD,
        dw_flags: DWORD,
        psz_prov_name: LPSTR,
        pcb_prov_name: PDWORD,
    ) -> BOOL;

    /// Получить провайдер по умолчанию (Unicode).
    pub fn CryptGetDefaultProviderW(
        dw_prov_type: DWORD,
        pdw_reserved: *mut DWORD,
        dw_flags: DWORD,
        pwsz_prov_name: LPWSTR,
        pcb_prov_name: PDWORD,
    ) -> BOOL;

    // -----------------------------------------------------------------------
    // Key management
    // -----------------------------------------------------------------------

    /// Сгенерировать новый ключ.
    pub fn CryptGenKey(
        h_prov: HCRYPTPROV,
        alg_id: ALG_ID,
        dw_flags: DWORD,
        ph_key: *mut HCRYPTKEY,
    ) -> BOOL;

    /// Уничтожить ключ.
    pub fn CryptDestroyKey(h_key: HCRYPTKEY) -> BOOL;

    /// Произвести ключ на основе хеш-данных (KDF).
    pub fn CryptDeriveKey(
        h_prov: HCRYPTPROV,
        alg_id: ALG_ID,
        h_base_data: HCRYPTHASH,
        dw_flags: DWORD,
        ph_key: *mut HCRYPTKEY,
    ) -> BOOL;

    /// Импортировать ключ из бинарного блоба.
    pub fn CryptImportKey(
        h_prov: HCRYPTPROV,
        pb_data: *const BYTE,
        dw_data_len: DWORD,
        h_pub_key: HCRYPTKEY,
        dw_flags: DWORD,
        ph_key: *mut HCRYPTKEY,
    ) -> BOOL;

    /// Экспортировать ключ в бинарный блоб.
    pub fn CryptExportKey(
        h_key: HCRYPTKEY,
        h_exp_key: HCRYPTKEY,
        dw_blob_type: DWORD,
        dw_flags: DWORD,
        pb_data: PBYTE,
        pdw_data_len: PDWORD,
    ) -> BOOL;

    /// Получить дескриптор ключа пользователя (AT_KEYEXCHANGE или AT_SIGNATURE).
    pub fn CryptGetUserKey(
        h_prov: HCRYPTPROV,
        dw_key_spec: DWORD,
        ph_user_key: *mut HCRYPTKEY,
    ) -> BOOL;

    /// Продублировать ключ.
    pub fn CryptDuplicateKey(
        h_key: HCRYPTKEY,
        pdw_reserved: *mut DWORD,
        dw_flags: DWORD,
        ph_key: *mut HCRYPTKEY,
    ) -> BOOL;

    /// Получить параметр ключа.
    pub fn CryptGetKeyParam(
        h_key: HCRYPTKEY,
        dw_param: DWORD,
        pb_data: PBYTE,
        pdw_data_len: PDWORD,
        dw_flags: DWORD,
    ) -> BOOL;

    /// Установить параметр ключа.
    pub fn CryptSetKeyParam(
        h_key: HCRYPTKEY,
        dw_param: DWORD,
        pb_data: *const BYTE,
        dw_flags: DWORD,
    ) -> BOOL;

    // -----------------------------------------------------------------------
    // Hash management
    // -----------------------------------------------------------------------

    /// Создать хеш-объект.
    pub fn CryptCreateHash(
        h_prov: HCRYPTPROV,
        alg_id: ALG_ID,
        h_key: HCRYPTKEY,
        dw_flags: DWORD,
        ph_hash: *mut HCRYPTHASH,
    ) -> BOOL;

    /// Уничтожить хеш-объект.
    pub fn CryptDestroyHash(h_hash: HCRYPTHASH) -> BOOL;

    /// Продублировать хеш-объект.
    pub fn CryptDuplicateHash(
        h_hash: HCRYPTHASH,
        pdw_reserved: *mut DWORD,
        dw_flags: DWORD,
        ph_hash: *mut HCRYPTHASH,
    ) -> BOOL;

    /// Хешировать данные.
    pub fn CryptHashData(
        h_hash: HCRYPTHASH,
        pb_data: *const BYTE,
        dw_data_len: DWORD,
        dw_flags: DWORD,
    ) -> BOOL;

    /// Хешировать ключ сессии.
    pub fn CryptHashSessionKey(
        h_hash: HCRYPTHASH,
        h_key: HCRYPTKEY,
        dw_flags: DWORD,
    ) -> BOOL;

    /// Получить параметр хеша.
    pub fn CryptGetHashParam(
        h_hash: HCRYPTHASH,
        dw_param: DWORD,
        pb_data: PBYTE,
        pdw_data_len: PDWORD,
        dw_flags: DWORD,
    ) -> BOOL;

    /// Установить параметр хеша.
    pub fn CryptSetHashParam(
        h_hash: HCRYPTHASH,
        dw_param: DWORD,
        pb_data: *const BYTE,
        dw_flags: DWORD,
    ) -> BOOL;

    // -----------------------------------------------------------------------
    // Encryption / Decryption
    // -----------------------------------------------------------------------

    /// Зашифровать данные (in-place).
    pub fn CryptEncrypt(
        h_key: HCRYPTKEY,
        h_hash: HCRYPTHASH,
        final_: BOOL,
        dw_flags: DWORD,
        pb_data: PBYTE,
        pdw_data_len: PDWORD,
        dw_buf_len: DWORD,
    ) -> BOOL;

    /// Расшифровать данные (in-place).
    pub fn CryptDecrypt(
        h_key: HCRYPTKEY,
        h_hash: HCRYPTHASH,
        final_: BOOL,
        dw_flags: DWORD,
        pb_data: PBYTE,
        pdw_data_len: PDWORD,
    ) -> BOOL;

    // -----------------------------------------------------------------------
    // Sign / Verify
    // -----------------------------------------------------------------------

    /// Подписать хеш (ANSI).
    pub fn CryptSignHashA(
        h_hash: HCRYPTHASH,
        dw_key_spec: DWORD,
        s_description: LPCSTR,
        dw_flags: DWORD,
        pb_signature: PBYTE,
        pdw_sig_len: PDWORD,
    ) -> BOOL;

    /// Подписать хеш (Unicode).
    pub fn CryptSignHashW(
        h_hash: HCRYPTHASH,
        dw_key_spec: DWORD,
        s_description: LPCWSTR,
        dw_flags: DWORD,
        pb_signature: PBYTE,
        pdw_sig_len: PDWORD,
    ) -> BOOL;

    /// Проверить подпись (ANSI).
    pub fn CryptVerifySignatureA(
        h_hash: HCRYPTHASH,
        pb_signature: *const BYTE,
        dw_sig_len: DWORD,
        h_pub_key: HCRYPTKEY,
        s_description: LPCSTR,
        dw_flags: DWORD,
    ) -> BOOL;

    /// Проверить подпись (Unicode).
    pub fn CryptVerifySignatureW(
        h_hash: HCRYPTHASH,
        pb_signature: *const BYTE,
        dw_sig_len: DWORD,
        h_pub_key: HCRYPTKEY,
        s_description: LPCWSTR,
        dw_flags: DWORD,
    ) -> BOOL;

    // -----------------------------------------------------------------------
    // Random
    // -----------------------------------------------------------------------

    /// Сгенерировать псевдослучайные данные.
    pub fn CryptGenRandom(h_prov: HCRYPTPROV, dw_len: DWORD, pb_buffer: PBYTE) -> BOOL;

    // -----------------------------------------------------------------------
    // OID functions
    // -----------------------------------------------------------------------

    /// Найти информацию об OID.
    /// Возвращает указатель на CRYPT_OID_INFO (PCCRYPT_OID_INFO).
    pub fn CryptFindOIDInfo(
        dw_key_type: DWORD,
        pv_key: LPCVOID,
        dw_group_id: DWORD,
    ) -> *const c_void;

    /// Перечислить информацию об OID.
    pub fn CryptEnumOIDInfo(
        dw_group_id: DWORD,
        dw_flags: DWORD,
        pv_key: *const c_void,
        pfn_enum_oid_info: *const c_void, // PFN_CRYPT_ENUM_OID_INFO
    ) -> BOOL;

    // -----------------------------------------------------------------------
    // Утилиты
    // -----------------------------------------------------------------------

    /// Локальное выделение памяти (аналог Windows LocalAlloc).
    pub fn LocalAlloc(u_flags: UINT, u_bytes: SIZE_T) -> *mut c_void;

    /// Освободить локальную память.
    pub fn LocalFree(h_mem: *mut c_void) -> *mut c_void;

    /// Получить код последней ошибки.
    pub fn GetLastError() -> DWORD;

    /// Установить код ошибки.
    pub fn SetLastError(dw_err: DWORD) -> ();
}

/// Тип `UINT` из CSP_WinDef.h:179 — `typedef unsigned int UINT;`
pub type UINT = std::os::raw::c_uint;
