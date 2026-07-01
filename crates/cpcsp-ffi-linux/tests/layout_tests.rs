//! Layout tests — проверка что #[repr(C)] структуры Rust
//! точно совпадают по размерам и смещениям полей с C-аналогами.
//!
/// Источник размеров: компиляция check_layout.c с GCC на amd64 Linux.
/// Все значения получены через `sizeof()` и `offsetof()`.

use std::mem::{offset_of, size_of};
use cpcsp_ffi_linux::raw_types::*;

// ===========================================================================
// Scalar types
// ===========================================================================

#[test]
fn test_bool_size() {
    assert_eq!(size_of::<BOOL>(), 4);
}

#[test]
fn test_dword_size() {
    assert_eq!(size_of::<DWORD>(), 4);
}

#[test]
fn test_word_size() {
    assert_eq!(size_of::<WORD>(), 2);
}

#[test]
fn test_byte_size() {
    assert_eq!(size_of::<BYTE>(), 1);
}

#[test]
fn test_long_size() {
    assert_eq!(size_of::<LONG>(), 4);
}

#[test]
fn test_alg_id_size() {
    assert_eq!(size_of::<ALG_ID>(), 4);
}

#[test]
fn test_hcryptprov_size() {
    // ULONG_PTR = usize на amd64 = 8 bytes
    assert_eq!(size_of::<HCRYPTPROV>(), 8);
}

#[test]
fn test_hcryptkey_size() {
    assert_eq!(size_of::<HCRYPTKEY>(), 8);
}

#[test]
fn test_hcrysthash_size() {
    assert_eq!(size_of::<HCRYPTHASH>(), 8);
}

#[test]
fn test_hcryptmsg_size() {
    assert_eq!(size_of::<HCRYPTMSG>(), 8);
}

#[test]
fn test_hcertstore_size() {
    assert_eq!(size_of::<HCERTSTORE>(), 8);
}

// ===========================================================================
// Blob types
// ===========================================================================

#[test]
fn test_data_blob_size() {
    // CRYPT_INTEGER_BLOB: 16 bytes (cbData:4 + pad:4 + pbData:8)
    assert_eq!(size_of::<DataBlob>(), 16);
}

#[test]
fn test_data_blob_offsets() {
    assert_eq!(offset_of!(DataBlob, cb_data), 0);
    assert_eq!(offset_of!(DataBlob, pb_data), 8);
}

#[test]
fn test_crypt_integer_blob_is_data_blob() {
    // Алиасы должны иметь тот же layout
    assert_eq!(size_of::<CRYPT_INTEGER_BLOB>(), size_of::<DataBlob>());
}

#[test]
fn test_bit_blob_size() {
    // CRYPT_BIT_BLOB: 24 bytes
    assert_eq!(size_of::<CRYPT_BIT_BLOB>(), 24);
}

#[test]
fn test_bit_blob_offsets() {
    assert_eq!(offset_of!(CRYPT_BIT_BLOB, cb_data), 0);
    assert_eq!(offset_of!(CRYPT_BIT_BLOB, pb_data), 8);
    assert_eq!(offset_of!(CRYPT_BIT_BLOB, c_unused_bits), 16);
}

// ===========================================================================
// Algorithm identifier
// ===========================================================================

#[test]
fn test_crypt_algorithm_identifier_size() {
    // 24 bytes: pszObjId(8) + Parameters(16)
    assert_eq!(size_of::<CRYPT_ALGORITHM_IDENTIFIER>(), 24);
}

#[test]
fn test_crypt_algorithm_identifier_offsets() {
    assert_eq!(offset_of!(CRYPT_ALGORITHM_IDENTIFIER, psz_obj_id), 0);
    assert_eq!(offset_of!(CRYPT_ALGORITHM_IDENTIFIER, parameters), 8);
}

// ===========================================================================
// BLOBHEADER
// ===========================================================================

#[test]
fn test_blobheader_size() {
    // 8 bytes: bType(1) + bVersion(1) + reserved(2) + aiKeyAlg(4)
    assert_eq!(size_of::<BLOBHEADER>(), 8);
}

#[test]
fn test_blobheader_offsets() {
    assert_eq!(offset_of!(BLOBHEADER, b_type), 0);
    assert_eq!(offset_of!(BLOBHEADER, b_version), 1);
    assert_eq!(offset_of!(BLOBHEADER, reserved), 2);
    assert_eq!(offset_of!(BLOBHEADER, ai_key_alg), 4);
}

// ===========================================================================
// RSAPUBKEY
// ===========================================================================

#[test]
fn test_rsapubkey_size() {
    // 12 bytes: magic(4) + bitlen(4) + pubexp(4)
    assert_eq!(size_of::<RSAPUBKEY>(), 12);
}

#[test]
fn test_rsapubkey_offsets() {
    assert_eq!(offset_of!(RSAPUBKEY, magic), 0);
    assert_eq!(offset_of!(RSAPUBKEY, bitlen), 4);
    assert_eq!(offset_of!(RSAPUBKEY, pubexp), 8);
}

// ===========================================================================
// FILETIME
// ===========================================================================

#[test]
fn test_filetime_size() {
    assert_eq!(size_of::<FILETIME>(), 8);
}

#[test]
fn test_filetime_offsets() {
    assert_eq!(offset_of!(FILETIME, dw_low_date_time), 0);
    assert_eq!(offset_of!(FILETIME, dw_high_date_time), 4);
}

// ===========================================================================
// SYSTEMTIME
// ===========================================================================

#[test]
fn test_systemtime_size() {
    // 16 bytes: 8 x WORD(2)
    assert_eq!(size_of::<SYSTEMTIME>(), 16);
}

// ===========================================================================
// HMAC_INFO
// ===========================================================================

#[test]
fn test_hmac_info_size() {
    // 40 bytes: hashAlgId(4+pad) + pbInnerString(8) + cbInnerString(4+pad) +
    //           pbOuterString(8) + cbOuterString(4+pad)
    assert_eq!(size_of::<HMAC_INFO>(), 40);
}

// ===========================================================================
// PROV_ENUMALGS
// ===========================================================================

#[test]
fn test_prov_enumalgs_size() {
    // 32 bytes: aiAlgid(4) + dwBitLen(4) + dwNameLen(4) + szName[20]
    assert_eq!(size_of::<PROV_ENUMALGS>(), 32);
}

// ===========================================================================
// PROV_ENUMALGS_EX
// ===========================================================================

#[test]
fn test_prov_enumalgs_ex_size() {
    // 88 bytes: aiAlgid(4) + dwDefaultLen(4) + dwMinLen(4) + dwMaxLen(4) +
    //           dwProtocols(4) + dwNameLen(4) + szName[20] + dwLongNameLen(4) +
    //           szLongName[40]
    assert_eq!(size_of::<PROV_ENUMALGS_EX>(), 88);
}

// ===========================================================================
// CERT_EXTENSION
// ===========================================================================

#[test]
fn test_cert_extension_size() {
    // 32 bytes: pszObjId(8) + fCritical(4+pad) + Value(16)
    assert_eq!(size_of::<CERT_EXTENSION>(), 32);
}

#[test]
fn test_cert_extension_offsets() {
    assert_eq!(offset_of!(CERT_EXTENSION, psz_obj_id), 0);
    assert_eq!(offset_of!(CERT_EXTENSION, f_critical), 8);
    assert_eq!(offset_of!(CERT_EXTENSION, value), 16);
}

// ===========================================================================
// CERT_RDN_ATTR
// ===========================================================================

#[test]
fn test_cert_rdn_attr_size() {
    // 32 bytes: pszObjId(8) + dwValueType(4+pad) + Value(16)
    assert_eq!(size_of::<CERT_RDN_ATTR>(), 32);
}

// ===========================================================================
// CERT_RDN
// ===========================================================================

#[test]
fn test_cert_rdn_size() {
    // 16 bytes: cRDNAttr(4+pad) + prgRDNAttr(8)
    assert_eq!(size_of::<CERT_RDN>(), 16);
}

// ===========================================================================
// CERT_PUBLIC_KEY_INFO
// ===========================================================================

#[test]
fn test_cert_public_key_info_size() {
    // 48 bytes: Algorithm(24) + PublicKey(16)
    assert_eq!(size_of::<CERT_PUBLIC_KEY_INFO>(), 48);
}

// ===========================================================================
// CERT_INFO
// ===========================================================================

#[test]
fn test_cert_info_size() {
    // 208 bytes
    assert_eq!(size_of::<CERT_INFO>(), 208);
}

#[test]
fn test_cert_info_offsets() {
    assert_eq!(offset_of!(CERT_INFO, dw_version), 0);
    assert_eq!(offset_of!(CERT_INFO, serial_number), 8);
    assert_eq!(offset_of!(CERT_INFO, signature_algorithm), 24);
    assert_eq!(offset_of!(CERT_INFO, issuer), 48);
    assert_eq!(offset_of!(CERT_INFO, not_before), 64);
    assert_eq!(offset_of!(CERT_INFO, not_after), 72);
    assert_eq!(offset_of!(CERT_INFO, subject), 80);
    assert_eq!(offset_of!(CERT_INFO, subject_public_key_info), 96);
    assert_eq!(offset_of!(CERT_INFO, issuer_unique_id), 144);
    assert_eq!(offset_of!(CERT_INFO, subject_unique_id), 168);
    assert_eq!(offset_of!(CERT_INFO, c_extension), 192);
    assert_eq!(offset_of!(CERT_INFO, rg_extension), 200);
}

// ===========================================================================
// CERT_CONTEXT
// ===========================================================================

#[test]
fn test_cert_context_size() {
    // 40 bytes
    assert_eq!(size_of::<CERT_CONTEXT>(), 40);
}

#[test]
fn test_cert_context_offsets() {
    assert_eq!(offset_of!(CERT_CONTEXT, dw_cert_encoding_type), 0);
    assert_eq!(offset_of!(CERT_CONTEXT, pb_cert_encoded), 8);
    assert_eq!(offset_of!(CERT_CONTEXT, cb_cert_encoded), 16);
    assert_eq!(offset_of!(CERT_CONTEXT, p_cert_info), 24);
    assert_eq!(offset_of!(CERT_CONTEXT, h_cert_store), 32);
}

// ===========================================================================
// CERT_SIGNED_CONTENT_INFO
// ===========================================================================

#[test]
fn test_cert_signed_content_info_size() {
    assert_eq!(size_of::<CERT_SIGNED_CONTENT_INFO>(), 64);
}

// ===========================================================================
// CERT_REQUEST_INFO
// ===========================================================================

#[test]
fn test_cert_request_info_size() {
    assert_eq!(size_of::<CERT_REQUEST_INFO>(), 88);
}

// ===========================================================================
// CRL_ENTRY
// ===========================================================================

#[test]
fn test_crl_entry_size() {
    assert_eq!(size_of::<CRL_ENTRY>(), 40);
}

// ===========================================================================
// CRL_INFO
// ===========================================================================

#[test]
fn test_crl_info_size() {
    assert_eq!(size_of::<CRL_INFO>(), 96);
}

// ===========================================================================
// CRL_CONTEXT
// ===========================================================================

#[test]
fn test_crl_context_size() {
    assert_eq!(size_of::<CRL_CONTEXT>(), 40);
}

// ===========================================================================
// CTL_ENTRY
// ===========================================================================

#[test]
fn test_ctl_entry_size() {
    assert_eq!(size_of::<CTL_ENTRY>(), 32);
}

// ===========================================================================
// CTL_INFO
// ===========================================================================

#[test]
fn test_ctl_info_size() {
    assert_eq!(size_of::<CTL_INFO>(), 128);
}

// ===========================================================================
// CTL_CONTEXT
// ===========================================================================

#[test]
fn test_ctl_context_size() {
    assert_eq!(size_of::<CTL_CONTEXT>(), 64);
}

// ===========================================================================
// CRYPT_ATTRIBUTE
// ===========================================================================

#[test]
fn test_crypt_attribute_size() {
    assert_eq!(size_of::<CRYPT_ATTRIBUTE>(), 24);
}

// ===========================================================================
// CRYPT_ATTRIBUTES
// ===========================================================================

#[test]
fn test_crypt_attributes_size() {
    assert_eq!(size_of::<CRYPT_ATTRIBUTES>(), 16);
}

// ===========================================================================
// CRYPT_KEY_PROV_INFO
// ===========================================================================

#[test]
fn test_crypt_key_prov_info_size() {
    // 48 bytes
    assert_eq!(size_of::<CRYPT_KEY_PROV_INFO>(), 48);
}

#[test]
fn test_crypt_key_prov_info_offsets() {
    assert_eq!(offset_of!(CRYPT_KEY_PROV_INFO, pwsz_container_name), 0);
    assert_eq!(offset_of!(CRYPT_KEY_PROV_INFO, pwsz_prov_name), 8);
    assert_eq!(offset_of!(CRYPT_KEY_PROV_INFO, dw_prov_type), 16);
    assert_eq!(offset_of!(CRYPT_KEY_PROV_INFO, dw_flags), 20);
    assert_eq!(offset_of!(CRYPT_KEY_PROV_INFO, c_prov_param), 24);
    assert_eq!(offset_of!(CRYPT_KEY_PROV_INFO, rg_prov_param), 32);
    assert_eq!(offset_of!(CRYPT_KEY_PROV_INFO, dw_key_spec), 40);
}

// ===========================================================================
// CRYPT_KEY_PROV_PARAM
// ===========================================================================

#[test]
fn test_crypt_key_prov_param_size() {
    assert_eq!(size_of::<CRYPT_KEY_PROV_PARAM>(), 24);
}

// ===========================================================================
// CMS_DH_KEY_INFO
// ===========================================================================

#[test]
fn test_cms_dh_key_info_size() {
    // dwVersion(4) + Algid(4) + pszContentEncObjId(8) + PubInfo(16) + pReserved(8) = 40
    assert_eq!(size_of::<CMS_DH_KEY_INFO>(), 40);
}

// ===========================================================================
// VTABLEPROVSTRUC
// ===========================================================================

#[test]
fn test_vtableprovstruc_size() {
    // 56 bytes
    assert_eq!(size_of::<VTABLEPROVSTRUC>(), 56);
}

// ===========================================================================
// CERT_BASIC_CONSTRAINTS2_INFO
// ===========================================================================

#[test]
fn test_cert_basic_constraints2_info_size() {
    assert_eq!(size_of::<CERT_BASIC_CONSTRAINTS2_INFO>(), 8);
}

// ===========================================================================
// Новые структуры для capi20
// ===========================================================================

#[test]
fn test_cert_usage_match_size() {
    assert_eq!(size_of::<CERT_USAGE_MATCH>(), 24);
}

#[test]
fn test_cert_extensions_size() {
    assert_eq!(size_of::<CERT_EXTENSIONS>(), 16);
}

#[test]
fn test_cert_chain_para_size() {
    assert_eq!(size_of::<CERT_CHAIN_PARA>(), 32);
}

#[test]
fn test_cert_chain_policy_para_size() {
    assert_eq!(size_of::<CERT_CHAIN_POLICY_PARA>(), 16);
}

#[test]
fn test_cert_chain_policy_status_size() {
    assert_eq!(size_of::<CERT_CHAIN_POLICY_STATUS>(), 24);
}

#[test]
fn test_cert_revocation_para_size() {
    assert_eq!(size_of::<CERT_REVOCATION_PARA>(), 48);
}

#[test]
fn test_cert_revocation_status_size() {
    assert_eq!(size_of::<CERT_REVOCATION_STATUS>(), 24);
}

#[test]
fn test_cert_revocation_crl_info_size() {
    assert_eq!(size_of::<CERT_REVOCATION_CRL_INFO>(), 40);
}

#[test]
fn test_crypt_sign_message_para_size() {
    assert_eq!(size_of::<CRYPT_SIGN_MESSAGE_PARA>(), 120);
}

#[test]
fn test_crypt_sign_message_para_offsets() {
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, cb_size), 0);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, dw_msg_encoding_type), 4);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, p_signing_cert), 8);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, hash_algorithm), 16);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, pv_hash_aux_info), 40);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, c_msg_cert), 48);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, rgp_msg_cert), 56);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, c_msg_crl), 64);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, rgp_msg_crl), 72);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, c_auth_attr), 80);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, rg_auth_attr), 88);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, c_unauth_attr), 96);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, rg_unauth_attr), 104);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, dw_flags), 112);
    assert_eq!(offset_of!(CRYPT_SIGN_MESSAGE_PARA, dw_inner_content_type), 116);
}

#[test]
fn test_crypt_verify_message_para_size() {
    assert_eq!(size_of::<CRYPT_VERIFY_MESSAGE_PARA>(), 32);
}

#[test]
fn test_crypt_verify_message_para_offsets() {
    assert_eq!(offset_of!(CRYPT_VERIFY_MESSAGE_PARA, cb_size), 0);
    assert_eq!(offset_of!(CRYPT_VERIFY_MESSAGE_PARA, dw_msg_and_cert_encoding_type), 4);
    assert_eq!(offset_of!(CRYPT_VERIFY_MESSAGE_PARA, h_crypt_prov), 8);
    assert_eq!(offset_of!(CRYPT_VERIFY_MESSAGE_PARA, pfn_get_signer_certificate), 16);
    assert_eq!(offset_of!(CRYPT_VERIFY_MESSAGE_PARA, pv_get_arg), 24);
}

#[test]
fn test_crypt_encrypt_message_para_size() {
    assert_eq!(size_of::<CRYPT_ENCRYPT_MESSAGE_PARA>(), 56);
}

#[test]
fn test_crypt_encrypt_message_para_offsets() {
    assert_eq!(offset_of!(CRYPT_ENCRYPT_MESSAGE_PARA, cb_size), 0);
    assert_eq!(offset_of!(CRYPT_ENCRYPT_MESSAGE_PARA, dw_msg_encoding_type), 4);
    assert_eq!(offset_of!(CRYPT_ENCRYPT_MESSAGE_PARA, h_crypt_prov), 8);
    assert_eq!(offset_of!(CRYPT_ENCRYPT_MESSAGE_PARA, content_encryption_algorithm), 16);
    assert_eq!(offset_of!(CRYPT_ENCRYPT_MESSAGE_PARA, pv_encryption_aux_info), 40);
    assert_eq!(offset_of!(CRYPT_ENCRYPT_MESSAGE_PARA, dw_flags), 48);
    assert_eq!(offset_of!(CRYPT_ENCRYPT_MESSAGE_PARA, dw_inner_content_type), 52);
}

#[test]
fn test_crypt_decrypt_message_para_size() {
    assert_eq!(size_of::<CRYPT_DECRYPT_MESSAGE_PARA>(), 24);
}

#[test]
fn test_crypt_decrypt_message_para_offsets() {
    assert_eq!(offset_of!(CRYPT_DECRYPT_MESSAGE_PARA, cb_size), 0);
    assert_eq!(offset_of!(CRYPT_DECRYPT_MESSAGE_PARA, dw_msg_and_cert_encoding_type), 4);
    assert_eq!(offset_of!(CRYPT_DECRYPT_MESSAGE_PARA, c_cert_store), 8);
    assert_eq!(offset_of!(CRYPT_DECRYPT_MESSAGE_PARA, rgh_cert_store), 16);
}

#[test]
fn test_crypt_oid_info_size() {
    assert_eq!(size_of::<CRYPT_OID_INFO>(), 48);
}

#[test]
fn test_crypt_oid_info_offsets() {
    assert_eq!(offset_of!(CRYPT_OID_INFO, cb_size), 0);
    assert_eq!(offset_of!(CRYPT_OID_INFO, psz_oid), 8);
    assert_eq!(offset_of!(CRYPT_OID_INFO, pwsz_name), 16);
    assert_eq!(offset_of!(CRYPT_OID_INFO, dw_group_id), 24);
    assert_eq!(offset_of!(CRYPT_OID_INFO, alg_id), 28);
    assert_eq!(offset_of!(CRYPT_OID_INFO, extra_info), 32);
}

#[test]
fn test_crypt_oid_func_entry_size() {
    assert_eq!(size_of::<CRYPT_OID_FUNC_ENTRY>(), 16);
}

#[test]
fn test_cmsg_stream_info_size() {
    assert_eq!(size_of::<CMSG_STREAM_INFO>(), 24);
}

#[test]
fn test_cmsg_stream_info_offsets() {
    assert_eq!(offset_of!(CMSG_STREAM_INFO, cb_content), 0);
    assert_eq!(offset_of!(CMSG_STREAM_INFO, pfn_stream_output), 8);
    assert_eq!(offset_of!(CMSG_STREAM_INFO, pv_arg), 16);
}

#[test]
fn test_crypt_url_array_size() {
    assert_eq!(size_of::<CRYPT_URL_ARRAY>(), 16);
}

#[test]
fn test_crypt_url_info_size() {
    assert_eq!(size_of::<CRYPT_URL_INFO>(), 24);
}

#[test]
fn test_crypt_url_info_offsets() {
    assert_eq!(offset_of!(CRYPT_URL_INFO, cb_size), 0);
    assert_eq!(offset_of!(CRYPT_URL_INFO, dw_sync_delta_time), 4);
    assert_eq!(offset_of!(CRYPT_URL_INFO, c_group), 8);
    assert_eq!(offset_of!(CRYPT_URL_INFO, rgc_group_entry), 16);
}
