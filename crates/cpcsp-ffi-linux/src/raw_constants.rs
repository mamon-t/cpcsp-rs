//! Raw FFI constants for CryptoPro CSP 5.0 on Linux.
//!
//! Константы сгруппированы по категориям, соответствующим группам
//! в исходных заголовках КриптоПро:
//! - Provider types и ProvParam
//! - AcquireContext / GenKey / ExportKey flags
//! - ALG_ID (алгоритмы)
//! - Key parameters (KP_*)
//! - Hash parameters (HP_*)
//! - Provider parameters (PP_*)
//! - Certificate store flags
//! - Key blob types
//! - Encoding types
//!
/// Источники: CSP_WinCrypt.h, WinCryptEx.h

use crate::raw_types::DWORD;

// ===========================================================================
// Provider types (CSP_WinCrypt.h:487+, WinCryptEx.h:307+)
// ===========================================================================

/// Типы провайдеров КриптоПро.
/// Источник: WinCryptEx.h:307-326
pub const PROV_GOST_DH: DWORD = 2;             // deprecated
pub const PROV_GOST_94_DH: DWORD = 71;         // deprecated
pub const PROV_GOST_2001_DH: DWORD = 75;
pub const PROV_GOST_2012_256: DWORD = 80;
pub const PROV_GOST_2012_512: DWORD = 81;
pub const PROV_RSA_AES: DWORD = 24;
pub const PROV_EC_CURVE25519: DWORD = 32;

// ===========================================================================
// CryptAcquireContext flags (CSP_WinCrypt.h:253-259, WinCryptEx.h:355+)
// ===========================================================================

pub const CRYPT_VERIFYCONTEXT: DWORD = 0xF0000000;
pub const CRYPT_NEWKEYSET: DWORD = 0x00000008;
pub const CRYPT_DELETEKEYSET: DWORD = 0x00000010;
pub const CRYPT_MACHINE_KEYSET: DWORD = 0x00000020;
pub const CRYPT_SILENT: DWORD = 0x00000040;
pub const CRYPT_DEFAULT_CONTAINER_OPTIONAL: DWORD = 0x00000080;

/// Дополнительные флаги AcquireContext (КриптоПро-специфичные).
/// Источник: WinCryptEx.h:355-364
pub const CRYPT_GENERAL: DWORD = 0x00004000;
pub const CRYPT_NOSERIALIZE: DWORD = 0x00010000;
pub const CRYPT_REBOOT: DWORD = 0x00020000;
pub const CRYPT_PROMT_INSERT_MEDIA: DWORD = 0x00040000;
pub const CRYPT_UECDATACONTEXT: DWORD = 0x00080000;
pub const CRYPT_CMS_HIGHLOAD_NOSERIALIZE: DWORD = 0x00100000;
pub const CRYPT_LOCAL_PASSWORD_CACHE: DWORD = 0x00200000;
pub const CRYPT_NO_CONTAINER_CACHE: DWORD = 0x00400000;

// ===========================================================================
// CryptGenKey flags (CSP_WinCrypt.h:262-278)
// ===========================================================================

pub const CRYPT_EXPORTABLE: DWORD = 0x00000001;
pub const CRYPT_USER_PROTECTED: DWORD = 0x00000002;
pub const CRYPT_CREATE_SALT: DWORD = 0x00000004;
pub const CRYPT_UPDATE_KEY: DWORD = 0x00000008;
pub const CRYPT_NO_SALT: DWORD = 0x00000010;
pub const CRYPT_PREGEN: DWORD = 0x00000040;
pub const CRYPT_RECIPIENT: DWORD = 0x00000010;
pub const CRYPT_INITIATOR: DWORD = 0x00000040;
pub const CRYPT_ONLINE: DWORD = 0x00000080;
pub const CRYPT_SF: DWORD = 0x00000100;
pub const CRYPT_CREATE_IV: DWORD = 0x00000200;
pub const CRYPT_KEK: DWORD = 0x00000400;
pub const CRYPT_DATA_KEY: DWORD = 0x00000800;
pub const CRYPT_VOLATILE: DWORD = 0x00001000;
pub const CRYPT_SGCKEY: DWORD = 0x00002000;
pub const CRYPT_ARCHIVABLE: DWORD = 0x00004000;
pub const CRYPT_FORCE_KEY_PROTECTION_HIGH: DWORD = 0x00008000;

/// КриптоПро-специфичные флаги GenKey.
/// Источник: WinCryptEx.h:443-475
pub const CRYPT_ECCNEGATIVE: DWORD = 0x00000400;
pub const CRYPT_PUBLICCOMPRESS: DWORD = 0x00000800;
pub const CP_CRYPT_DH_ALLOWED: DWORD = 0x00002000;
pub const CP_CREATE_TLS_PREMASTER: DWORD = 0x00004000;
pub const CP_FORCE_GOST_DH: DWORD = 0x00008000;
pub const CP_CRYPT_CALCULATE_PUBLIC_KEY: DWORD = 0x00000080;

// ===========================================================================
// CryptDeriveKey flags (CSP_WinCrypt.h:281)
// ===========================================================================

pub const CRYPT_SERVER: DWORD = 0x00000400;

// ===========================================================================
// CryptExportKey flags (CSP_WinCrypt.h:286-298)
// ===========================================================================

pub const CRYPT_Y_ONLY: DWORD = 0x00000001;
pub const CRYPT_SSL2_FALLBACK: DWORD = 0x00000002;
pub const CRYPT_DESTROYKEY: DWORD = 0x00000004;
pub const CRYPT_OAEP: DWORD = 0x00000040;
pub const CRYPT_BLOB_VER3: DWORD = 0x00000080;
pub const CRYPT_DECRYPT_RSA_NO_PADDING_CHECK: DWORD = 0x00000020;

/// КриптоПро-специфичные флаги ImportKey/ExportKey.
/// Источник: WinCryptEx.h:477-495
pub const CP_CRYPT_PKUP_ATTRIBUTE: DWORD = 0x00800000;
pub const CP_PUBKEY_REUSABLE: DWORD = 0x00002000;
pub const CP_PRIMITIVE_PUBLICKEYBLOB: DWORD = 0x00000020;
pub const CP_AUTH_TAG_DISABLED: DWORD = 0x10000000;

// ===========================================================================
// CryptCreateHash flags (CSP_WinCrypt.h:301)
// ===========================================================================

pub const CRYPT_SECRETDIGEST: DWORD = 0x00000001;

// ===========================================================================
// CryptHashSessionKey flags (CSP_WinCrypt.h:304)
// ===========================================================================

pub const CRYPT_LITTLE_ENDIAN: DWORD = 0x00000001;

// ===========================================================================
// CryptSignHash / CryptVerifySignature flags (CSP_WinCrypt.h:307-309)
// ===========================================================================

pub const CRYPT_NOHASHOID: DWORD = 0x00000001;
pub const CRYPT_TYPE2_FORMAT: DWORD = 0x00000002;
pub const CRYPT_X931_FORMAT: DWORD = 0x00000004;

/// КриптоПро-специфичные флаги SignHash/VerifySignature.
/// Источник: WinCryptEx.h:512-519
pub const CP_ECC_PLAIN_SIGNATURE: DWORD = 0x00000008;
pub const CP_CONTANER_AFFECTED_SIGNATURE: DWORD = 0x00000010;
pub const CP_ECC_PLAIN_SIGNATURE_CNG_REVERSED: DWORD = 0x00000020;
pub const CP_PSEUDO_RANDOM_K_ONLY: DWORD = 0x00000040;
pub const CRYPT_RSA_PSS: DWORD = 0x00000080;
pub const CP_ECC_SIGNATURE_RECOVERY_ID: DWORD = 0x00000100;
pub const CP_KDF_FOR_SIGN_PUBLIC_KEY: DWORD = 0x00000200;

// ===========================================================================
// Key blob types (CSP_WinCrypt.h:317-323)
// ===========================================================================

pub const SIMPLEBLOB: DWORD = 0x1;
pub const PUBLICKEYBLOB: DWORD = 0x6;
pub const PRIVATEKEYBLOB: DWORD = 0x7;
pub const PLAINTEXTKEYBLOB: DWORD = 0x8;
pub const OPAQUEKEYBLOB: DWORD = 0x9;
pub const PUBLICKEYBLOBEX: DWORD = 0xA;
pub const SYMMETRICWRAPKEYBLOB: DWORD = 0xB;

// ===========================================================================
// ALG_CLASS / ALG_TYPE / ALG_SID (CSP_WinCrypt.h:86-178)
// ===========================================================================

pub const ALG_CLASS_ANY: DWORD = 0;
pub const ALG_CLASS_SIGNATURE: DWORD = 1 << 13;
pub const ALG_CLASS_MSG_ENCRYPT: DWORD = 2 << 13;
pub const ALG_CLASS_DATA_ENCRYPT: DWORD = 3 << 13;
pub const ALG_CLASS_HASH: DWORD = 4 << 13;
pub const ALG_CLASS_KEY_EXCHANGE: DWORD = 5 << 13;

pub const ALG_TYPE_ANY: DWORD = 0;
pub const ALG_TYPE_DSS: DWORD = 1 << 9;
pub const ALG_TYPE_RSA: DWORD = 2 << 9;
pub const ALG_TYPE_BLOCK: DWORD = 3 << 9;
pub const ALG_TYPE_STREAM: DWORD = 4 << 9;
pub const ALG_TYPE_DH: DWORD = 5 << 9;
pub const ALG_TYPE_SECURECHANNEL: DWORD = 6 << 9;

pub const ALG_SID_MD2: DWORD = 1;
pub const ALG_SID_MD4: DWORD = 2;
pub const ALG_SID_MD5: DWORD = 3;
pub const ALG_SID_SHA: DWORD = 4;
pub const ALG_SID_SHA1: DWORD = 4;
pub const ALG_SID_SSL3SHAMD5: DWORD = 8;

// ===========================================================================
// CALG_* — Algorithm IDs (CSP_WinCrypt.h:203-232, WinCryptEx.h:968+)
// ===========================================================================

pub const CALG_MD2: DWORD = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD2;
pub const CALG_MD4: DWORD = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD4;
pub const CALG_MD5: DWORD = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5;
pub const CALG_SHA: DWORD = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA;
pub const CALG_SHA1: DWORD = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1;

pub const CALG_RSA_SIGN: DWORD = ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | 0;
pub const CALG_RSA_KEYX: DWORD = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | 0;
pub const CALG_DES: DWORD = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 1;
pub const CALG_3DES: DWORD = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 3;
pub const CALG_RC2: DWORD = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 2;
pub const CALG_RC4: DWORD = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | 1;

/// CryptoPro GOST 2012 256-bit key generation / exchange.
/// Определено эмпирически (0x2400).
pub const CALG_GOST_2012_256: DWORD = 0x2400;

/// CryptoPro GOST 2012 512-bit key generation / exchange.
/// Определено эмпирически (0x2401).
pub const CALG_GOST_2012_512: DWORD = 0x2401;

/// GOST R 34.11-2012 256-bit hash (Стрибог-256).
/// Определено эмпирически: 32 bytes output.
pub const CALG_GOST_34_11_2012_256: DWORD = 0x8021;

/// GOST R 34.11-2012 512-bit hash (Стрибог-512).
/// Определено эмпирически: 64 bytes output.
pub const CALG_GOST_34_11_2012_512: DWORD = 0x8022;

// ===========================================================================
// AT_* key spec constants (CSP_WinCrypt.h:325-326)
// ===========================================================================

pub const AT_KEYEXCHANGE: DWORD = 1;
pub const AT_SIGNATURE: DWORD = 2;

/// КриптоПро: специфические KeySpec.
/// Источник: WinCryptEx.h:666-668
pub const AT_SYMMETRIC: DWORD = 0x80000005;

// ===========================================================================
// KP_* key parameters (CSP_WinCrypt.h:331-371)
// ===========================================================================

pub const KP_IV: DWORD = 1;
pub const KP_SALT: DWORD = 2;
pub const KP_PADDING: DWORD = 3;
pub const KP_MODE: DWORD = 4;
pub const KP_MODE_BITS: DWORD = 5;
pub const KP_PERMISSIONS: DWORD = 6;
pub const KP_ALGID: DWORD = 7;
pub const KP_BLOCKLEN: DWORD = 8;
pub const KP_KEYLEN: DWORD = 9;
pub const KP_SALT_EX: DWORD = 10;
pub const KP_P: DWORD = 11;
pub const KP_G: DWORD = 12;
pub const KP_Q: DWORD = 13;
pub const KP_X: DWORD = 14;
pub const KP_Y: DWORD = 15;
pub const KP_RA: DWORD = 16;
pub const KP_RB: DWORD = 17;
pub const KP_INFO: DWORD = 18;
pub const KP_EFFECTIVE_KEYLEN: DWORD = 19;
pub const KP_SCHANNEL_ALG: DWORD = 20;
pub const KP_CLIENT_RANDOM: DWORD = 21;
pub const KP_SERVER_RANDOM: DWORD = 22;
pub const KP_RP: DWORD = 23;
pub const KP_PRECOMP_MD5: DWORD = 24;
pub const KP_PRECOMP_SHA: DWORD = 25;
pub const KP_CERTIFICATE: DWORD = 26;
pub const KP_CLEAR_KEY: DWORD = 27;
pub const KP_PUB_EX_LEN: DWORD = 28;
pub const KP_PUB_EX_VAL: DWORD = 29;
pub const KP_KEYVAL: DWORD = 30;
pub const KP_ADMIN_PIN: DWORD = 31;
pub const KP_KEYEXCHANGE_PIN: DWORD = 32;
pub const KP_SIGNATURE_PIN: DWORD = 33;
pub const KP_PREHASH: DWORD = 34;
pub const KP_OAEP_PARAMS: DWORD = 36;
pub const KP_CMS_KEY_INFO: DWORD = 37;
pub const KP_CMS_DH_KEY_INFO: DWORD = 38;
pub const KP_PUB_PARAMS: DWORD = 39;
pub const KP_VERIFY_PARAMS: DWORD = 40;
pub const KP_HIGHEST_VERSION: DWORD = 41;

/// КриптоПро-специфичные KP_*.
/// Источник: WinCryptEx.h:446-495
pub const KP_ADDX: DWORD = 50;               // Условный — из примеров
pub const KP_AUTH_TAG: DWORD = 51;
pub const KP_STORE: DWORD = 52;
pub const CP_CRYPT_DATA_HANDLE: DWORD = 0x00000010;
pub const CP_MAKE_EXPORTABLE: DWORD = 0x00000020;

// ===========================================================================
// KP_PADDING values (CSP_WinCrypt.h:374-376)
// ===========================================================================

pub const PKCS5_PADDING: DWORD = 1;
pub const RANDOM_PADDING: DWORD = 2;
pub const ZERO_PADDING: DWORD = 3;

/// КриптоПро-специфичные padding types.
/// Источник: WinCryptEx.h:498-503
pub const ISO10126_PADDING: DWORD = 4;
pub const ANSI_X923_PADDING: DWORD = 5;
pub const TLS_1_0_PADDING: DWORD = 6;
pub const ISO_IEC_7816_4_PADDING: DWORD = 7;
pub const TLS_1_0_MAX_PADDING_LENGTH: DWORD = 256;

// ===========================================================================
// KP_MODE values (CSP_WinCrypt.h:379-383)
// ===========================================================================

pub const CRYPT_MODE_CBC: DWORD = 1;
pub const CRYPT_MODE_ECB: DWORD = 2;
pub const CRYPT_MODE_OFB: DWORD = 3;
pub const CRYPT_MODE_CFB: DWORD = 4;
pub const CRYPT_MODE_CTS: DWORD = 5;

// ===========================================================================
// KP_PERMISSIONS flags (CSP_WinCrypt.h:386-394)
// ===========================================================================

pub const CRYPT_ENCRYPT: DWORD = 0x0001;
pub const CRYPT_DECRYPT: DWORD = 0x0002;
pub const CRYPT_EXPORT: DWORD = 0x0004;
pub const CRYPT_READ: DWORD = 0x0008;
pub const CRYPT_WRITE: DWORD = 0x0010;
pub const CRYPT_MAC: DWORD = 0x0020;
pub const CRYPT_EXPORT_KEY: DWORD = 0x0040;
pub const CRYPT_IMPORT_KEY: DWORD = 0x0080;
pub const CRYPT_ARCHIVE: DWORD = 0x0100;

/// КриптоПро-специфичные разрешения.
/// Источник: WinCryptEx.h:457
pub const CP_CRYPT_DH_PERMISSION: DWORD = 0x00010000;
pub const CP_CRYPT_REWRITABLE: DWORD = 0x00020000;

// ===========================================================================
// HP_* hash parameters (CSP_WinCrypt.h:396-401)
// ===========================================================================

pub const HP_ALGID: DWORD = 0x0001;
pub const HP_HASHVAL: DWORD = 0x0002;
pub const HP_HASHSIZE: DWORD = 0x0004;
pub const HP_HMAC_INFO: DWORD = 0x0005;
pub const HP_TLS1PRF_LABEL: DWORD = 0x0006;
pub const HP_TLS1PRF_SEED: DWORD = 0x0007;

// ===========================================================================
// PP_* provider parameters (CSP_WinCrypt.h:412-444)
// ===========================================================================

pub const PP_ENUMALGS: DWORD = 1;
pub const PP_ENUMCONTAINERS: DWORD = 2;
pub const PP_IMPTYPE: DWORD = 3;
pub const PP_NAME: DWORD = 4;
pub const PP_VERSION: DWORD = 5;
pub const PP_CONTAINER: DWORD = 6;
pub const PP_CHANGE_PASSWORD: DWORD = 7;
pub const PP_KEYSET_SEC_DESCR: DWORD = 8;
pub const PP_CERTCHAIN: DWORD = 9;
pub const PP_KEY_TYPE_SUBTYPE: DWORD = 10;
pub const PP_PROVTYPE: DWORD = 16;
pub const PP_KEYSTORAGE: DWORD = 17;
pub const PP_APPLI_CERT: DWORD = 18;
pub const PP_SYM_KEYSIZE: DWORD = 19;
pub const PP_SESSION_KEYSIZE: DWORD = 20;
pub const PP_UI_PROMPT: DWORD = 21;
pub const PP_ENUMALGS_EX: DWORD = 22;
pub const PP_ENUMMANDROOTS: DWORD = 25;
pub const PP_ENUMELECTROOTS: DWORD = 26;
pub const PP_KEYSET_TYPE: DWORD = 27;
pub const PP_ADMIN_PIN: DWORD = 31;
pub const PP_KEYEXCHANGE_PIN: DWORD = 32;
pub const PP_SIGNATURE_PIN: DWORD = 33;
pub const PP_SIG_KEYSIZE_INC: DWORD = 34;
pub const PP_KEYX_KEYSIZE_INC: DWORD = 35;
pub const PP_UNIQUE_CONTAINER: DWORD = 36;
pub const PP_SGC_INFO: DWORD = 37;
pub const PP_USE_HARDWARE_RNG: DWORD = 38;
pub const PP_KEYSPEC: DWORD = 39;
pub const PP_ENUMEX_SIGNING_PROT: DWORD = 40;
pub const PP_CRYPT_COUNT_KEY_USE: DWORD = 41;
pub const PP_USER_CERTSTORE: DWORD = 42;
pub const PP_SMARTCARD_READER: DWORD = 43;
pub const PP_SMARTCARD_GUID: DWORD = 45;
pub const PP_ROOT_CERTSTORE: DWORD = 46;

/// КриптоПро-специфичные PP_*.
/// Источник: WinCryptEx.h:400-416
pub const CP_CRYPT_SAVE_PASSWORD: DWORD = 0x00001000;
pub const CP_CRYPT_CACHE_ONLY: DWORD = 0x00002000;
pub const CP_CRYPT_SERIALIZED_STORE: DWORD = 0x00004000;

// ===========================================================================
// PP_ENUMALGS / PP_ENUMCONTAINERS flags
// ===========================================================================

pub const CRYPT_FIRST: DWORD = 1;
pub const CRYPT_NEXT: DWORD = 2;
pub const CRYPT_SGC_ENUM: DWORD = 4;

// ===========================================================================
// Implementation types (CSP_WinCrypt.h:453-457)
// ===========================================================================

pub const CRYPT_IMPL_HARDWARE: DWORD = 1;
pub const CRYPT_IMPL_SOFTWARE: DWORD = 2;
pub const CRYPT_IMPL_MIXED: DWORD = 3;
pub const CRYPT_IMPL_UNKNOWN: DWORD = 4;
pub const CRYPT_IMPL_REMOVABLE: DWORD = 8;

// ===========================================================================
// CERT_CONTEXT property IDs (CSP_WinCrypt.h)
// ===========================================================================

pub const CERT_KEY_PROV_HANDLE_PROP_ID: DWORD = 1;
pub const CERT_KEY_PROV_INFO_PROP_ID: DWORD = 2;
pub const CERT_SHA1_HASH_PROP_ID: DWORD = 3;
pub const CERT_MD5_HASH_PROP_ID: DWORD = 4;
pub const CERT_HASH_PROP_ID: DWORD = CERT_SHA1_HASH_PROP_ID;
pub const CERT_KEY_IDENTIFIER_PROP_ID: DWORD = 20;
pub const CERT_CERT_PROP_ID: DWORD = 32;
pub const CERT_CROSS_CERT_DIST_POINTS_PROP_ID: DWORD = 33;
pub const CERT_AUTO_ENROLL_PROP_ID: DWORD = 34;
pub const CERT_EXTENSIONS_PROP_ID: DWORD = 36;
pub const CERT_NEXT_UPDATE_LOCATION_PROP_ID: DWORD = 49;
pub const CERT_FRIENDLY_NAME_PROP_ID: DWORD = 11;
pub const CERT_DESCRIPTION_PROP_ID: DWORD = 13;

/// КриптоПро-специфичные property IDs.
/// Источник: WinCryptEx.h:344-346
pub const CP_CERT_SHADOW_CERT_PROP_ID: DWORD = 0x0000FF00;
pub const CP_CERT_LINKED_CERT_PROP_ID: DWORD = 0x0000FF01;

// ===========================================================================
// CertOpenStoredwFlags (CSP_WinCrypt.h)
// ===========================================================================

pub const CERT_STORE_NO_CRL_RELEASE: DWORD = 0x00000200;
pub const CERT_STORE_SET_LOCALIZED_NAME_FLAG: DWORD = 0x00000002;
pub const CERT_STORE_BACKUP_RESTORE_FLAG: DWORD = 0x00000400;
pub const CERT_STORE_READONLY_FLAG: DWORD = 0x00008000;
pub const CERT_STORE_OPEN_EXISTING_FLAG: DWORD = 0x00004000;
pub const CERT_STORE_CREATE_NEW_FLAG: DWORD = 0x00002000;
pub const CERT_STORE_UPDATE_KEYID_FLAG: DWORD = 0x00001000;

// System store flags
pub const CERT_SYSTEM_STORE_CURRENT_USER: DWORD = 0x00010000;
pub const CERT_SYSTEM_STORE_LOCAL_MACHINE: DWORD = 0x00020000;
pub const CERT_SYSTEM_STORE_CURRENT_SERVICE: DWORD = 0x00040000;
pub const CERT_SYSTEM_STORE_SERVICES: DWORD = 0x00080000;
pub const CERT_SYSTEM_STORE_USERS: DWORD = 0x00100000;

// ===========================================================================
// CRYPT_* encoding types (CSP_WinCrypt.h:340)
// ===========================================================================

pub const CRYPT_ASN_ENCODING: DWORD = 0x00000001;
pub const CRYPT_NDR_ENCODING: DWORD = 0x00000002;
pub const CRYPT_XER_ENCODING: DWORD = 0x00000008;

// ===========================================================================
// CMSG_* constants (CSP_WinCrypt.h)
// ===========================================================================

// CMSG_* flags для CryptMsgOpenToEncode/CryptMsgControl
pub const CMSG_CACHED_UNLINKED_SIGNER_FLAG: DWORD = 0x10;

/// КриптоПро CAdES-BES флаги.
/// Источник: WinCryptEx.h:420-440
pub const CPCMSG_CADES_STRICT: DWORD = 0x00000100;
pub const CPCMSG_CADES_DISABLE: DWORD = 0x00000200;
pub const CPCMSG_CADES_DISABLE_CERT_SEARCH: DWORD = 0x00000400;
pub const CPCMSG_DTBS_CONTENT: DWORD = 0x00000800;
pub const CPCMSG_DTBS_ATTRIBUTE: DWORD = 0x00001000;
pub const CPCMSG_DTBS_CERTIFICATE: DWORD = 0x00002000;

pub const CPCRYPT_MESSAGE_CADES_STRICT: DWORD = CPCMSG_CADES_STRICT;
pub const CPCRYPT_MESSAGE_CADES_DISABLE: DWORD = CPCMSG_CADES_DISABLE;
pub const CPCRYPT_MESSAGE_DTBS_CONTENT: DWORD = CPCMSG_DTBS_CONTENT;
pub const CPCRYPT_MESSAGE_DTBS_ATTRIBUTE: DWORD = CPCMSG_DTBS_ATTRIBUTE;

// ===========================================================================
// KEY_LENGTH_MASK (CSP_WinCrypt.h:283)
// ===========================================================================

pub const KEY_LENGTH_MASK: DWORD = 0xFFFF0000;

// ===========================================================================
// CUR_BLOB_VERSION (CSP_WinCrypt.h:506)
// ===========================================================================

pub const CUR_BLOB_VERSION: DWORD = 2;

// ===========================================================================
// SIGNATURE_RESOURCE_NUMBER (CSP_WinCrypt.h:245)
// ===========================================================================

pub const SIGNATURE_RESOURCE_NUMBER: DWORD = 0x29A;

// ===========================================================================
// CRYPT_SUCCEEDED / CRYPT_FAILED (CSP_WinCrypt.h:403-407)
// ===========================================================================

pub const CRYPT_FAILED: BOOL = 0;   // FALSE
pub const CRYPT_SUCCEED: BOOL = 1;  // TRUE

use crate::raw_types::BOOL;

// ===========================================================================
// Container types (WinCryptEx.h:329-332)
// ===========================================================================

pub const KEY_CARRIER_VERSION_V1: DWORD = 1;
pub const KEY_CARRIER_VERSION_V2: DWORD = 2;
pub const KEY_CARRIER_VERSION_V3: DWORD = 3; // FKC-1, unused in 5.0
pub const KEY_CARRIER_VERSION_V4: DWORD = 4; // FKC-2

// ===========================================================================
// CERT_CREATE_SELFSIGN flags (WinCryptEx.h:9990-9991)
// ===========================================================================

pub const CERT_CREATE_SELFSIGN_NO_SIGN: DWORD = 1;
pub const CERT_CREATE_SELFSIGN_NO_KEY_INFO: DWORD = 2;

// ===========================================================================
// CMS_BLOCKLEN_TAG (WinCryptEx.h:521)
// ===========================================================================

pub const CMS_BLOCKLEN_TAG: DWORD = b'B' as DWORD;

// ===========================================================================
// EC key flags (WinCryptEx.h:447-448)
// ===========================================================================

pub const EC_PLUS: DWORD = 0;
pub const EC_MINUS: DWORD = 1;
pub const SAVE_AUTH_TAG: DWORD = 0x100;

// ===========================================================================
// Encoding types — X509 / PKCS_7 (CSP_WinCrypt.h:344-350)
// ===========================================================================

/// X.509 ASN.1 encoding.
pub const X509_ASN_ENCODING: DWORD = 0x00000001;

/// PKCS #7 ASN.1 encoding.
pub const PKCS_7_ASN_ENCODING: DWORD = 0x00010000;

/// Combined encoding: X509 + PKCS_7.
pub const X509_PKCS_7_ASN_ENCODING: DWORD = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

// ===========================================================================
// CertCloseStore flags (CSP_WinCrypt.h:4753)
// ===========================================================================

pub const CERT_CLOSE_STORE_FORCE_FLAG: DWORD = 0x00000001;
pub const CERT_CLOSE_STORE_CHECK_FLAG: DWORD = 0x00000002;

// ===========================================================================
// CertFindCertificateInStore find type (CSP_WinCrypt.h:4831)
// ===========================================================================

pub const CERT_FIND_ANY: DWORD = 0;
pub const CERT_FIND_CERT_ID: DWORD = 10;
pub const CERT_FINDCTL_USAGE: DWORD = 14;
pub const CERT_FIND_ENHKEY_USAGE: DWORD = 14; // Same as above
pub const CERT_FIND_EXISTING: DWORD = 12;
pub const CERT_FIND_HASH: DWORD = 12;         // Same
pub const CERT_FIND_ISSUER_ATTR: DWORD = 7;
pub const CERT_FIND_ISSUER_NAME: DWORD = 9;
pub const CERT_FIND_ISSUER_OF: DWORD = 6;
pub const CERT_FIND_KEY_IDENTIFIER: DWORD = 13;
pub const CERT_FIND_KEY_SPEC: DWORD = 10;
pub const CERT_FIND_MD5_HASH: DWORD = 4;
pub const CERT_FIND_PROPERTY: DWORD = 5;
pub const CERT_FIND_PUBLIC_KEY: DWORD = 8;
pub const CERT_FIND_SHA1_HASH: DWORD = 1;
pub const CERT_FIND_SUBJECT_ATTR: DWORD = 3;
pub const CERT_FIND_SUBJECT_NAME: DWORD = 9;
pub const CERT_FIND_SUBJECT_INFO_ACCESS: DWORD = 16;
pub const CERT_FIND_SUBJECT_STR: DWORD = 11;
pub const CERT_FIND_ISSUER_STR: DWORD = 11;

// ===========================================================================
// CertAddEncodedCertificateToStore disposition (CSP_WinCrypt.h:5907)
// ===========================================================================

pub const CERT_STORE_ADD_NEW: DWORD = 1;
pub const CERT_STORE_ADD_USE_EXISTING: DWORD = 2;
pub const CERT_STORE_ADD_REPLACE_EXISTING: DWORD = 3;
pub const CERT_STORE_ADD_ALWAYS: DWORD = 4;

// ===========================================================================
// CMSG_* message type constants (CSP_WinCrypt.h:10015-10030)
// ===========================================================================

pub const CMSG_SIGNED: DWORD = 2;
pub const CMSG_ENVELOPED: DWORD = 3;
pub const CMSG_SIGNED_AND_ENVELOPED: DWORD = 4;

pub const CMSG_DATA_FLAG: DWORD = 1 << 1;
pub const CMSG_SIGNED_FLAG: DWORD = 1 << 2;
pub const CMSG_ENVELOPED_FLAG: DWORD = 1 << 3;
pub const CMSG_SIGNED_AND_ENVELOPED_FLAG: DWORD = 1 << 4;

// ===========================================================================
// CMSG_* encoding flags (CSP_WinCrypt.h:10068+)
// ===========================================================================

/// CryptMsgOpenToEncode flags.
pub const CMSG_DETACHED_FLAG: DWORD = 0x00000008;
pub const CMSG_CRYPT_RELEASE_CONTEXT_FLAG: DWORD = 0x00008000;

// ===========================================================================
// CMSG_* control type (for CryptMsgControl)
// ===========================================================================

pub const CMSG_CTRL_VERIFY_SIGNATURE: DWORD = 1;
pub const CMSG_CTRL_DECRYPT: DWORD = 2;
pub const CMSG_CTRL_ADD_HASH: DWORD = 3;
pub const CMSG_CTRL_ADD_KEY: DWORD = 4;
pub const CMSG_CTRL_ADD_CERT: DWORD = 5;
pub const CMSG_CTRL_ADD_SIGNER: DWORD = 6;
pub const CMSG_CTRL_DEL_SIGNER: DWORD = 7;
pub const CMSG_CTRL_ADD_CRL: DWORD = 10;

// ===========================================================================
// CMSG_* get param type (for CryptMsgGetParam)
// ===========================================================================

pub const CMSG_TYPE_PARAM: DWORD = 1;
pub const CMSG_CONTENT_PARAM: DWORD = 2;
pub const CMSG_SIGNER_COUNT_PARAM: DWORD = 5;
pub const CMSG_SIGNER_INFO_PARAM: DWORD = 6;
pub const CMSG_CERT_COUNT_PARAM: DWORD = 11;
pub const CMSG_CERT_PARAM: DWORD = 12;
pub const CMSG_CRL_COUNT_PARAM: DWORD = 13;
pub const CMSG_CRL_PARAM: DWORD = 14;
pub const CMSG_SIGNER_CERT_INFO_PARAM: DWORD = 8;

// ===========================================================================
// szOID_* — well-known OID strings
// ===========================================================================

pub const szOID_COMMON_NAME: &str = "2.5.4.3";
pub const szOID_ORGANIZATION_NAME: &str = "2.5.4.10";
pub const szOID_ORGANIZATIONAL_UNIT_NAME: &str = "2.5.4.11";
pub const szOID_COUNTRY_NAME: &str = "2.5.4.6";
pub const szOID_LOCALITY_NAME: &str = "2.5.4.7";
pub const szOID_STATE_OR_PROVINCE_NAME: &str = "2.5.4.8";

/// OID хеша ГОСТ Р 34.11-2012 256 (Стрибог-256).
pub const szOID_GOST_R3411_2012_256: &str = "1.2.643.7.1.1.1.1";

/// OID хеша ГОСТ Р 34.11-2012 512 (Стрибог-512).
pub const szOID_GOST_R3411_2012_512: &str = "1.2.643.7.1.1.1.2";

/// OID подписи ГОСТ Р 34.10-2012 256.
pub const szOID_GOST_R3410_2012_256: &str = "1.2.643.7.1.1.1.1";

/// OID подписи ГОСТ Р 34.10-2012 512.
pub const szOID_GOST_R3410_2012_512: &str = "1.2.643.7.1.1.1.2";

/// OID шифрования ГОСТ 28147-89.
pub const szOID_GOST28147_89: &str = "1.2.643.2.2.21";

/// OID ключа ГОСТ Р 34.10-2001 (ЭЦП-2001).
pub const szOID_GOST_R3410_2001: &str = "1.2.643.2.2.19";

/// OID ключа ГОСТ Р 34.10-94.
pub const szOID_GOST_R3410_94: &str = "1.2.643.2.2.20";

// ===========================================================================
// PFX / PKCS12 flags (CSP_WinCrypt.h:12796-12872)
// ===========================================================================

/// Разрешить перезапись существующего ключа при импорте PFX.
pub const PKCS12_ALLOW_OVERWRITE_KEY: DWORD = 0x00004000;

/// Ключ не будет сохранён permanently (volatile).
pub const PKCS12_NO_PERSIST_KEY: DWORD = 0x00008000;

/// Включить расширенные свойства сертификата при экспорте PFX.
pub const PKCS12_INCLUDE_EXTENDED_PROPERTIES: DWORD = 0x0010;

/// Использовать обходной путь для обнаружения ошибок (CryptoPro).
pub const PKCS12_NO_OPTIMIZED: DWORD = 0x00001000;

/// Упаковать сертификаты (только сертификаты, без ключей).
pub const PKCS12_EXPORT_CERTIFICATES: DWORD = 0x00000001;

/// Упаковать ключи (только ключи, без сертификатов).
pub const PKCS12_EXPORT_PRIVATE_KEYS: DWORD = 0x00000004;

/// Экспортировать все ключи.
pub const PKCS12_EXPORT_KEY_SET: DWORD = 0x00000008;
