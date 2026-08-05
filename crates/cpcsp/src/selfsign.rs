//! Создание самоподписанных сертификатов (CertCreateSelfSignCertificate).
//!
//! # Пример
//!
//! ```no_run
//! use cpcsp::provider::Provider;
//! use cpcsp::selfsign::create_self_signed;
//! use cpcsp_ffi_linux::raw_constants::*;
//!
//! let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
//! let cert = create_self_signed(&prov, "CN=Example", AT_SIGNATURE, szOID_GOST_R3411_2012_256, 1)?;
//! println!("Создан сертификат: {:?}", cert.subject_name());
//! # Ok::<(), cpcsp::types::error::CpcspError>(())
//! ```
//!
//! Источник: CSP_WinCrypt.h:1032 (CertCreateSelfSignCertificate)

use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::capi20::*;
use cpcsp_ffi_linux::raw_types::{
    DWORD, SYSTEMTIME, CRYPT_KEY_PROV_INFO, CRYPT_ALGORITHM_IDENTIFIER,
    CRYPT_ATTR_BLOB, DataBlob, WORD,
};

use crate::certificate::Certificate;
use crate::ffi_helpers::string::to_wide;
use crate::provider::Provider;
use crate::types::error::{check_bool, CpcspError};

/// CERT_X500_NAME_STR (не определён в raw_constants).
const CERT_X500_NAME_STR: DWORD = 3;

/// Создать самоподписанный сертификат (X.509).
///
/// # Аргументы
/// * `prov` — провайдер, в котором генерируется/используется ключ
/// * `subject` — субъект в X.500-нотации (например, `"CN=Example, O=Org"`)
/// * `key_spec` — `AT_KEYEXCHANGE` (1) или `AT_SIGNATURE` (2)
/// * `hash_oid` — OID алгоритма подписи (например, `szOID_GOST_R3411_2012_256`)
/// * `validity_years` — срок действия сертификата, в годах
pub fn create_self_signed(
    prov: &Provider,
    subject: &str,
    key_spec: DWORD,
    hash_oid: &str,
    validity_years: u32,
) -> Result<Certificate, CpcspError> {
    // 1. Закодировать субъект в CERT_NAME_BLOB через CertStrToNameA.
    let name_der = encode_x500_name(subject)?;
    let name_blob = DataBlob {
        cb_data: name_der.len() as DWORD,
        pb_data: name_der.as_ptr() as *mut _,
    };

    // 2. Информация о провайдере ключа.
    let container_wide = to_wide(&prov.container_name().unwrap_or_default());
    let mut key_prov_info: CRYPT_KEY_PROV_INFO = unsafe { std::mem::zeroed() };
    key_prov_info.pwsz_container_name = container_wide.as_ptr() as *mut u16;
    key_prov_info.dw_prov_type = prov.provider_type();
    key_prov_info.dw_key_spec = key_spec;

    // 3. Алгоритм подписи.
    let hash_oid_cstr = std::ffi::CString::new(hash_oid)
        .map_err(|_| CpcspError::from_raw(0x57))?;
    let signature_algorithm = CRYPT_ALGORITHM_IDENTIFIER {
        psz_obj_id: hash_oid_cstr.as_ptr() as *mut _,
        parameters: CRYPT_ATTR_BLOB {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        },
    };

    // 4. Период действия.
    let now = utc_now_system_time();
    let end = add_years(now, validity_years);

    unsafe {
        let ctx = CertCreateSelfSignCertificate(
            prov.raw_handle() as cpcsp_ffi_linux::raw_types::HCRYPTPROV,
            &name_blob as *const DataBlob as cpcsp_ffi_linux::raw_types::PCERT_NAME_BLOB,
            0, // dw_flags
            &key_prov_info as *const CRYPT_KEY_PROV_INFO,
            &signature_algorithm as *const CRYPT_ALGORITHM_IDENTIFIER,
            &now as *const SYSTEMTIME as *mut SYSTEMTIME,
            &end as *const SYSTEMTIME as *mut SYSTEMTIME,
            std::ptr::null_mut(), // p_extensions
        );

        if ctx.is_null() {
            return Err(CpcspError::last_os_error());
        }

        Ok(Certificate::from_raw(ctx))
    }
}

/// Закодировать X.500-имя в DER (CERT_NAME_BLOB) через CertStrToNameA.
fn encode_x500_name(subject: &str) -> Result<Vec<u8>, CpcspError> {
    let subject_cstr = std::ffi::CString::new(subject)
        .map_err(|_| CpcspError::from_raw(0x57))?;

    unsafe {
        // Первый вызов — определить размер.
        let mut size: DWORD = 0;
        check_bool(|| CertStrToNameA(
            X509_ASN_ENCODING,
            subject_cstr.as_ptr(),
            CERT_X500_NAME_STR,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
        ))?;

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size as usize];
        check_bool(|| CertStrToNameA(
            X509_ASN_ENCODING,
            subject_cstr.as_ptr(),
            CERT_X500_NAME_STR,
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            &mut size,
            std::ptr::null_mut(),
        ))?;

        buf.truncate(size as usize);
        Ok(buf)
    }
}

/// Текущее UTC время в формате SYSTEMTIME.
fn utc_now_system_time() -> SYSTEMTIME {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total = dur.as_secs() as i64;
    let days = total.div_euclid(86_400);
    let secs_of_day = total.rem_euclid(86_400);

    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    SYSTEMTIME {
        w_year: year as WORD,
        w_month: month as WORD,
        w_day_of_week: 0,
        w_day: day as WORD,
        w_hour: hour as WORD,
        w_minute: minute as WORD,
        w_second: second as WORD,
        w_milliseconds: 0,
    }
}

/// Прибавить `years` лет к SYSTEMTIME (упрощённо — только год, месяц/день те же).
fn add_years(t: SYSTEMTIME, years: u32) -> SYSTEMTIME {
    let mut y = t;
    y.w_year = y.w_year.saturating_add(years as WORD);
    y
}

/// Конвертация дней с эпохи (1970-01-01) в (year, month, day) по UTC.
/// Алгоритм Ховарда Хиннанта (civil_from_days).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}