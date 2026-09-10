//!
//! Демонстрация encode/decode пути CryptMsg против живого КриптоПро CSP:
//! подпись через `CryptMsg::encode_signed` и проверка через
//! `CryptVerifyMessageSignature` (sign.rs), затем расшифровка конверта.
//!
//! Требуется сертификат с приватным ключом в хранилище MY
//! (для подписи — AT_SIGNATURE, для конверта — AT_KEYEXCHANGE).
//!
//! Запуск:
//! ```sh
//! cargo run --example crypt_msg
//! ```

use cpcsp::cert_store::CertStore;
use cpcsp::msg::CryptMsg;
use cpcsp::sign::verify_signature;
use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::DWORD;

fn find_cert(key_spec: DWORD) -> Option<cpcsp::certificate::Certificate> {
    let store = CertStore::open_system("MY").ok()?;
    store
        .iter()
        .find(|c| {
            c.acquire_private_key()
                .map(|k| k.key_spec() == key_spec)
                .unwrap_or(false)
        })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = b"Hello, CryptoPro CSP 5.0!";

    // ------------------------------------------------------------------
    // 1. Подпись через CryptMsg::encode_signed (CryptMsgOpenToEncode)
    // ------------------------------------------------------------------
    println!("=== 1. CryptMsg::encode_signed ===");

    let signer_cert = match find_cert(AT_SIGNATURE) {
        Some(c) => c,
        None => {
            println!("Нет сертификата с AT_SIGNATURE в MY — пропуск подписи");
            return Ok(());
        }
    };
    println!("Подписант: {:?}", signer_cert.subject_name());

    let signed = CryptMsg::encode_signed(
        &signer_cert,
        szOID_GOST_R3411_2012_256,
        data,
    )?;
    println!("Подписанное сообщение: {} байт", signed.len());

    // ------------------------------------------------------------------
    // 2. Проверка подписи штатным verify (CryptVerifyMessageSignature)
    // ------------------------------------------------------------------
    println!("\n=== 2. verify_signature (контроль) ===");

    let verified = verify_signature(&signed)?;
    assert_eq!(verified.content, data, "контент после verify не совпал");
    println!("Подпись верна, контент: {}", String::from_utf8_lossy(&verified.content));

    // ------------------------------------------------------------------
    // 3. Контроль типа и декодирование через CryptMsg
    // ------------------------------------------------------------------
    println!("\n=== 3. CryptMsg::get_type / decode ===");

    let msg_type = CryptMsg::get_type(&signed)?;
    println!("Тип сообщения: {} (ожидался {} = CMSG_SIGNED)", msg_type, CMSG_SIGNED);
    assert_eq!(msg_type, CMSG_SIGNED);

    // ------------------------------------------------------------------
    // 4. Конверт: CryptMsg::encode_enveloped + расшифровка
    //    Получатель — сертификат с ключом обмена (AT_KEYEXCHANGE):
    //    расшифровка приватным ключом подписи запрещена (NTE_PERM).
    // ------------------------------------------------------------------
    println!("\n=== 4. CryptMsg::encode_enveloped ===");

    let recipient_cert = match find_cert(AT_KEYEXCHANGE) {
        Some(c) => c,
        None => {
            println!("Нет сертификата с AT_KEYEXCHANGE в MY — пропуск конверта");
            println!("\n=== Готово (без конверта) ===");
            return Ok(());
        }
    };
    println!("Получатель: {:?}", recipient_cert.subject_name());

    let enveloped = CryptMsg::encode_enveloped(
        &[&recipient_cert],
        szOID_CP_GOST_R3412_2015_K,
        data,
    )?;
    println!("Конверт: {} байт", enveloped.len());

    let env_type = CryptMsg::get_type(&enveloped)?;
    println!("Тип конверта: {} (ожидался {} = CMSG_ENVELOPED)", env_type, CMSG_ENVELOPED);
    assert_eq!(env_type, CMSG_ENVELOPED);

    // ------------------------------------------------------------------
    // 5. Расшифровка конверта: OpenToDecode + CMSG_CTRL_DECRYPT
    // ------------------------------------------------------------------
    println!("\n=== 5. Расшифровка конверта ===");

    let mut msg = unsafe {
        CryptMsg::open_to_decode(0, 0, std::ptr::null_mut())?
    };
    msg.update(&enveloped, true)?;

    // Приватный ключ получателя — через acquire_private_key.
    let key = recipient_cert.acquire_private_key()?;
    let decrypt_para = cpcsp_ffi_linux::raw_types::CMSG_CTRL_DECRYPT_PARA {
        cb_size: std::mem::size_of::<cpcsp_ffi_linux::raw_types::CMSG_CTRL_DECRYPT_PARA>()
            as DWORD,
        h_crypt_prov: key.raw_prov() as usize,
        dw_key_spec: key.key_spec(),
        dw_recipient_index: 0,
    };
    msg.control(
        CMSG_CTRL_DECRYPT,
        &decrypt_para as *const _ as *mut std::ffi::c_void,
    )?;

    let decrypted = msg.finish()?;
    assert_eq!(decrypted, data, "расшифрованный контент не совпал");
    println!("Расшифровано: {} байт — контент совпал ✓", decrypted.len());

    println!("\n=== Готово: полный roundtrip подписи и конверта ===");
    Ok(())
}