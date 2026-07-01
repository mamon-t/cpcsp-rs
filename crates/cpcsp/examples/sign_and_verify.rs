//! Пример: подпись и проверка CMS-сообщения.
//!
//! Запуск:
//! ```sh
//! cargo run --example sign_and_verify
//! ```

use cpcsp::cert_store::CertStore;
use cpcsp::sign::{Signer, sign_message, verify_signature};
use cpcsp_ffi_linux::raw_constants::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Открыть хранилище MY и найти сертификат
    let store = CertStore::open_system("MY")?;
    let cert = store.iter().next()
        .ok_or("В хранилище MY нет сертификатов")?;

    println!("Используется сертификат:");
    println!("  Субъект: {:?}", cert.subject_name());
    println!("  Издатель: {:?}", cert.issuer_name());

    // Создать подписанта (GOST R 34.11-2012 256-bit хеш)
    let signer = Signer::new(&cert, AT_KEYEXCHANGE, szOID_GOST_R3411_2012_256);

    // Подписать сообщение
    let message = b"Hello, CryptoPro CSP! This is a signed message.";
    println!("\nПодписываемое сообщение ({} байт):", message.len());
    println!("  {:?}", String::from_utf8_lossy(message));

    let signed = sign_message(&[signer], message, false)?;
    println!("\nПодписанное сообщение: {} байт", signed.len());

    // Проверить подпись
    println!("\nПроверяем подпись...");
    let result = verify_signature(&signed)?;

    println!("Подпись действительна!");
    println!("  Распакованные данные: {} байт", result.content.len());
    println!("  Совпадают с оригиналом: {}", result.content == message);

    if let Some(signer_cert) = &result.signer_cert {
        println!("  Сертификат подписанта: {:?}", signer_cert.subject_name());
    }

    // Пример: отсоединённая подпись
    println!("\n=== Отсоединённая подпись ===");
    let signer2 = Signer::new(&cert, AT_KEYEXCHANGE, szOID_GOST_R3411_2012_256);
    let detached = sign_message(&[signer2], message, true)?;
    println!("Отсоединённая подпись: {} байт", detached.len());

    Ok(())
}
