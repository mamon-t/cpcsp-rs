//! Пример: ASN.1 операции — Base64, хеширование сертификатов.
//!
//! Запуск:
//! ```sh
//! cargo run --example asn1_base64
//! ```

use cpcsp::asn1::Asn1;
use cpcsp::cert_store::CertStore;
use cpcsp_ffi_linux::raw_constants::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // === Base64 кодирование ===
    println!("=== Base64 кодирование ===");
    let data = b"Hello, CryptoPro CSP!";
    let b64 = Asn1::binary_to_base64(data)?;
    println!("Исходные данные: {}", String::from_utf8_lossy(data));
    println!("Base64: {}", b64);

    // Декодировать обратно
    let decoded = Asn1::base64_to_binary(&b64)?;
    assert_eq!(data.as_slice(), decoded.as_slice());
    println!("Декодировано: {} байт (OK)", decoded.len());

    // === Hex кодирование ===
    println!("\n=== Hex кодирование ===");
    let hex_str = Asn1::binary_to_hex(data)?;
    println!("Hex: {}", hex_str);

    let hex_decoded = Asn1::hex_to_binary(&hex_str)?;
    assert_eq!(data.as_slice(), hex_decoded.as_slice());
    println!("Декодировано: {} байт (OK)", hex_decoded.len());

    // === Хеширование сертификата ===
    println!("\n=== Хеширование сертификата ===");
    let store = CertStore::open_system("MY")?;

    if let Some(cert) = store.iter().next() {
        if let Some(subject) = cert.subject_name() {
            println!("Сертификат: {}", subject);
        }

        // Хеш Стрибог-256
        let hash_256 = Asn1::hash_certificate(&cert, CALG_GOST_34_11_2012_256)?;
        println!("Стрибог-256 ({} байт): {}", hash_256.len(), hex::encode(&hash_256));

        // Хеш Стрибог-512
        let hash_512 = Asn1::hash_certificate(&cert, CALG_GOST_34_11_2012_512)?;
        println!("Стрибог-512 ({} байт): {}", hash_512.len(), hex::encode(&hash_512));
    } else {
        println!("Нет сертификатов в хранилище MY");
    }

    Ok(())
}
