//! Пример: получение OID-информации (CryptoPro extensions).
//!
//! Запуск:
//! ```sh
//! cargo run --example pki_info
//! ```

use cpcsp::pki::Pki;
use cpcsp_ffi_linux::raw_constants::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== CryptoPro PKI: OID-информация ===");

    // OID ключа ГОСТ Р 34.10-2012 256
    let gost_key_oid = "1.2.643.7.1.1.1.1";

    // Информация о хеше по умолчанию
    println!("\n--- Хеш по умолчанию ---");
    match Pki::get_default_hash_oid_info(gost_key_oid) {
        Ok(info) => {
            println!("OID: {}", info.oid);
            println!("Имя: {}", info.name);
            println!("ALG_ID: 0x{:04X}", info.alg_id);
            println!("Group ID: {}", info.group_id);
        }
        Err(e) => println!("Ошибка: {}", e),
    }

    // ALG_ID хеша ГОСТ по умолчанию
    println!("\n--- ALG_ID хеша ГОСТ по умолчанию ---");
    match Pki::get_default_gost_hash_alg_id(gost_key_oid) {
        Ok(alg_id) => println!("ALG_ID: 0x{:04X}", alg_id),
        Err(e) => println!("Ошибка: {}", e),
    }

    // Информация о подписи по умолчанию
    println!("\n--- Подпись по умолчанию ---");
    match Pki::get_default_signature_oid_info(gost_key_oid) {
        Ok(info) => {
            println!("OID: {}", info.oid);
            println!("Имя: {}", info.name);
            println!("ALG_ID: 0x{:04X}", info.alg_id);
        }
        Err(e) => println!("Ошибка: {}", e),
    }

    // Информация о публичном ключе
    println!("\n--- Информация о публичном ключе ---");
    match Pki::get_public_key_oid_info(gost_key_oid, AT_KEYEXCHANGE) {
        Ok(info) => {
            println!("OID: {}", info.oid);
            println!("Имя: {}", info.name);
            println!("ALG_ID: 0x{:04X}", info.alg_id);
        }
        Err(e) => println!("Ошибка: {}", e),
    }

    // Текущий PIN-callback
    println!("\n--- PIN-callback ---");
    match Pki::get_pin_callback() {
        Some((_, _)) => println!("PIN-callback установлен"),
        None => println!("PIN-callback не установлен (стандартное поведение)"),
    }

    // Тестовые данные
    println!("\n=== Тестовые данные ===");
    let test_data = b"Test data for OID lookup";
    println!("Данные: {}", String::from_utf8_lossy(test_data));

    Ok(())
}
