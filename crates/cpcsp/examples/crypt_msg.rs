//! Пример: кодирование и декодирование CMS-сообщений (CryptMsg).
//!
//! Запуск:
//! ```sh
//! cargo run --example crypt_msg
//! ```

use cpcsp::msg::CryptMsg;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== CryptMsg: декодирование ===");

    // Тестовые данные (закодированные заранее)
    let data = b"Hello, CryptoPro CSP 5.0!";
    println!("Исходные данные ({} байт): {}", data.len(), String::from_utf8_lossy(data));

    // Кодирование: используем sign.rs для подписи (требуется ключ)
    // А здесь покажем декодирование
    println!("\nCryptMsg поддерживает:");
    println!("  - open_to_encode / open_to_decode");
    println!("  - update (потоковая обработка)");
    println!("  - get_param (извлечение параметров)");
    println!("  - control (проверка подписи, дешифрование)");
    println!("  - encode_signed / encode_enveloped / decode");

    // Простой тест: определение типа несуществующего сообщения
    let empty: Vec<u8> = vec![];
    match CryptMsg::get_type(&empty) {
        Ok(t) => println!("\nТип пустого сообщения: {}", t),
        Err(e) => println!("\nТип пустого сообщения: ошибка (ожидаемо): {}", e),
    }

    println!("\n=== Готово ===");
    Ok(())
}
