//! Пример: работа с хранилищем сертификатов (MY, ROOT, CA).
//!
//! Запуск:
//! ```sh
//! cargo run --example cert_store
//! ```

use cpcsp::cert_store::CertStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Открыть системное хранилище "MY" (личные сертификаты)
    let store = CertStore::open_system("MY")?;
    println!("Хранилище MY открыто");

    // Подсчитать количество сертификатов
    let count = store.count();
    println!("Количество сертификатов: {}", count);

    // Перечислить сертификаты
    for (i, cert) in store.iter().take(10).enumerate() {
        println!("\n--- Сертификат {} ---", i + 1);

        if let Some(subject) = cert.subject_name() {
            println!("  Субъект: {}", subject);
        }

        if let Some(issuer) = cert.issuer_name() {
            println!("  Издатель: {}", issuer);
        }

        if let Some(hash) = cert.sha1_hash() {
            println!("  SHA1: {}", hex::encode(&hash));
        }

        match cert.verify_time() {
            Ok(0) => println!("  Время: валиден"),
            Ok(_) => println!("  Время: НЕ валиден"),
            Err(e) => println!("  Время: ошибка проверки: {}", e),
        }
    }

    // Открыть хранилище корневых сертификатов
    println!("\n=== Хранилище ROOT ===");
    let root_store = CertStore::open_system("ROOT")?;
    println!("Количество корневых сертификатов: {}", root_store.count());

    for cert in root_store.iter().take(5) {
        if let Some(subject) = cert.subject_name() {
            println!("  {}", subject);
        }
    }

    Ok(())
}
