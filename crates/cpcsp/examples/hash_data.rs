//! Пример: хеширование данных (ГОСТ Р 34.11-2012 Стрибог-256).
//!
//! Запуск:
//! ```sh
//! cargo run --example hash_data
//! ```

use cpcsp::provider::Provider;
use cpcsp::hash::Hash;
use cpcsp_ffi_linux::raw_constants::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Открыть провайдер
    let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;

    // Создать хеш Стрибог-256
    let hash = Hash::create(prov.raw_handle(), CALG_GOST_34_11_2012_256, 0)?;
    println!("Хеш создан: {:?}", hash);

    // Узнать размер хеша
    let hash_size = hash.hash_size()?;
    println!("Размер хеша: {} байт", hash_size);

    // Хешировать данные
    let data = b"Hello, CryptoPro CSP!";
    hash.update(data)?;
    println!("Данные захешированы: {} байт", data.len());

    // Получить значение хеша
    let digest = hash.hash_value()?;
    println!("Хеш (hexdigest): {}", hex::encode(&digest));

    // Проверить что повторное хеширование даёт тот же результат
    let hash2 = Hash::create(prov.raw_handle(), CALG_GOST_34_11_2012_256, 0)?;
    hash2.update(data)?;
    let digest2 = hash2.hash_value()?;
    assert_eq!(digest, digest2);
    println!("Хеш-значения совпадают!");

    // Пример: хеширование строки
    let message = "Тестовое сообщение для хеширования";
    let hash3 = Hash::create(prov.raw_handle(), CALG_GOST_34_11_2012_256, 0)?;
    hash3.update(message.as_bytes())?;
    let digest3 = hash3.hash_value()?;
    println!("\nСообщение: {:?}", message);
    println!("Хеш: {}", hex::encode(&digest3));

    Ok(())
}
