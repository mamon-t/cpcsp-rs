//! Пример: создание провайдера и генерация ключа.
//!
//! Запуск:
//! ```sh
//! cargo run --example provider_and_key
//! ```

use cpcsp::provider::Provider;
use cpcsp::key::Key;
use cpcsp_ffi_linux::raw_constants::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Открыть системный провайдер КриптоПро (GOST 2012 256-bit)
    let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
    println!("Провайдер открыт: {:?}", prov);

    // Сгенерировать ключ для подписи (GOST 2012 256-bit)
    let key = Key::gen(prov.raw_handle(), CALG_GOST_2012_256, CRYPT_EXPORTABLE)?;
    println!("Ключ создан: {:?}", key);

    // Узнать размер ключа
    let key_len = key.key_len()?;
    println!("Размер ключа: {} бит", key_len);

    // Экспортировать открытый ключ в PUBLICKEYBLOB
    let pub_blob = key.export_blob(PUBLICKEYBLOB, 0)?;
    println!("Открытый ключ: {} байт", pub_blob.len());
    println!("  bType: 0x{:02x}", pub_blob[0]);
    println!("  bVersion: 0x{:02x}", pub_blob[1]);

    // Импортировать ключ обратно
    let key2 = Key::from_blob(prov.raw_handle(), &pub_blob, 0)?;
    println!("Ключ импортирован: {:?}", key2);

    // Проверить что открытый ключ совпадает
    let pub_blob2 = key2.export_blob(PUBLICKEYBLOB, 0)?;
    assert_eq!(pub_blob, pub_blob2);
    println!("Открытые ключи совпадают!");

    Ok(())
}
