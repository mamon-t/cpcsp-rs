//! Пример: импорт PFX-контейнера и подпись/проверка найденным ключом.
//!
//! Запуск:
//! ```sh
//! PFX_PATH=/path/to/file.pfx PFX_PASSWORD=111 cargo run -p cpcsp --example pfx_import
//! ```

use std::path::PathBuf;

use cpcsp::pfx::Pfx;
use cpcsp::sign::{Signer, sign_message, verify_signature};
use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::DWORD;

/// Комбинации флагов импорта. КриптоПро на Linux поддерживает не все
/// флаги Windows (в частности NO_PERSIST_KEY, судя по заглушке
/// PFXVerifyPassword, может быть не реализован) — ищем рабочую.
const FLAG_COMBOS: &[(&str, DWORD)] = &[
    ("NO_PERSIST", PKCS12_NO_PERSIST_KEY),
    ("без флагов", 0),
    ("ALLOW_OVERWRITE", PKCS12_ALLOW_OVERWRITE_KEY),
    ("ALLOW_OVERWRITE|NO_PERSIST", PKCS12_ALLOW_OVERWRITE_KEY | PKCS12_NO_PERSIST_KEY),
    ("EXTENDED_PROPERTIES", PKCS12_INCLUDE_EXTENDED_PROPERTIES),
    ("NO_OPTIMIZED", PKCS12_NO_OPTIMIZED),
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pfx_path = PathBuf::from(
        std::env::var("PFX_PATH")
            .unwrap_or_else(|_| "../../mikhail_sign2.pfx".to_string()),
    );
    let password =
        std::env::var("PFX_PASSWORD").unwrap_or_else(|_| "111".to_string());

    let data = std::fs::read(&pfx_path)
        .map_err(|e| format!("Не удалось прочитать {:?}: {}", pfx_path, e))?;
    println!("PFX-файл: {:?} ({} байт)", pfx_path, data.len());

    assert!(Pfx::is_pfx_blob(&data), "Файл не является PFX-контейнером");
    println!("Формат PFX подтверждён");

    // Перебираем комбинации флагов — первая успешная выигрывает.
    let mut store = None;
    for (name, flags) in FLAG_COMBOS {
        match Pfx::import_with_flags(&data, &password, *flags) {
            Ok(s) => {
                println!("Импорт успешен, флаги: {name} (0x{:04X})", flags);
                store = Some(s);
                break;
            }
            Err(e) => println!("  флаги {name} (0x{:04X}) -> ошибка {e}", flags),
        }
    }
    let store = store.ok_or("Ни одна комбинация флагов не подошла для импорта")?;
    println!("Импортировано сертификатов: {}", store.count());

    // Ищем сертификат с закрытым ключом подписи.
    let cert = store
        .iter()
        .find(|c| {
            c.has_private_key()
                && c.acquire_private_key()
                    .map(|k| k.key_spec() == AT_SIGNATURE)
                    .unwrap_or(false)
        })
        .or_else(|| store.iter().find(|c| c.has_private_key()))
        .ok_or("В PFX нет сертификатов с закрытым ключом")?;

    println!("Сертификат: {:?}", cert.subject_name());

    // Подпись и проверка.
    let message = b"PFX import roundtrip test via cpcsp-rs";
    let signer = Signer::new(&cert, AT_SIGNATURE, szOID_GOST_R3411_2012_256);
    let signed = sign_message(&[signer], message, false)?;
    println!("\nПодписано: {} байт CMS", signed.len());

    let result = verify_signature(&signed)?;
    println!("Подпись проверена, данные совпали: {}", result.content == message);
    if let Some(sc) = &result.signer_cert {
        println!("Сертификат подписанта: {:?}", sc.subject_name());
    }

    println!("\nГотово: PFX импорт → подпись → проверка.");
    Ok(())
}