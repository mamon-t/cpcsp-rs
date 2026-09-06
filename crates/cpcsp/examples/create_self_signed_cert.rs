//! Пример: создание самоподписанного тестового сертификата с нуля средствами библиотеки.
//!
//! Этот пример программно повторяет логику команды:
//! `csptest -minica -dn "CN=TestCert" -provtype 80 -container "test_rust" -keytype signature -store uMy -until 2`
//!
//! Запуск:
//! `cargo run --example create_self_signed_cert`

use cpcsp::cert_store::CertStore;
use cpcsp::key::Key;
use cpcsp::provider::Provider;
use cpcsp::selfsign::create_self_signed;
use cpcsp_ffi_linux::raw_constants::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let container_name = "test_sign_cert";
    let subject = "CN=TestRustCert, O=MyCompany, C=RU";
    let validity_years = 2;

    println!("1. Создаём новый контейнер ключей: '{}'", container_name);
    // CRYPT_NEWKEYSET создаст контейнер, если его нет. 
    // Если контейнер уже существует, можно убрать этот флаг.
    let prov = Provider::acquire(
        Some(container_name),
        None, // Имя провайдера по умолчанию для данного типа
        PROV_GOST_2012_256,
        CRYPT_NEWKEYSET,
    )?;
    println!("   ✅ Контейнер открыт/создан успешно.");

    println!("2. Генерируем ключевую пару ГОСТ Р 34.10-2012 (256 бит)...skipped");
    // Генерируем ключ. Флаг CRYPT_EXPORTABLE позволяет при необходимости экспортировать его позже.
    let _key = Key::gen(prov.raw_handle(), CALG_GOST_2012_256, CRYPT_EXPORTABLE)?;
    println!("   ✅ Ключ успешно сгенерирован и привязан к контейнеру.");

    println!("3. Создаём самоподписанный сертификат...");
    let cert = create_self_signed(
        &prov,
        subject,
        AT_SIGNATURE, // 2 = ключ для подписи (а не для шифрования)
        "1.2.643.7.1.1.3.2", //szOID_GOST_R3410_2012_256,
        validity_years,
    )?;
    println!("   ✅ Сертификат создан. Субъект: {:?}", cert.subject_name());

    println!("4. Устанавливаем сертификат в личное хранилище (MY)...");
    let store = CertStore::open_system("MY")?;
    
    // Сериализуем сертификат в DER и добавляем в хранилище
    // let der_bytes = cert.to_der()?;
    // store.add_encoded(&der_bytes)?;
    store.add_context(&cert)?;

    println!("   ✅ Сертификат успешно добавлен в хранилище MY.");

    println!("\n🎉 Готово! Теперь этот сертификат можно использовать для подписи.");
    println!("Проверить его наличие в системе можно командой:");
    println!("  /opt/cprocsp/bin/amd64/certmgr -list -store uMy");

    Ok(())
}