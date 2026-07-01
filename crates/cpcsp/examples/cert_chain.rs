//! Пример: построение цепочки сертификатов.
//!
//! Запуск:
//! ```sh
//! cargo run --example cert_chain
//! ```

use cpcsp::cert_store::CertStore;
use cpcsp::chain::CertChain;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = CertStore::open_system("ROOT")?;
    println!("Хранилище ROOT: {} сертификатов", store.count());

    let cert = store.iter().next().ok_or("Нет сертификатов в ROOT")?;
    if let Some(subject) = cert.subject_name() {
        println!("Субъект: {}", subject);
    }
    if let Some(issuer) = cert.issuer_name() {
        println!("Издатель: {}", issuer);
    }

    println!("\nПостроение цепочки...");
    let chain = CertChain::build_default(&cert)?;
    println!("Элементов в цепочке: {}", chain.element_count());
    println!("Trust status:  0x{:08X}", chain.trust_status());
    println!("Trust error:   0x{:08X}", chain.trust_status_error());
    println!("Debug: {:?}", chain);

    let chain2 = chain.duplicate();
    println!("\nДублировано: {} элементов", chain2.element_count());

    Ok(())
}
