# Step 02 — Safe wrapper: Provider

## Что сделано

### `cpcsp/src/provider.rs`
Safe обёртка над `HCRYPTPROV` (криптографический провайдер).

```rust
pub struct Provider {
    handle: ProvHandle,     // RAII —自动调 CryptReleaseContext при drop
    provider_type: DWORD,   // тип провайдера (PROV_GOST_2012_256, ...)
}
```

**API:**
- `Provider::acquire(container, provider, provider_type, flags)` — открыть провайдер
- `Provider::acquire_system(provider_type, flags)` — открыть без контейнера (CRYPT_VERIFYCONTEXT)
- `provider.raw_handle()` — получить сырой HCRYPTPROV для FFI
- `provider.provider_type()` — тип провайдера
- `provider.is_valid()` — проверка на null

**Drop:** автоматически вызывает `CryptReleaseContext`.

### `cpcsp-ffi-linux/build.rs`, `cpcsp/build.rs`
Добавлены build scripts для линковки:
- `libcapi10.so` — CryptoAPI
- `libcapi20.so` — CryptoAPI Extensions
- `librdrsup.so` — GetLastError/SetLastError

### Исправления
- `CERT_PUBLIC_KEY_INFO.PublicKey`: `DataBlob` → `CRYPT_BIT_BLOB` (16→24 bytes)
- `from_ansi()`: возврат `Option<String>` вместо `Option<&str>`
- `Handle<T>`: замена generic Drop на три отдельных типа (ProvHandle, KeyHandle, HashHandle)
- `CERT_EXTENSIONS`: добавлен padding `_pad0` (16 bytes с padding)
- `CpcspError::new` → `CpcspError::last_os_error()`

## Тесты
- 22 unit tests (provider: 3, types: 19)
- 77 layout tests
- 3 doc tests
- Все проходят

## Следующий шаг
Safe wrapper для ключей: `key.rs` — генерация, импорт, экспорт, подпись.
