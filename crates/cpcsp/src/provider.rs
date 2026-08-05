//! Safe обёртка над криптографическим провайдером (HCRYPTPROV).
//!
//! `Provider` инкапсулирует `CryptAcquireContext` / `CryptReleaseContext`,
//! обеспечивая автоматическое освобождение дескриптора через Drop.
//!
//! # Примеры
//!
//! ```no_run
//! use cpcsp::provider::Provider;
//! use cpcsp_ffi_linux::raw_constants::*;
//!
//! // Открыть системный провайдер (контейнер не нужен)
//! let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
//!
//! // Открыть провайдер с конкретным контейнером
//! let prov = Provider::acquire(Some("MyContainer"), None, PROV_GOST_2012_256, 0)?;
//! # Ok::<(), cpcsp::types::error::CpcspError>(())
//! ```
//!
//! Источник: CSP_WinCrypt.h:246 (HCRYPTPROV), CSP_WinCrypt.h:3700-3770 (AcquireContext)

use crate::types::error::{check_bool, CpcspError};
use crate::types::handle::ProvHandle;
use cpcsp_ffi_linux::raw_constants::*;
use cpcsp_ffi_linux::raw_types::{BYTE, DWORD};

/// Криптографический провайдер.
///
/// Владеет дескриптором `HCRYPTPROV` и автоматически освобождает его при drop.
/// Соответствует вызову `CryptAcquireContext` / `CryptReleaseContext`.
///
/// # Потокобезопасность
///
/// `Provider` не является `Send`/`Sync` — дескриптор привязан к потоку.
///
/// # Типы провайдеров
///
/// | Константа | Описание |
/// |-----------|----------|
/// | `PROV_GOST_2012_256` | ГОСТ Р 34.10-2012 256-bit |
/// | `PROV_GOST_2012_512` | ГОСТ Р 34.10-2012 512-bit |
/// | `PROV_RSA_AES` | RSA + AES (стандартный Windows CSP) |
///
/// # Примеры
///
/// ```no_run
/// use cpcsp::provider::Provider;
/// use cpcsp_ffi_linux::raw_constants::*;
///
/// // Системный провайдер (без контейнера)
/// let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
///
/// // С конкретным контейнером
/// let prov = Provider::acquire(Some("MyKey"), None, PROV_GOST_2012_256, 0)?;
/// # Ok::<(), cpcsp::types::error::CpcspError>(())
/// ```
///
/// Источник: CSP_WinCrypt.h:3700-3770
pub struct Provider {
    handle: ProvHandle,
    provider_type: DWORD,
}

impl Provider {
    // -----------------------------------------------------------------------
    // Конструкторы
    // -----------------------------------------------------------------------

    /// Открыть провайдер с указанным контейнером и именем провайдера.
    ///
    /// Соответствует `CryptAcquireContext(psz_container, psz_provider, ...)`.
    ///
    /// # Аргументы
    /// * `container` — имя контейнера ключей. `None` = контейнер по умолчанию.
    /// * `provider` — имя провайдера. `None` = провайдер по умолчанию для типа.
    /// * `provider_type` — тип провайдера (`PROV_GOST_2012_256`, `PROV_RSA_AES`, ...).
    /// * `flags` — флаги (`CRYPT_VERIFYCONTEXT`, `CRYPT_NEWKEYSET`, ...).
    ///
    /// # Ошибки
    /// Возвращает `CpcspError` если `CryptAcquireContext` вернул FALSE.
    ///
    /// # Пример
    /// ```no_run
    /// use cpcsp::provider::Provider;
    /// use cpcsp_ffi_linux::raw_constants::*;
    ///
    /// let prov = Provider::acquire(
    ///     Some("MyContainer"),
    ///     None,
    ///     PROV_GOST_2012_256,
    ///     CRYPT_VERIFYCONTEXT,
    /// )?;
    /// # Ok::<(), cpcsp::types::error::CpcspError>(())
    /// ```
    pub fn acquire(
        container: Option<&str>,
        provider: Option<&str>,
        provider_type: DWORD,
        flags: DWORD,
    ) -> Result<Self, CpcspError> {
        let container_cstr = container
            .map(|s| std::ffi::CString::new(s).expect("container name contains null byte"));
        let provider_cstr = provider
            .map(|s| std::ffi::CString::new(s).expect("provider name contains null byte"));

        let mut ph_prov: usize = 0;

        check_bool(|| unsafe {
            cpcsp_ffi_linux::capi10::CryptAcquireContextA(
                &mut ph_prov as *mut usize,
                container_cstr
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(std::ptr::null()),
                provider_cstr
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(std::ptr::null()),
                provider_type,
                flags,
            )
        })?;

        let handle = unsafe { ProvHandle::from_raw(ph_prov) };

        Ok(Self {
            handle,
            provider_type,
        })
    }

    /// Открыть системный провайдер без контейнера.
    ///
    /// Удобный конструктор: использует `CRYPT_VERIFYCONTEXT` и провайдер по умолчанию.
    /// Подходит для операций, не требующих доступа к контейнеру ключей
    /// (хеширование, проверка подписей, работа с сертификатами).
    ///
    /// # Пример
    /// ```no_run
    /// use cpcsp::provider::Provider;
    /// use cpcsp_ffi_linux::raw_constants::*;
    ///
    /// let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
    /// # Ok::<(), cpcsp::types::error::CpcspError>(())
    /// ```
    pub fn acquire_system(provider_type: DWORD, flags: DWORD) -> Result<Self, CpcspError> {
        Self::acquire(None, None, provider_type, flags)
    }

    // -----------------------------------------------------------------------
    // Методы
    // -----------------------------------------------------------------------

    /// Возвращает сырой дескриптор HCRYPTPROV.
    ///
    /// Используется для передачи в FFI-функции.
    /// Дескриптор остаётся владением `Provider` — вызывающий НЕ должен
    /// вызывать `CryptReleaseContext` самостоятельно.
    pub fn raw_handle(&self) -> usize {
        self.handle.raw()
    }

    /// Возвращает тип провайдера.
    pub fn provider_type(&self) -> DWORD {
        self.provider_type
    }

    /// Проверяет, является ли дескриптор валидным (не null).
    pub fn is_valid(&self) -> bool {
        !self.handle.is_null()
    }

    /// Генерирует криптографически стойкие случайные байты (CSPRNG).
    ///
    /// Соответствует `CryptGenRandom`.
    ///
    /// # Аргументы
    /// * `len` — количество случайных байт.
    ///
    /// # Пример
    /// ```no_run
    /// use cpcsp::provider::Provider;
    /// use cpcsp_ffi_linux::raw_constants::*;
    ///
    /// let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)?;
    /// let rnd = prov.gen_random(32)?;
    /// # Ok::<(), cpcsp::types::error::CpcspError>(())
    /// ```
    pub fn gen_random(&self, len: usize) -> Result<Vec<u8>, CpcspError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; len];
        unsafe {
            check_bool(|| {
                cpcsp_ffi_linux::capi10::CryptGenRandom(
                    self.handle.raw() as cpcsp_ffi_linux::raw_types::HCRYPTPROV,
                    len as DWORD,
                    buf.as_mut_ptr() as *mut BYTE,
                )
            })?;
        }
        Ok(buf)
    }

    /// Получить параметр провайдера (CryptGetProvParam).
    ///
    /// Возвращает сырые байты параметра. Для строковых параметров
    /// (PP_CONTAINER, PP_NAME) используйте [`Provider::container_name`] /
    /// [`Provider::provider_name`].
    pub fn get_param(&self, param: DWORD) -> Result<Vec<u8>, CpcspError> {
        unsafe {
            let mut size: DWORD = 0;
            check_bool(|| {
                cpcsp_ffi_linux::capi10::CryptGetProvParam(
                    self.handle.raw() as cpcsp_ffi_linux::raw_types::HCRYPTPROV,
                    param,
                    std::ptr::null_mut(),
                    &mut size,
                    0,
                )
            })?;

            if size == 0 {
                return Ok(Vec::new());
            }

            let mut buf = vec![0u8; size as usize];
            check_bool(|| {
                cpcsp_ffi_linux::capi10::CryptGetProvParam(
                    self.handle.raw() as cpcsp_ffi_linux::raw_types::HCRYPTPROV,
                    param,
                    buf.as_mut_ptr() as *mut BYTE,
                    &mut size,
                    0,
                )
            })?;

            buf.truncate(size as usize);
            Ok(buf)
        }
    }

    /// Имя контейнера ключей (PP_CONTAINER).
    pub fn container_name(&self) -> Result<String, CpcspError> {
        self.get_param(PP_CONTAINER)
            .and_then(trim_cstr)
    }

    /// Имя провайдера (PP_NAME).
    pub fn provider_name(&self) -> Result<String, CpcspError> {
        self.get_param(PP_NAME)
            .and_then(trim_cstr)
    }

    // -----------------------------------------------------------------------
    // FFI helper — для использования в safe wrapper'ах других модулей
    // -----------------------------------------------------------------------

    /// Внутренний FFI-вызов CryptReleaseContext.
    /// Используется для явного освобождения (вне Drop).
    fn release(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                cpcsp_ffi_linux::capi10::CryptReleaseContext(self.handle.raw(), 0);
            }
            // Обнуляем handle чтобы Drop не вызвал повторный release
            self.handle = unsafe { ProvHandle::from_raw(0) };
        }
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.release();
    }
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Provider(type={}, handle=0x{:X})",
            self.provider_type,
            self.handle.raw()
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Отбросить trailing-нули строки C (ANSI/UTF-8 буфер).
fn trim_cstr(mut buf: Vec<u8>) -> Result<String, CpcspError> {
    while buf.last() == Some(&0) {
        buf.pop();
    }
    String::from_utf8(buf).map_err(|_| CpcspError::from_raw(0x57))
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cpcsp_ffi_linux::raw_constants::*;

    #[test]
    fn test_provider_acquire_system() {
        let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT);
        assert!(prov.is_ok(), "acquire_system failed: {:?}", prov.err());
        let prov = prov.unwrap();
        assert!(prov.is_valid());
        assert_eq!(prov.provider_type(), PROV_GOST_2012_256);
        drop(prov);
    }

    #[test]
    fn test_provider_acquire_with_container() {
        let prov = Provider::acquire(
            Some("TestContainer_Rust"),
            None,
            PROV_GOST_2012_256,
            CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET,
        );
        if let Ok(prov) = prov {
            assert!(prov.is_valid());
            // Очищаем за собой — удаляем контейнер
            drop(prov);
        }
    }

    #[test]
    fn test_provider_debug() {
        let prov = Provider::acquire_system(PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT).unwrap();
        let debug_str = format!("{:?}", prov);
        assert!(debug_str.contains("Provider"));
        assert!(debug_str.contains("0x"));
    }
}
