//! Хелперы для работы с буферами при FFI-вызовах.
///
/// Типичный паттерн в CryptoPro API:
/// 1. Вызвать функцию с `pdwDataLen = NULL` чтобы получить размер
/// 2. Выделить буфер нужного размера
/// 3. Вызвать функцию снова с выделенным буфером
///
/// Этот модуль предоставляет абстракцию для этого паттерна.

use crate::types::error::{CpcspError, CpcspResult};

/// Вызвать FFI-функцию дважды: для получения размера и заполнения буфера.
///
/// # Аргументы
/// - `estimate`: начальная оценка размера (обычно 0 или 256)
/// - `get_size`: функция, которая вызывается с NULL для получения размера
/// - `fill`: функция, которая заполняет буфер
///
/// # Возвращает
/// `Vec<u8>` с данными или ошибку.
///
/// # Пример
/// ```ignore
/// let data = call_with_buffer(
///     0,
///     |size_ptr| unsafe {
///         CryptGetKeyParam(h_key, KP_ALGID, std::ptr::null_mut(), size_ptr, 0)
///     },
///     |buf_ptr, size_ptr| unsafe {
///         CryptGetKeyParam(h_key, KP_ALGID, buf_ptr, size_ptr, 0)
///     },
/// )?;
/// ```
pub fn call_with_buffer<F, G>(
    estimate: usize,
    get_size: F,
    fill: G,
) -> CpcspResult<Vec<u8>>
where
    F: FnOnce(*mut u32) -> u32,
    G: FnOnce(*mut u8, *mut u32) -> u32,
{
    let mut size = estimate as u32;
    let result = get_size(&mut size);
    if result == 0 {
        return Err(CpcspError::last_os_error());
    }

    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; size as usize];
    let mut size2 = size;
    let result = fill(buf.as_mut_ptr(), &mut size2);
    if result == 0 {
        return Err(CpcspError::last_os_error());
    }

    buf.truncate(size2 as usize);
    Ok(buf)
}

/// Вызвать FFI-функцию, которая возвращает размер в первом вызове
/// и данные — во втором. Возвращает Vec<u8>.
///
/// Паттерн аналогичен `call_with_buffer`, но get_size возвращает
/// код ошибки (0 = ошибка), а не BOOL.
pub fn get_buffer_no_bool<F, G>(
    estimate: usize,
    get_size: F,
    fill: G,
) -> CpcspResult<Vec<u8>>
where
    F: FnOnce(*mut u32) -> u32,
    G: FnOnce(*mut u8, *mut u32) -> u32,
{
    let mut size = estimate as u32;
    let _ = get_size(&mut size); //ignore errors on size query

    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; size as usize];
    let mut size2 = size;
    let result = fill(buf.as_mut_ptr(), &mut size2);
    if result == 0 {
        return Err(CpcspError::last_os_error());
    }

    buf.truncate(size2 as usize);
    Ok(buf)
}
