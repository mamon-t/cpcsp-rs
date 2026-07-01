//! Safe обёртки над C-бинарными блобами (CRYPT_INTEGER_BLOB, CRYPT_DATA_BLOB и т.д.).
///
/// C-структура `CRYPTOAPI_BLOB` содержит указатель `pbData` и размер `cbData`.
/// Rust-обёртка хранит данные в `Vec<u8>`, а C-указатель указывает внутрь Vec.
///
/// При drop — память освобождается через `LocalFree`.
///
/// Источник: CSP_WinCrypt.h:1233-1252

use cpcsp_ffi_linux::raw_types as ffi;

/// Безопасная обёртка над C-бинарным блобом.
///
/// Данные хранятся в `Vec<u8>`, C-структура `DataBlob` указывает внутрь.
/// Автоматически освобождает память при drop.
///
/// # Safety
/// Гарантирует, что `pb_data` всегда указывает на валидную память
/// и `cb_data` соответствует реальному размеру данных.
#[derive(Clone, Debug)]
pub struct DataBlob {
    inner: Vec<u8>,
}

impl DataBlob {
    /// Создать блоб из байтов.
    pub fn new(data: &[u8]) -> Self {
        Self {
            inner: data.to_vec(),
        }
    }

    /// Создать пустой блоб.
    pub fn new_empty() -> Self {
        Self { inner: Vec::new() }
    }

    /// Создать блоб заданного размера, заполненный нулями.
    pub fn new_zeroed(size: usize) -> Self {
        Self {
            inner: vec![0u8; size],
        }
    }

    /// Данные блоба.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Mutable доступ к данным.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Размер данных.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Пуст ли блоб.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Конвертировать в C-структуру `DataBlob`.
    /// C-структура указывает внутрь self.inner — безопасно, пока DataBlob жив.
    pub fn as_ffi(&self) -> ffi::DataBlob {
        ffi::DataBlob {
            cb_data: self.inner.len() as u32,
            pb_data: self.inner.as_ptr() as *mut u8,
        }
    }

    /// Константный вариант — для функций, которые принимают `const BLOB*`.
    pub fn as_ffi_const(&self) -> ffi::DataBlob {
        ffi::DataBlob {
            cb_data: self.inner.len() as u32,
            pb_data: self.inner.as_ptr() as *mut u8,
        }
    }

    /// Присвоить данные из C-блоба (копирование).
    /// # Safety
    /// `src` должен указывать на валидную память размером `src.cb_data` байт.
    pub unsafe fn clone_from_ffi(&mut self, src: &ffi::DataBlob) {
        if src.cb_data == 0 || src.pb_data.is_null() {
            self.inner.clear();
        } else {
            let slice = std::slice::from_raw_parts(src.pb_data, src.cb_data as usize);
            self.inner = slice.to_vec();
        }
    }
}

impl Default for DataBlob {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl AsRef<[u8]> for DataBlob {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<&[u8]> for DataBlob {
    fn from(data: &[u8]) -> Self {
        Self::new(data)
    }
}

impl From<Vec<u8>> for DataBlob {
    fn from(data: Vec<u8>) -> Self {
        Self { inner: data }
    }
}

impl From<DataBlob> for Vec<u8> {
    fn from(blob: DataBlob) -> Self {
        blob.inner
    }
}

/// Обёртка для CRYPT_BIT_BLOB — блоб с количеством неиспользованных бит.
///
/// Источник: CSP_WinCrypt.h:1267-1271
#[derive(Clone, Debug)]
pub struct BitBlob {
    data: Vec<u8>,
    unused_bits: u32,
}

impl BitBlob {
    pub fn new(data: &[u8], unused_bits: u32) -> Self {
        Self {
            data: data.to_vec(),
            unused_bits,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn unused_bits(&self) -> u32 {
        self.unused_bits
    }

    /// Количество значимых бит.
    pub fn bit_len(&self) -> usize {
        self.data.len() * 8 - self.unused_bits as usize
    }

    pub fn as_ffi(&self) -> ffi::CRYPT_BIT_BLOB {
        ffi::CRYPT_BIT_BLOB {
            cb_data: self.data.len() as u32,
            pb_data: self.data.as_ptr() as *mut u8,
            c_unused_bits: self.unused_bits,
        }
    }
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_new() {
        let blob = DataBlob::new(&[1, 2, 3, 4]);
        assert_eq!(blob.len(), 4);
        assert_eq!(blob.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_blob_empty() {
        let blob = DataBlob::new_empty();
        assert!(blob.is_empty());
    }

    #[test]
    fn test_blob_ffi_roundtrip() {
        let blob = DataBlob::new(&[0xAA, 0xBB, 0xCC]);
        let ffi_blob = blob.as_ffi();
        assert_eq!(ffi_blob.cb_data, 3);
        assert!(!ffi_blob.pb_data.is_null());

        // Проверяем, что C-структура указывает на правильные данные
        let slice = unsafe {
            std::slice::from_raw_parts(ffi_blob.pb_data, ffi_blob.cb_data as usize)
        };
        assert_eq!(slice, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_blob_from_vec() {
        let blob = DataBlob::from(vec![10, 20, 30]);
        assert_eq!(blob.as_bytes(), &[10, 20, 30]);
    }

    #[test]
    fn test_blob_into_vec() {
        let blob = DataBlob::new(&[5, 6, 7]);
        let v: Vec<u8> = blob.into();
        assert_eq!(v, vec![5, 6, 7]);
    }

    #[test]
    fn test_bit_blob() {
        let bb = BitBlob::new(&[0xFF, 0x80], 1);
        assert_eq!(bb.bit_len(), 15);
        assert_eq!(bb.unused_bits(), 1);
    }
}
