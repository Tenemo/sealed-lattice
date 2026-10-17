use crate::{
    Error, Result,
    field::{Element, MODULUS},
};

pub struct Reader<'a> {
    bytes: &'a [u8],
    pub position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    pub fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(length).ok_or(Error::Encoding)?;
        let value = self.bytes.get(self.position..end).ok_or(Error::Encoding)?;
        self.position = end;
        Ok(value)
    }
    pub fn word(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
    pub fn wide(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn digest(&mut self) -> Result<[u8; 64]> {
        Ok(self.take(64)?.try_into().unwrap())
    }
    pub fn field(&mut self) -> Result<Element> {
        let bytes = self.take(48)?;
        let value = std::array::from_fn(|index| {
            u128::from_le_bytes(bytes[16 * index..16 * (index + 1)].try_into().unwrap())
        });
        if value.iter().all(|&coordinate| coordinate < MODULUS) {
            Ok(value)
        } else {
            Err(Error::Encoding)
        }
    }
    pub fn fields(&mut self, length: usize) -> Result<Vec<Element>> {
        (0..length).map(|_| self.field()).collect()
    }
    pub fn finish(&self) -> Result<()> {
        crate::require(self.position == self.bytes.len(), Error::Encoding)
    }
}
