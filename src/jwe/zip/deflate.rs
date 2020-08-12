use crate::jwe::JweCompression;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum DeflateJweCompression {
    /// Compression with the DEFLATE [RFC1951] algorithm
    Def,
}

impl JweCompression for DeflateJweCompression {
    fn name(&self) -> &str {
        match self {
            Self::Def => "DEF",
        }
    }

    fn compress(&self, message: &[u8]) -> Result<Vec<u8>, crate::jose::JoseError> {
        todo!()
    }

    fn decompress(&self, message: &[u8]) -> Result<Vec<u8>, crate::jose::JoseError> {
        todo!()
    }
}
