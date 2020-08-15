use std::io::{self, Read, Write};
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;

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

    fn compress(&self, message: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(message)?;
        let vec = encoder.finish()?;
        Ok(vec)
    }

    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut decoder = DeflateDecoder::new(data);
        let mut vec = Vec::new();
        decoder.read_to_end(&mut vec)?;
        Ok(vec)
    }

    fn box_clone(&self) -> Box<dyn JweCompression> {
        Box::new(self.clone())
    }
}
