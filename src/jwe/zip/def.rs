#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum DeflateJweCompression {
    /// Compression with the DEFLATE [RFC1951] algorithm
    Def,
}

impl JweCompression for DeflateJweCompression {
    fn name(&self) -> &str {
        match self {
            Self::DEF => "DEF",
        }
    }
}
