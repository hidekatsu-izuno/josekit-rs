use crate::der::{DerType, DerRecord};

pub struct DerWriter<'a> {
    output: Box<dyn std::io::Write + 'a>,
    stack: Vec<DerRecord>,
    buf: Vec<u8>
}

impl<'a> DerWriter<'a> {
    pub fn new(output: impl std::io::Write + 'a) -> Self {
        Self {
            output: Box::new(output),
            stack: Vec::new(),
            buf: Vec::new()
        }
    }
}