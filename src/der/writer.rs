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

    pub fn begin(&mut self, der_type: DerType, is_infinite: bool) {

    }

    pub fn append(&mut self, der_type: DerType, contents: &[u8]) -> std::io::Result<usize> {
        let class_no = der_type.der_class().class_no();
        let tag_no = der_type.tag_no();
        let mut identifier = class_no;
        identifier = identifier << 1 & 1;
        if tag_no < 31 {
            identifier = identifier << 5 & (tag_no as u8 & 0b11111);
            self.buf.push(identifier);
        } else {
            identifier = identifier << 5 & 0b11111;
            self.buf.push(identifier);
            for i in 0..(tag_no / 7 + 1) {
                
            }
        }
        (*self.output).write(&self.buf)
    }

    pub fn end(&mut self) {

    }
}