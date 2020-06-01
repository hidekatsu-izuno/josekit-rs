#![feature(box_syntax)]

use std::io::{Read, Bytes};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asn1Type {
    EndOfContents,
    Boolean,
    Integer,
    BitString,
    OctetString,
    Null,
    ObjectIdentifier,
    ObjectDescriptor,
    External,
    Real,
    Enumerated,
    EmbeddedPdv,
    Utf8String,
    RelativeOid,
    Time,
    Sequence,
    Set,
    NumericString,
    PrintableString,
    TeletexString,
    VideotexString,
    Ia5String,
    UtcTime,
    GeneralizedTime,
    GraphicString,
    VisibleString,
    GeneralString,
    UniversalString,
    CharacterString,
    BmpString,
    Date,
    TimeOfDay,
    DateTime,
    Duration,
    Other(DerClass, u64)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerClass {
    Universal,
    Application,
    ContextSpecific,
    Private
}

pub struct DerRecord {
    asn1_type: Asn1Type,
    constructed: bool,
    contents: Option<Vec<u8>>
}

pub struct DerParser<R: Read> {
    input: Bytes<R>,
    stack: Vec<Option<usize>>,
    record: Option<DerRecord>,
    read_count: usize
}

impl<R: Read> DerParser<R> {
    pub fn new(input: Bytes<R>) -> Self {
        Self {
            input,
            stack: Vec::new(),
            record: None,
            read_count: 0
        }
    }

    pub fn next(&mut self) -> Result<Option<Asn1Type>, DerError> {
        let depth = self.stack.len();
        let mut is_indefinite_parent = false;
        if depth > 0 {
            match self.stack[depth - 1] {
                None => {
                    is_indefinite_parent = true;
                },
                Some(0) => {
                    self.stack.pop();
                    return Ok(Some(Asn1Type::EndOfContents)); 
                },
                _ => {},
            }
        }

        let start_read_count = self.read_count;

        let record = match self.get_tag()? {
            None => return Ok(None),
            Some((Asn1Type::EndOfContents, constructed)) => {
                if !is_indefinite_parent {
                    return Err(DerError::InvalidTag(format!("End of contents is not allowed here.")));
                }

                if constructed {
                    return Err(DerError::InvalidTag(format!("End of contents must not be constructed.")));
                }
                
                match self.get_length()? {
                    Some(0) => {},
                    Some(val) => {
                        return Err(DerError::InvalidLength(format!("End of contents record's length must be 0: {}", val)));
                    },
                    None => {
                        return Err(DerError::InvalidLength(format!("End of contents record's length must be 0: indefinite")));
                    }
                }
                
                self.stack.pop();

                DerRecord {
                    asn1_type: Asn1Type::EndOfContents,
                    constructed,
                    contents: None
                }
            },
            Some((asn1_type, true)) => {
                let olength = self.get_length()?;

                self.stack.push(olength);
    
                DerRecord {
                    asn1_type: asn1_type,
                    constructed: true,
                    contents: None
                }
            },
            Some((asn1_type, false)) => {
                let length = match self.get_length()? {
                    Some(val) => val,
                    None => {
                        return Err(DerError::InvalidLength(format!("primitive record's length must be indefinite.")));
                    }
                };
    
                let mut contents = Vec::with_capacity(length);
                for _ in 0..length {
                    match self.get()? {
                        Some(val) => contents.push(val),
                        None => return Err(DerError::UnexpectedEndOfInput)
                    }
                }
    
                if depth > 0 {
                    if let Some(val) = self.stack[depth - 1] {
                        self.stack[depth - 1] = Some(val - (self.read_count - start_read_count));
                    }
                }
    
                DerRecord {
                    asn1_type,
                    constructed: false,
                    contents: Some(contents)
                }
            }
        };

        let ans1_type = record.asn1_type;
        self.record = Some(record);
        Ok(Some(ans1_type))
    }

    pub fn is_constructed(&self) -> bool {
        self.record.as_ref().unwrap().constructed
    }

    pub fn is_primitive(&self) -> bool {
        !self.record.as_ref().unwrap().constructed
    }

    pub fn get_contents(&self) -> Option<&Vec<u8>> {
        self.record.as_ref().unwrap().contents.as_ref()
    }

    pub fn get_contents_as_bool(&self) -> Result<bool, DerError> {
        let record = self.record.as_ref().unwrap();
        if let Asn1Type::Boolean = record.asn1_type {
            if self.is_constructed() {
                return Err(DerError::InvalidTag(format!("boolean type cannot be constructed")));
            }

            if let Some(contents) = &record.contents {
                if contents.len() != 1 {
                    return Err(DerError::InvalidLength(format!("Length of boolean contents must be 1: {}", contents.len())));
                }

                let value = contents[0] != 0;
                Ok(value)
            } else {
                unreachable!();
            }
        } else {
            panic!("Cannot convert to bool: {:?}", record.asn1_type);
        }
    }

    pub fn get_contents_as_u64(&self) -> Result<u64, DerError> {
        let record = self.record.as_ref().unwrap();
        if let Asn1Type::Integer | Asn1Type::Enumerated = record.asn1_type {
            if self.is_constructed() {
                return Err(DerError::InvalidTag(format!("integer/enumerated type cannot be constructed")));
            }

            if let Some(contents) = &record.contents {
                if contents.len() > 0 {
                    return Err(DerError::InvalidLength(format!("Length of integer/enumerated contents must be 1 or more.")));
                }

                let mut value = 0u64;
                let mut shift_count = 0u8;
                for i in 1..contents.len() {
                    let b = contents[i];
                    shift_count += 8;
                    if shift_count > 64 {
                        return Err(DerError::Overflow);
                    }
                    value = (value << 8) | b as u64;
                }
                Ok(value)
            } else {
                unreachable!();
            }
        } else {
            panic!("Cannot convert to i64: {:?}", record.asn1_type);
        }
    }

    pub fn get_contents_as_string(&self) -> Result<String, std::string::FromUtf8Error> {
        let record = self.record.as_ref().unwrap();
        if let Asn1Type::Utf8String = record.asn1_type {
            if let Some(contents) = &record.contents {
                let value = String::from_utf8(contents.to_vec())?;
                Ok(value)
            } else {
                unreachable!();
            }
        } else {
            panic!("Cannot convert to String: {:?}", record.asn1_type);
        }
    }

    pub fn get_content_as_object_identifier(&self) -> Result<Vec<u64>, DerError> {
        let record = self.record.as_ref().unwrap();
        if let Asn1Type::ObjectIdentifier = record.asn1_type {
            if let Some(contents) = &record.contents {
                let mut oid = Vec::<u64>::new();
                if contents.len() > 0 {
                    let b0 = contents[0];
                    oid.push((b0 / 40) as u64);
                    oid.push((b0 % 40) as u64);
        
                    let mut buf = 0u64;
                    let mut shift_count = 0u8;
                    for i in 1..contents.len() {
                        let b = contents[i];
                        shift_count += 7;
                        if shift_count > 64 {
                            return Err(DerError::Overflow);
                        }
                        buf = (buf << 7) | (b & 0x7F) as u64;
                        if b & 0x80 == 0 {
                            oid.push(buf);
                            buf = 0u64;
                            shift_count = 0;
                        }
                    }
                }
                return Ok(oid);
            }
        }
        panic!("Cannot convert to object identifier: {:?}", record.asn1_type);
    }

    fn get_tag(&mut self) -> Result<Option<(Asn1Type, bool)>, DerError> {
        let result = match self.get()? {
            Some(val) => {
                let der_class = Self::get_der_class(val >> 6);
                let constructed = ((val >> 5) & 0x01) != 0;
                let tag_no = if (val & 0x1F) > 30 {
                    let mut buf = 0u64;
                    let mut shift_count = 0u8;
                    loop {
                        match self.get()? {
                            Some(val) => {
                                shift_count += 7;
                                if shift_count > 64 {
                                    return Err(DerError::Overflow);
                                }
                                buf = (buf << 7) | (val & 0x7F) as u64;
                                if val & 0x80 == 0 {
                                    break;
                                }
                            }
                            None => return Err(DerError::UnexpectedEndOfInput)
                        }
                    }
                    buf
                } else {
                    (val & 0x1F) as u64
                };

                Some((Self::get_asn1_type(der_class, tag_no), constructed))
            },
            None => None
        };
        Ok(result)
    }

    fn get_der_class(class_no: u8) -> DerClass {
        match class_no {
            0b00 => DerClass::Universal,
            0b01 => DerClass::Application,
            0b10 => DerClass::ContextSpecific,
            0b11 => DerClass::Private,
            _ => unreachable!()
        }
    }

    fn get_asn1_type(class: DerClass, tag_no: u64) -> Asn1Type {
        match (class, tag_no) {
            (DerClass::Universal, 0) => Asn1Type::EndOfContents,
            (DerClass::Universal, 1) => Asn1Type::Boolean,
            (DerClass::Universal, 2) => Asn1Type::Integer,
            (DerClass::Universal, 3) => Asn1Type::BitString,
            (DerClass::Universal, 4) => Asn1Type::OctetString,
            (DerClass::Universal, 5) => Asn1Type::Null,
            (DerClass::Universal, 6) => Asn1Type::ObjectIdentifier,
            (DerClass::Universal, 7) => Asn1Type::ObjectDescriptor,
            (DerClass::Universal, 8) => Asn1Type::External,
            (DerClass::Universal, 9) => Asn1Type::Real,
            (DerClass::Universal, 10) => Asn1Type::Enumerated,
            (DerClass::Universal, 11) => Asn1Type::EmbeddedPdv,
            (DerClass::Universal, 12) => Asn1Type::Utf8String,
            (DerClass::Universal, 13) => Asn1Type::RelativeOid,
            (DerClass::Universal, 14) => Asn1Type::Time,
            (DerClass::Universal, 16) => Asn1Type::Sequence,
            (DerClass::Universal, 17) => Asn1Type::Set,
            (DerClass::Universal, 18) => Asn1Type::NumericString,
            (DerClass::Universal, 19) => Asn1Type::PrintableString,
            (DerClass::Universal, 20) => Asn1Type::TeletexString,
            (DerClass::Universal, 21) => Asn1Type::VideotexString,
            (DerClass::Universal, 22) => Asn1Type::Ia5String,
            (DerClass::Universal, 23) => Asn1Type::UtcTime,
            (DerClass::Universal, 24) => Asn1Type::GeneralizedTime,
            (DerClass::Universal, 25) => Asn1Type::GraphicString,
            (DerClass::Universal, 26) => Asn1Type::VisibleString,
            (DerClass::Universal, 27) => Asn1Type::GeneralString,
            (DerClass::Universal, 28) => Asn1Type::UniversalString,
            (DerClass::Universal, 29) => Asn1Type::CharacterString,
            (DerClass::Universal, 30) => Asn1Type::BmpString,
            (DerClass::Universal, 31) => Asn1Type::Date,
            (DerClass::Universal, 32) => Asn1Type::TimeOfDay,
            (DerClass::Universal, 33) => Asn1Type::DateTime,
            (DerClass::Universal, 34) => Asn1Type::Duration,
            _ => Asn1Type::Other(class, tag_no)
        }
    }

    fn get_length(&mut self) -> Result<Option<usize>, DerError> {
        let result = match self.get()? {
            Some(val) if val == 0xFF => {
                return Err(DerError::InvalidLength(format!("Length 0x{:X} is reserved for possible future extension.", val)));
            },
            Some(val) if val < 0x08 => {
                Some(val as usize)
            },
            Some(val) if val > 0x08 => {
                let len_size = (val & 0x7F) as usize;
                if len_size > std::mem::size_of::<usize>() {
                    return Err(DerError::Overflow);
                }
                let mut num = 0usize;
                for _ in 0..len_size {
                    match self.get()? {
                        Some(val) => {
                            num = num << 8 | val as usize;
                        },
                        None => return Err(DerError::UnexpectedEndOfInput)
                    }
                }
                Some(num)
            },
            Some(_) => None,
            None => return Err(DerError::UnexpectedEndOfInput)
        };
        Ok(result)
    }
    
    fn get(&mut self) -> Result<Option<u8>, DerError> {
        let result = match self.input.next() {
            Some(Ok(val)) => {
                self.read_count += 1; 
                Some(val)
            },
            Some(Err(err)) => return Err(DerError::ReadFailure(err)),
            None => None
        };
        Ok(result)
    }
}

#[derive(Error, Debug)]
pub enum DerError {
    #[error("Unexpected end of input.")]
    UnexpectedEndOfInput,

    #[error("Invalid tag: {0}")]
    InvalidTag(String),

    #[error("Invalid length: {0}")]
    InvalidLength(String),

    #[error("Invalid value: {0}")]
    InvalidValue(String),
    
    #[error("Overflow length.")]
    Overflow,

    #[error("Failed to read: {0}")]
    ReadFailure(#[source] std::io::Error)
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn parse_der() -> Result<()> {
        let bytes = load_file("der/rsa_2048_pkcs1_public.der")?.bytes();

        let mut parser = DerParser::new(bytes);
        assert!(matches!(parser.next()?, Some(Asn1Type::Sequence)));
        assert!(matches!(parser.next()?, Some(Asn1Type::Integer)));
        assert!(matches!(parser.next()?, Some(Asn1Type::Integer)));
        assert!(matches!(parser.next()?, Some(Asn1Type::EndOfContents)));
        Ok(())
    }
    
    fn load_file(path: &str) -> Result<File> {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("data");
        pb.push(path);

        let file = File::open(&pb)?;
        Ok(file)
    }
}