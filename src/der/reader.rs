use std::io;
use bit_vec::BitVec;

use crate::der::{DerType, DerClass, DerRecord, DerError};
use crate::der::oid::{ ObjectIdentifier };

pub struct DerReader<R: io::Read> {
    input: io::Bytes<R>,
    stack: Vec<Option<usize>>,
    record: Option<DerRecord>,
    read_count: usize
}

impl<R: io::Read> DerReader<R> {
    pub fn new(input: io::Bytes<R>) -> Self {
        Self {
            input,
            stack: Vec::new(),
            record: None,
            read_count: 0
        }
    }

    pub fn next(&mut self) -> Result<Option<DerType>, DerError> {
        let depth = self.stack.len();
        let mut is_indefinite_parent = false;
        if depth > 0 {
            match self.stack[depth - 1] {
                None => {
                    is_indefinite_parent = true;
                },
                Some(0) => {
                    self.stack.pop();
                    return Ok(Some(DerType::EndOfContents)); 
                },
                _ => {},
            }
        }

        let start_read_count = self.read_count;

        let record = match self.get_tag()? {
            None => return Ok(None),
            Some((DerType::EndOfContents, constructed)) => {
                if !is_indefinite_parent {
                    return Err(DerError::InvalidTag(format!("End of contents type is not allowed here.")));
                }

                if constructed {
                    return Err(DerError::InvalidTag(format!("End of contents type must not be constructed.")));
                }
                
                match self.get_length()? {
                    Some(0) => {},
                    Some(val) => {
                        return Err(DerError::InvalidLength(format!("End of contents content length must be 0: {}", val)));
                    },
                    None => {
                        return Err(DerError::InvalidLength(format!("End of contents content length must be 0: indefinite")));
                    }
                }
                
                self.stack.pop();

                DerRecord {
                    der_type: DerType::EndOfContents,
                    constructed,
                    contents: None
                }
            },
            Some((der_type, true)) => {
                let olength = self.get_length()?;

                self.stack.push(olength);
    
                DerRecord {
                    der_type: der_type,
                    constructed: true,
                    contents: None
                }
            },
            Some((der_type, false)) => {
                let length = match self.get_length()? {
                    Some(val) => val,
                    None => {
                        return Err(DerError::InvalidLength(format!("Primitive type content length cannot be indefinite.")));
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
                    der_type,
                    constructed: false,
                    contents: Some(contents)
                }
            }
        };

        let ans1_type = record.der_type;
        self.record = Some(record);
        Ok(Some(ans1_type))
    }

    pub fn is_constructed(&self) -> bool {
        self.record.as_ref().unwrap().constructed
    }

    pub fn is_primitive(&self) -> bool {
        !self.record.as_ref().unwrap().constructed
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.record.as_ref().unwrap().contents.as_ref().unwrap().to_vec()
    }

    pub fn to_null(&self) -> Result<(), DerError> {
        let record = self.record.as_ref().unwrap();
        if let DerType::Null = record.der_type {
            if self.is_constructed() {
                return Err(DerError::InvalidTag(format!("Null type cannot be constructed.")));
            }

            if let Some(contents) = &record.contents {
                if contents.len() != 0 {
                    return Err(DerError::InvalidLength(format!("Null content length must be 0: {}", contents.len())));
                }

                Ok(())
            } else {
                unreachable!();
            }
        } else {
            panic!("{} type is not supported to convert to null.", record.der_type);
        }
    }

    pub fn to_boolean(&self) -> Result<bool, DerError> {
        let record = self.record.as_ref().unwrap();
        if let DerType::Boolean = record.der_type {
            if self.is_constructed() {
                return Err(DerError::InvalidTag(format!("Boolean type cannot be constructed")));
            }

            if let Some(contents) = &record.contents {
                if contents.len() != 1 {
                    return Err(DerError::InvalidLength(format!("Boolean content length must be 1: {}", contents.len())));
                }

                let value = contents[0] != 0;
                Ok(value)
            } else {
                unreachable!();
            }
        } else {
            panic!("{} type is not supported to convert to bool.", record.der_type);
        }
    }

    pub fn to_u64(&self) -> Result<u64, DerError> {
        let record = self.record.as_ref().unwrap();
        if let DerType::Integer | DerType::Enumerated = record.der_type {
            if self.is_constructed() {
                return Err(DerError::InvalidTag(format!("{} type cannot be constructed", record.der_type)));
            }

            if let Some(contents) = &record.contents {
                if contents.len() > 0 {
                    return Err(DerError::InvalidLength(format!("{} content length must be 1 or more.", record.der_type)));
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
            panic!("{} type is not supported to convert to u64.", record.der_type);
        }
    }

    pub fn to_bit_vec(&self) -> Result<BitVec, DerError> {
        let record = self.record.as_ref().unwrap();
        if let DerType::BitString = record.der_type {
            if let Some(contents) = &record.contents {
                if contents.len() >= 2 {
                    return Err(DerError::InvalidLength(format!("Bit String content length must be 2 or more.")));
                }

                let unused_bits = contents[0] as usize;
                if unused_bits > 7 {
                    return Err(DerError::InvalidContents(format!("Unused bit count of Bit String must be from 0 to 7.")));
                }

                let mut bit_vec = BitVec::from_bytes(&contents[1..]);
                bit_vec.truncate((contents.len() - 1) * 8 - unused_bits);
                Ok(bit_vec)
            } else {
                unreachable!();
            }
        } else {
            panic!("{} type is not supported to convert to BitVec", record.der_type);
        }
    }

    pub fn to_string(&self) -> Result<String, DerError> {
        let record = self.record.as_ref().unwrap();
        if let DerType::Utf8String = record.der_type {
            if let Some(contents) = &record.contents {
                let value = String::from_utf8(contents.to_vec()).map_err(|err| {
                    DerError::InvalidUtf8String(err)
                })?;
                Ok(value)
            } else {
                unreachable!();
            }
        } else {
            panic!("{} type is not supported to convert to String.", record.der_type);
        }
    }

    pub fn to_object_identifier(&self) -> Result<ObjectIdentifier, DerError> {
        let record = self.record.as_ref().unwrap();
        if let DerType::ObjectIdentifier = record.der_type {
            if self.is_constructed() {
                return Err(DerError::InvalidTag(format!("Object Identifier type cannot be constructed.")));
            }

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
                return Ok(ObjectIdentifier::from_vec(oid));
            } else {
                unreachable!();
            }
        }
        panic!("{} type is not supported to convert to ObjectIdentifier.", record.der_type);
    }

    fn get_tag(&mut self) -> Result<Option<(DerType, bool)>, DerError> {
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

                Some((Self::get_der_type(der_class, tag_no), constructed))
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

    fn get_der_type(class: DerClass, tag_no: u64) -> DerType {
        match (class, tag_no) {
            (DerClass::Universal, 0) => DerType::EndOfContents,
            (DerClass::Universal, 1) => DerType::Boolean,
            (DerClass::Universal, 2) => DerType::Integer,
            (DerClass::Universal, 3) => DerType::BitString,
            (DerClass::Universal, 4) => DerType::OctetString,
            (DerClass::Universal, 5) => DerType::Null,
            (DerClass::Universal, 6) => DerType::ObjectIdentifier,
            (DerClass::Universal, 7) => DerType::ObjectDescriptor,
            (DerClass::Universal, 8) => DerType::External,
            (DerClass::Universal, 9) => DerType::Real,
            (DerClass::Universal, 10) => DerType::Enumerated,
            (DerClass::Universal, 11) => DerType::EmbeddedPdv,
            (DerClass::Universal, 12) => DerType::Utf8String,
            (DerClass::Universal, 13) => DerType::RelativeOid,
            (DerClass::Universal, 14) => DerType::Time,
            (DerClass::Universal, 16) => DerType::Sequence,
            (DerClass::Universal, 17) => DerType::Set,
            (DerClass::Universal, 18) => DerType::NumericString,
            (DerClass::Universal, 19) => DerType::PrintableString,
            (DerClass::Universal, 20) => DerType::TeletexString,
            (DerClass::Universal, 21) => DerType::VideotexString,
            (DerClass::Universal, 22) => DerType::Ia5String,
            (DerClass::Universal, 23) => DerType::UtcTime,
            (DerClass::Universal, 24) => DerType::GeneralizedTime,
            (DerClass::Universal, 25) => DerType::GraphicString,
            (DerClass::Universal, 26) => DerType::VisibleString,
            (DerClass::Universal, 27) => DerType::GeneralString,
            (DerClass::Universal, 28) => DerType::UniversalString,
            (DerClass::Universal, 29) => DerType::CharacterString,
            (DerClass::Universal, 30) => DerType::BmpString,
            (DerClass::Universal, 31) => DerType::Date,
            (DerClass::Universal, 32) => DerType::TimeOfDay,
            (DerClass::Universal, 33) => DerType::DateTime,
            (DerClass::Universal, 34) => DerType::Duration,
            _ => DerType::Other(class, tag_no)
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

        let mut parser = DerReader::new(bytes);
        assert!(matches!(parser.next()?, Some(DerType::Sequence)));
        assert!(matches!(parser.next()?, Some(DerType::Integer)));
        assert!(matches!(parser.next()?, Some(DerType::Integer)));
        assert!(matches!(parser.next()?, Some(DerType::EndOfContents)));
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