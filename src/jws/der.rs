use std::io::{Read, Bytes};
use thiserror::Error;

#[derive(Debug)]
pub enum DataType {
    Boolean(bool),
    Integer(Vec<u8>),
    BitString(Vec<u8>),
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(Vec<u8>),
    Utf8String(Vec<u8>),
    PrintableString(Vec<u8>),
    TeletexString(Vec<u8>),
    Ia5String(Vec<u8>),
    BmpString(Vec<u8>),
    StartSequence,
    EndSequence,
    StartSet,
    EndSet
}

pub struct DerRecord {
    identifier: DataType,
    length: Option<usize>,
    contents: Option<Vec<u8>>
}

pub struct DerParser<R: Read> {
    input: Bytes<R>,
    states: Vec<DerRecord>
}

impl<R: Read> DerParser<R> {
    pub fn new(input: Bytes<R>) -> Self {
        Self {
            input,
            states: Vec::new()
        }
    }

    pub fn next(&mut self) -> Result<Option<DataType>, DerError> {
        let states_len = self.states.len();
        let mut is_indefinite_parent = false;
        if states_len > 0 {
            match self.states[states_len - 1].length {
                Some(val) if val == 0 => {
                    let record = self.states.pop().unwrap();
                    return Ok(Some(record.identifier)); 
                },
                Some(_) => {},
                None => {
                    is_indefinite_parent = true;
                }
            }
        }

        let tag = match self.input.next() {
            Some(Ok(val)) => val,
            Some(Err(err)) => return Err(DerError::ReadFailure(err)),
            None => return Ok(None)
        };

        let len = self.get_len()?;
        let value = match tag {
            0x00 => {
                if !is_indefinite_parent {
                    return Err(DerError::InvalidTag(format!("end of contents ({:X})", tag)));
                }
                
                match len {
                    Some(val) if val == 0 => {
                        let record = self.states.pop().unwrap();
                        return Ok(Some(record.identifier)); 
                    },
                    Some(val) => {
                        return Err(DerError::InvalidLength(format!("end of contents record's length must be 0: {}", val)));
                    },
                    None => {
                        return Err(DerError::InvalidLength(format!("end of contents record's length must be 0: indefinite")));
                    }
                }
            },
            0x30 => {
                self.states.push(DerRecord {
                    identifier: DataType::EndSequence,
                    length: len,
                    contents: None
                });
                return Ok(Some(DataType::StartSequence));
            },
            0x31 => {
                self.states.push(DerRecord {
                    identifier: DataType::EndSet,
                    length: len,
                    contents: None
                });
                return Ok(Some(DataType::StartSet));
            },
            _ => self.get_val(len)?
        };

        if let Some(val) = self.states[states_len - 1].length {
            self.states[states_len - 1].length = Some(val - value.len());
        }

        let data_type = match tag {
            0x01 => {
                if value.len() != 1 {
                    return Err(DerError::InvalidLength(format!("boolean record's length must be 1: {}", value.len())));
                }
                DataType::Boolean(value[0] != 0)
            },
            0x02 => {
                DataType::Integer(value)
            },
            0x03 => {
                DataType::BitString(value)
            },
            0x04 => {
                DataType::OctetString(value)
            },
            0x05 => {
                if value.len() != 1 {
                    return Err(DerError::InvalidLength(format!("null record's length must be 1: {}", value.len())));
                }
                if value[0] != 0 {
                    return Err(DerError::InvalidValue(format!("null record's value must be 0x00: {:X}", value[0])));
                }
                DataType::Null
            },
            0x06 => {
                DataType::ObjectIdentifier(value)
            },
            0x0C => {
                DataType::Utf8String(value)
            },
            0x13 => {
                DataType::PrintableString(value)
            },
            0x14 => {
                DataType::TeletexString(value)
            },
            0x16 => {
                DataType::Ia5String(value)
            },
            0x1E => {
                DataType::BmpString(value)
            },
            _ => return Err(DerError::UnknownTag(tag))
        };

        Ok(Some(data_type))
    }

    fn get(&mut self) -> Result<u8, DerError> {
        match self.input.next() {
            Some(Ok(val)) => Ok(val),
            Some(Err(err)) => Err(DerError::ReadFailure(err)),
            None => Err(DerError::UnexpectedEndOfInput)
        }
    }

    fn get_len(&mut self) -> Result<Option<usize>, DerError> {
        match self.get()? {
            val if val < 0x08 => Ok(Some(val as usize)),
            val if val > 0x08 => {
                let len_size = (val & 0x7F) as usize;
                if len_size > std::mem::size_of::<usize>() {
                    Err(DerError::TooMuchLength)?;
                }
                let mut num = 0usize;
                for _ in 0..len_size {
                    num = num << 8 | self.get()? as usize;
                }
                Ok(Some(num))
            }
            _ => Ok(None),
        }
    }

    fn get_val(&mut self, len: Option<usize>) -> Result<Vec<u8>, DerError> {
        if let Some(val) = len {
            let mut vec = Vec::with_capacity(val);
            for _ in 0..val {
                vec.push(self.get()?);
            }
            Ok(vec)
        } else {
            let mut vec = Vec::new();
            let mut maybe_eoc = false;
            while let b = self.get()? {
                if b == 0x00 {
                    if maybe_eoc {
                        break;
                    } else {
                        maybe_eoc = true
                    }
                } else {
                    if maybe_eoc {
                        maybe_eoc = false
                    }
                    vec.push(b);
                }
            }
            Ok(vec)
        }
    }
}

#[derive(Error, Debug)]
pub enum DerError {
    #[error("Unexpected end of input.")]
    UnexpectedEndOfInput,

    #[error("Unknown tag: {0:X}")]
    UnknownTag(u8),

    #[error("Invalid tag: {0}")]
    InvalidTag(String),

    #[error("Invalid length: {0}")]
    InvalidLength(String),

    #[error("Invalid value: {0}")]
    InvalidValue(String),
    
    #[error("Too much length.")]
    TooMuchLength,

    #[error("Failed to read: {0}")]
    ReadFailure(#[source] std::io::Error)
}
