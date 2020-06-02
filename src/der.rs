pub mod oid;
mod reader;
mod error;

pub use crate::der::reader::DerReader;
pub use crate::der::error::DerError;

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerType {
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

impl fmt::Display for DerType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerClass {
    Universal,
    Application,
    ContextSpecific,
    Private
}

impl fmt::Display for DerClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct DerRecord {
    der_type: DerType,
    constructed: bool,
    contents: Option<Vec<u8>>
}
