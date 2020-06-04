pub mod oid;
mod reader;
mod writer;
mod error;

pub use crate::der::reader::DerReader;
pub use crate::der::writer::DerWriter;
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

impl DerType {
    pub fn can_primitive(&self) -> bool {
        match self {
            DerType::EndOfContents => true,
            DerType::Boolean => true,
            DerType::Integer => true,
            DerType::BitString => true,
            DerType::OctetString => true,
            DerType::Null => true,
            DerType::ObjectIdentifier => true,
            DerType::ObjectDescriptor => true,
            DerType::Real => true,
            DerType::Enumerated => true,
            DerType::Utf8String => true,
            DerType::RelativeOid => true,
            DerType::Time => true,
            DerType::NumericString => true,
            DerType::PrintableString => true,
            DerType::TeletexString => true,
            DerType::VideotexString => true,
            DerType::Ia5String => true,
            DerType::GraphicString => true,
            DerType::VisibleString => true,
            DerType::GeneralString => true,
            DerType::UniversalString => true,
            DerType::CharacterString => true,
            DerType::BmpString => true,
            DerType::Date => true,
            DerType::TimeOfDay => true,
            DerType::DateTime => true,
            DerType::Duration => true,
            DerType::Other(_, _) => true,
            _ => false
        }
    }

    pub fn can_constructed(&self) -> bool {
        match self {
            DerType::BitString => true,
            DerType::OctetString => true,
            DerType::External => true,
            DerType::EmbeddedPdv => true,
            DerType::Utf8String => true,
            DerType::Sequence => true,
            DerType::Set => true,
            DerType::NumericString => true,
            DerType::PrintableString => true,
            DerType::TeletexString => true,
            DerType::VideotexString => true,
            DerType::Ia5String => true,
            DerType::GraphicString => true,
            DerType::VisibleString => true,
            DerType::GeneralString => true,
            DerType::UniversalString => true,
            DerType::CharacterString => true,
            DerType::BmpString => true,
            DerType::Other(_, _) => true,
            _ => false
        }
    }
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
