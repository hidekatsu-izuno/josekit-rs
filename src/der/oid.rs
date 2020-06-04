#[derive(Debug, Eq, PartialEq)]
pub struct ObjectIdentifier {
    vec: Vec<u64>
}

impl ObjectIdentifier {
    pub fn new() -> Self {
        ObjectIdentifier {
            vec: Vec::new()
        }
    }

    pub fn from_vec(vec: Vec<u64>) -> Self {
        ObjectIdentifier {
            vec
        } 
    }

    pub fn push(&mut self, value: u64) {
        self.vec.push(value);
    }
}

impl PartialEq<&str> for ObjectIdentifier {
    fn eq(&self, other: &&str) -> bool {
        let mut vec: Vec<u64> = Vec::new();
        for val in other.split(".") {
            match val.parse() {
                Ok(nval) => vec.push(nval),
                Err(_) => return false
            }
        }
        self.vec == vec
    }
}

impl std::fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.vec.iter()
            .map(|val| val.to_string())
            .collect::<Vec<String>>()
            .join("."))
    }
}

#[macro_export]
macro_rules! oid {
    ( $( $x:expr ),* ) => {
        {
            let mut oid = crate::der::oid::ObjectIdentifier::new();
            $(
                oid.push($x);
            )*
            oid
        }
    };
}