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