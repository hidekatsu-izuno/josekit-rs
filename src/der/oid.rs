#[derive(Debug, Eq, PartialEq)]
pub struct ObjectIdentifier {
    values: Vec<u64>,
}

impl ObjectIdentifier {
    pub fn from_slice(values: &[u64]) -> Self {
        ObjectIdentifier {
            values: values.to_vec(),
        }
    }
}

impl<'a> IntoIterator for &'a ObjectIdentifier {
    type Item = &'a u64;
    type IntoIter = std::slice::Iter<'a, u64>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

impl PartialEq<&str> for ObjectIdentifier {
    fn eq(&self, other: &&str) -> bool {
        let mut vec: Vec<u64> = Vec::new();
        for val in other.split(".") {
            match val.parse() {
                Ok(nval) => vec.push(nval),
                Err(_) => return false,
            }
        }
        vec == self.values
    }
}

impl std::fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.values
                .iter()
                .map(|val| val.to_string())
                .collect::<Vec<String>>()
                .join(".")
        )
    }
}
