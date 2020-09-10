use std::fmt::Debug;

pub trait JweAlgorithm: Debug + Send + Sync {
    /// Return the "alg" (algorithm) header parameter value of JWE.
    fn name(&self) -> &str;

    fn box_clone(&self) -> Box<dyn JweAlgorithm>;
}

impl PartialEq for Box<dyn JweAlgorithm> {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for Box<dyn JweAlgorithm> {}

impl Clone for Box<dyn JweAlgorithm> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}