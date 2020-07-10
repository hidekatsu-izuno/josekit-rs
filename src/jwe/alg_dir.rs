#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum DirJweAlgorithm {
    /// Direct use of a shared symmetric key as the CEK
    Dir,
}
