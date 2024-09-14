use crate::Value;

use std::{any::Any, fmt::Debug};

pub trait JoseHeader: Any + Send + Sync + Debug {
    /// Return claim count.
    fn len(&self) -> usize;

    /// Return the value for header claim of a specified key.
    ///
    /// # Arguments
    ///
    /// * `key` - a key name of header claim
    fn claim(&self, key: &str) -> Option<&Value>;

    fn box_clone(&self) -> Box<dyn JoseHeader>;

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

impl Clone for Box<dyn JoseHeader> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
