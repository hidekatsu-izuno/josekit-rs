use rand::{RngCore, thread_rng};

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut vec = vec![0; len];
    thread_rng().fill_bytes(&mut vec);
    vec
}
