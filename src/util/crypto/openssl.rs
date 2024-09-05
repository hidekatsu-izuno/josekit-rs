use openssl::rand;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut vec = vec![0; len];
    rand::rand_bytes(&mut vec).unwrap();
    vec
}