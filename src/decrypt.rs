use chacha20::{
    XChaCha20,
    cipher::{KeyInit, KeyIvInit, StreamCipher},
};
use crypto_common::generic_array::GenericArray;
use poly1305::Poly1305;
use poly1305::universal_hash::UniversalHash;
use subtle::ConstantTimeEq;

pub struct Decryptor {
    cipher: XChaCha20,
    poly1305: Poly1305,
}

impl Decryptor {
    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        let mut cipher = XChaCha20::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(nonce),
        );
        let mut block = [0u8; 64];
        cipher.apply_keystream(&mut block);
        let poly1305_key = GenericArray::from_slice(&block[..32]);
        let poly1305 = Poly1305::new(poly1305_key);

        Self { cipher, poly1305 }
    }

    pub fn add_associated_data(&mut self, data: &[u8]) {
        self.poly1305.update_padded(data);
    }

    pub fn verify_tag(&self, expected_tag: &[u8; 16]) -> bool {
        let calculated_tag = self.poly1305.clone().finalize();
        let tag_bytes: [u8; 16] = *calculated_tag.as_ref();
        tag_bytes.ct_eq(expected_tag).into()
    }

    pub fn feed(&mut self, data: &mut Vec<u8>) {
        self.poly1305.update_padded(data.as_slice());
        self.cipher.apply_keystream(data);
    }
}

#[macro_export]
macro_rules! decrypt {
    ($key:expr, $nonce:expr, |$decryptor:ident| $body:block) => {{
        let mut $decryptor = $crate::decrypt::Decryptor::new($key, $nonce);
        $body
    }};
}
