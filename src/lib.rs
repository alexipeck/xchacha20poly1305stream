use chacha20::{
    XChaCha20,
    cipher::{KeyInit, KeyIvInit, StreamCipher},
};
use crypto_common::generic_array::GenericArray;
use poly1305::Poly1305;
use poly1305::universal_hash::UniversalHash;
use subtle::ConstantTimeEq;

pub struct XChaCha20Poly1305Encryptor {
    cipher: XChaCha20,
    poly1305: Poly1305,
}

pub struct XChaCha20Poly1305Decryptor {
    cipher: XChaCha20,
    poly1305: Poly1305,
}

impl XChaCha20Poly1305Encryptor {
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

    pub fn encrypt_chunk(&mut self, data: &mut Vec<u8>) {
        self.cipher.apply_keystream(data);
        let data_slice = data.as_slice();
        self.poly1305.update_padded(data_slice);
    }

    pub fn finalize_tag(self) -> [u8; 16] {
        let tag = self.poly1305.finalize();
        *tag.as_ref()
    }
}

impl XChaCha20Poly1305Decryptor {
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

    pub fn authenticate_chunk(&mut self, data: &[u8]) {
        self.poly1305.update_padded(data);
    }

    pub fn verify_tag(&self, expected_tag: &[u8; 16]) -> bool {
        let calculated_tag = self.poly1305.clone().finalize();
        let tag_bytes: [u8; 16] = *calculated_tag.as_ref();
        tag_bytes.ct_eq(expected_tag).into()
    }

    pub fn decrypt_chunk(&mut self, data: &mut Vec<u8>) {
        self.cipher.apply_keystream(data);
    }
}

#[macro_export]
macro_rules! xchacha20_poly1305_encrypt {
    ($key:expr, $nonce:expr, |$streamer:ident| $body:block) => {{
        let mut $streamer = $crate::XChaCha20Poly1305Encryptor::new($key, $nonce);
        $body
        $streamer.finalize_tag()
    }};
}

#[macro_export]
macro_rules! xchacha20_poly1305_decrypt {
    ($key:expr, $nonce:expr, $expected_tag:expr, $data:expr) => {{
        let mut decryptor = $crate::XChaCha20Poly1305Decryptor::new($key, $nonce);
        decryptor.authenticate_chunk($data);

        if decryptor.verify_tag($expected_tag) {
            let mut result = $data.clone();
            decryptor.decrypt_chunk(&mut result);
            Some(result)
        } else {
            None
        }
    }};
}
