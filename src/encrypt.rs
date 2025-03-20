use chacha20::{
    XChaCha20,
    cipher::{KeyInit, KeyIvInit, StreamCipher},
};
use crypto_common::generic_array::GenericArray;
use poly1305::Poly1305;
use poly1305::universal_hash::UniversalHash;

pub struct Encryptor {
    cipher: XChaCha20,
    poly1305: Poly1305,
}

impl Encryptor {
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

    pub fn feed(&mut self, data: &mut Vec<u8>) {
        self.cipher.apply_keystream(data);
        let data_slice = data.as_slice();
        self.poly1305.update_padded(data_slice);
    }

    pub fn add_associated_data(&mut self, data: &[u8]) {
        self.poly1305.update_padded(data);
    }

    pub fn finalize_tag(self) -> [u8; 16] {
        let tag = self.poly1305.finalize();
        *tag.as_ref()
    }
}

#[macro_export]
macro_rules! encrypt {
    ($key:expr, $nonce:expr, |$streamer:ident| $body:block) => {{
        let mut $streamer = $crate::encrypt::Encryptor::new($key, $nonce);
        $body
        $streamer.finalize_tag()
    }};
}
