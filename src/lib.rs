use chacha20::{
    XChaCha20,
    cipher::{KeyInit, KeyIvInit, StreamCipher},
};
use crypto_common::generic_array::GenericArray;
use poly1305::Poly1305;
use poly1305::universal_hash::UniversalHash;

pub struct XChaCha20Poly1305Streamer {
    cipher: XChaCha20,
    poly1305: Poly1305,
}

impl XChaCha20Poly1305Streamer {
    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        let cipher_key = GenericArray::from_slice(key);
        let cipher_nonce = GenericArray::from_slice(nonce);
        let cipher = XChaCha20::new(cipher_key, cipher_nonce);

        let poly_key = GenericArray::from_slice(key);
        let poly1305 = Poly1305::new(poly_key);

        Self { cipher, poly1305 }
    }

    pub fn apply_keystream(&mut self, data: &mut Vec<u8>) {
        self.cipher.apply_keystream(data);

        let data_slice = data.as_slice();
        self.poly1305.update_padded(data_slice);
    }

    pub fn finalize_tag(self) -> [u8; 16] {
        let tag = self.poly1305.finalize();
        *tag.as_ref()
    }
}

#[macro_export]
macro_rules! xchacha20_poly1305_stream {
    ($key:expr, $nonce:expr, |$streamer:ident| $body:block) => {{
        let mut $streamer = $crate::XChaCha20Poly1305Streamer::new($key, $nonce);
        $body
        $streamer.finalize_tag()
    }};
}
