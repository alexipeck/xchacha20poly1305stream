use chacha20::{
    XChaCha20,
    cipher::{KeyInit, KeyIvInit, StreamCipher},
};
use crypto_common::generic_array::GenericArray;
use poly1305::Poly1305;
use poly1305::universal_hash::UniversalHash;

pub struct Tagger {
    poly1305: Poly1305,
}

impl Tagger {
    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        let mut cipher = XChaCha20::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(nonce),
        );
        let mut block = [0u8; 64];
        cipher.apply_keystream(&mut block);
        let poly1305_key = GenericArray::from_slice(&block[..32]);
        let poly1305 = Poly1305::new(poly1305_key);

        Self { poly1305 }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.poly1305.update_padded(data);
    }

    pub fn finalize_tag(self) -> [u8; 16] {
        let tag = self.poly1305.finalize();
        *tag.as_ref()
    }
}

#[macro_export]
macro_rules! tag {
    ($key:expr, $nonce:expr, |$tagger:ident| $body:block) => {{
        let mut $tagger = $crate::tag::Tagger::new($key, $nonce);
        $body
        $tagger.finalize_tag()
    }};
}
