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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encryption_decryption() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];
        let plaintext = b"This is a secret message".to_vec();

        let mut ciphertext = plaintext.clone();
        let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.encrypt_chunk(&mut ciphertext);
        });

        assert_ne!(ciphertext, plaintext);

        let decryption_result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, &ciphertext);

        assert!(decryption_result.is_some());
        assert_eq!(decryption_result.unwrap(), plaintext);
    }

    #[test]
    fn test_tampered_tag_detection() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];
        let plaintext = b"This is a secret message".to_vec();

        let mut ciphertext = plaintext.clone();
        let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.encrypt_chunk(&mut ciphertext);
        });

        let mut bad_tag = tag;
        bad_tag[0] ^= 1;

        let tampered_result = xchacha20_poly1305_decrypt!(&key, &nonce, &bad_tag, &ciphertext);

        assert!(tampered_result.is_none());
    }

    #[test]
    fn test_tampered_ciphertext_detection() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];
        let plaintext = b"This is a secret message".to_vec();

        let mut ciphertext = plaintext.clone();
        let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.encrypt_chunk(&mut ciphertext);
        });

        let mut tampered_ciphertext = ciphertext.clone();
        tampered_ciphertext[0] ^= 1;

        let tampered_data_result =
            xchacha20_poly1305_decrypt!(&key, &nonce, &tag, &tampered_ciphertext);

        assert!(tampered_data_result.is_none());
    }

    #[test]
    fn test_streaming_encryption() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];
        let plaintext1 = b"First chunk of data".to_vec();
        let plaintext2 = b"Second chunk of data".to_vec();

        let mut ciphertext1 = plaintext1.clone();
        let mut ciphertext2 = plaintext2.clone();

        let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.encrypt_chunk(&mut ciphertext1);
            streamer.encrypt_chunk(&mut ciphertext2);
        });

        let mut decryptor = XChaCha20Poly1305Decryptor::new(&key, &nonce);

        decryptor.authenticate_chunk(&ciphertext1);
        decryptor.authenticate_chunk(&ciphertext2);

        assert!(decryptor.verify_tag(&tag));

        let mut decrypted1 = ciphertext1.clone();
        let mut decrypted2 = ciphertext2.clone();
        decryptor.decrypt_chunk(&mut decrypted1);
        decryptor.decrypt_chunk(&mut decrypted2);

        assert_eq!(decrypted1, plaintext1);
        assert_eq!(decrypted2, plaintext2);
    }

    #[test]
    fn test_different_keys_and_nonces() {
        let plaintext = b"Secret data needs protection".to_vec();

        let key1 = [0x42; 32];
        let nonce1 = [0x24; 24];

        let key2 = [0x55; 32];
        let nonce2 = [0x33; 24];

        let mut ciphertext1 = plaintext.clone();
        let tag1 = xchacha20_poly1305_encrypt!(&key1, &nonce1, |streamer| {
            streamer.encrypt_chunk(&mut ciphertext1);
        });

        let mut ciphertext2 = plaintext.clone();
        let tag2 = xchacha20_poly1305_encrypt!(&key2, &nonce2, |streamer| {
            streamer.encrypt_chunk(&mut ciphertext2);
        });

        assert_ne!(ciphertext1, ciphertext2);

        assert_ne!(tag1, tag2);

        let cross_result = xchacha20_poly1305_decrypt!(&key1, &nonce1, &tag1, &ciphertext2);
        assert!(cross_result.is_none());

        let decrypted1 = xchacha20_poly1305_decrypt!(&key1, &nonce1, &tag1, &ciphertext1).unwrap();
        let decrypted2 = xchacha20_poly1305_decrypt!(&key2, &nonce2, &tag2, &ciphertext2).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
}
