use chacha20::{
    XChaCha20,
    cipher::{KeyInit, KeyIvInit, StreamCipher},
};
use crypto_common::generic_array::GenericArray;
use poly1305::Poly1305;
use poly1305::universal_hash::UniversalHash;
use subtle::ConstantTimeEq;

pub mod implementation {
    use super::*;

    pub struct XChaCha20Poly1305Encryptor {
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

    pub struct XChaCha20Poly1305Decryptor {
        cipher: XChaCha20,
        poly1305: Poly1305,
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
}

#[macro_export]
macro_rules! xchacha20_poly1305_encrypt {
    ($key:expr, $nonce:expr, |$streamer:ident| $body:block) => {{
        let mut $streamer = $crate::implementation::XChaCha20Poly1305Encryptor::new($key, $nonce);
        $body
        $streamer.finalize_tag()
    }};
}

#[macro_export]
macro_rules! xchacha20_poly1305_decrypt {
    ($key:expr, $nonce:expr, $expected_tag:expr, |$streamer:ident| $auth_body:block, |$decryptor:ident| $decrypt_body:block) => {{
        let mut $streamer = $crate::implementation::XChaCha20Poly1305Decryptor::new($key, $nonce);
        $auth_body

        if $streamer.verify_tag($expected_tag) {
            let mut $decryptor = $streamer;
            $decrypt_body
            Some(())
        } else {
            None
        }
    }};
    ($key:expr, $nonce:expr, $expected_tag:expr, |$streamer:ident| $body:block) => {{
        let mut $streamer = $crate::implementation::XChaCha20Poly1305Decryptor::new($key, $nonce);
        $body

        if $streamer.verify_tag($expected_tag) {
            Some(())
        } else {
            None
        }
    }};
}

#[macro_export]
macro_rules! xchacha20_poly1305_decrypt_simple {
    ($key:expr, $nonce:expr, $expected_tag:expr, |$streamer:ident| $body:block) => {{
        let mut $streamer = $crate::implementation::XChaCha20Poly1305Decryptor::new($key, $nonce);
        $body
        if $streamer.verify_tag($expected_tag) {
            Some(())
        } else {
            None
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::implementation::{XChaCha20Poly1305Decryptor, XChaCha20Poly1305Encryptor};

    #[test]
    fn test_basic_encryption_decryption() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];
        let plaintext = b"This is a secret message".to_vec();

        let mut ciphertext = plaintext.clone();
        let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.feed(&mut ciphertext);
        });

        assert_ne!(ciphertext, plaintext);

        let mut decrypted = ciphertext.clone();

        let decryption_result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, |streamer| {
            streamer.feed(&mut decrypted);
        });

        assert!(decryption_result.is_some());
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_tag_detection() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];
        let plaintext = b"This is a secret message".to_vec();

        let mut ciphertext = plaintext.clone();
        let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.feed(&mut ciphertext);
        });

        let mut bad_tag = tag;
        bad_tag[0] ^= 1;

        let mut decrypted = ciphertext.clone();

        let tampered_result = xchacha20_poly1305_decrypt!(&key, &nonce, &bad_tag, |streamer| {
            streamer.feed(&mut decrypted);
        });

        assert!(tampered_result.is_none());
    }

    #[test]
    fn test_tampered_ciphertext_detection() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];
        let plaintext = b"This is a secret message".to_vec();

        let mut ciphertext = plaintext.clone();
        let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.feed(&mut ciphertext);
        });

        let mut tampered_ciphertext = ciphertext.clone();
        tampered_ciphertext[0] ^= 1;

        let tampered_data_result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, |streamer| {
            streamer.feed(&mut tampered_ciphertext);
        });

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
            streamer.feed(&mut ciphertext1);
            streamer.feed(&mut ciphertext2);
        });

        let mut decrypted1 = ciphertext1.clone();
        let mut decrypted2 = ciphertext2.clone();

        let mut decryptor = XChaCha20Poly1305Decryptor::new(&key, &nonce);
        decryptor.feed(&mut decrypted1);
        decryptor.feed(&mut decrypted2);

        assert!(decryptor.verify_tag(&tag));
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
            streamer.feed(&mut ciphertext1);
        });

        let mut ciphertext2 = plaintext.clone();
        let tag2 = xchacha20_poly1305_encrypt!(&key2, &nonce2, |streamer| {
            streamer.feed(&mut ciphertext2);
        });

        assert_ne!(ciphertext1, ciphertext2);
        assert_ne!(tag1, tag2);

        let mut cross_ciphertext = ciphertext2.clone();
        let cross_result = xchacha20_poly1305_decrypt!(&key1, &nonce1, &tag1, |streamer| {
            streamer.feed(&mut cross_ciphertext);
        });
        assert!(cross_result.is_none());

        let mut decryption1 = ciphertext1.clone();
        let result1 = xchacha20_poly1305_decrypt!(&key1, &nonce1, &tag1, |streamer| {
            streamer.feed(&mut decryption1);
        });
        assert!(result1.is_some());
        assert_eq!(decryption1, plaintext);

        let mut decryption2 = ciphertext2.clone();
        let result2 = xchacha20_poly1305_decrypt!(&key2, &nonce2, &tag2, |streamer| {
            streamer.feed(&mut decryption2);
        });
        assert!(result2.is_some());
        assert_eq!(decryption2, plaintext);
    }

    #[test]
    fn test_streaming_decrypt_macro() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];
        let plaintext1 = b"First chunk of data".to_vec();
        let plaintext2 = b"Second chunk of data".to_vec();

        let mut ciphertext1 = plaintext1.clone();
        let mut ciphertext2 = plaintext2.clone();

        let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.feed(&mut ciphertext1);
            streamer.feed(&mut ciphertext2);
        });

        let mut decrypted1 = ciphertext1.clone();
        let mut decrypted2 = ciphertext2.clone();

        let result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, |streamer| {
            streamer.feed(&mut decrypted1);
            streamer.feed(&mut decrypted2);

            assert_eq!(decrypted1, plaintext1);
            assert_eq!(decrypted2, plaintext2);
        });

        assert!(result.is_some());
    }

    #[test]
    fn test_large_data_streaming() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];

        let mut large_data = Vec::with_capacity(100 * 1024);
        for i in 0..100 * 1024 {
            large_data.push((i % 256) as u8);
        }

        let chunk_size = 16 * 1024;
        let mut chunks: Vec<Vec<u8>> = Vec::new();

        for chunk_start in (0..large_data.len()).step_by(chunk_size) {
            let chunk_end = std::cmp::min(chunk_start + chunk_size, large_data.len());
            chunks.push(large_data[chunk_start..chunk_end].to_vec());
        }

        let original_chunks = chunks.clone();

        let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            for chunk in chunks.iter_mut() {
                streamer.feed(chunk);
            }
        });

        for (original, encrypted) in original_chunks.iter().zip(chunks.iter()) {
            assert_ne!(original, encrypted);
        }

        let result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, |streamer| {
            for chunk in chunks.iter_mut() {
                streamer.feed(chunk);
            }
        });

        assert!(result.is_some());

        for (original, decrypted) in original_chunks.iter().zip(chunks.iter()) {
            assert_eq!(original, decrypted);
        }
    }

    #[test]
    fn test_authentication_failure_with_partial_data() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];

        let mut chunk1 = b"First chunk of the message".to_vec();
        let mut chunk2 = b"Second chunk of the message".to_vec();
        let mut chunk3 = b"Third chunk of the message".to_vec();

        let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.feed(&mut chunk1);
            streamer.feed(&mut chunk2);
            streamer.feed(&mut chunk3);
        });

        let mut decrypt1 = chunk1.clone();
        let mut decrypt2 = chunk2.clone();

        let result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, |streamer| {
            streamer.feed(&mut decrypt1);
            streamer.feed(&mut decrypt2);
        });

        assert!(result.is_none());
    }

    #[test]
    fn test_with_associated_data() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];

        let mut message = b"Secret message".to_vec();
        let associated_data1 = b"Associated metadata 1".to_vec();
        let associated_data2 = b"Associated metadata 2".to_vec();

        let mut encryptor = implementation::XChaCha20Poly1305Encryptor::new(&key, &nonce);
        encryptor.add_associated_data(&associated_data1);
        encryptor.add_associated_data(&associated_data2);

        encryptor.feed(&mut message);
        let tag = encryptor.finalize_tag();

        let original_message = b"Secret message".to_vec();

        let mut decrypted_message = message.clone();
        let mut decryptor = implementation::XChaCha20Poly1305Decryptor::new(&key, &nonce);
        decryptor.add_associated_data(&associated_data1);
        decryptor.add_associated_data(&associated_data2);
        decryptor.feed(&mut decrypted_message);

        assert!(decryptor.verify_tag(&tag));
        assert_eq!(decrypted_message, original_message);

        let mut wrong_decrypted = message.clone();
        let mut decryptor_wrong = implementation::XChaCha20Poly1305Decryptor::new(&key, &nonce);
        let wrong_data = b"Wrong data".to_vec();
        decryptor_wrong.add_associated_data(&wrong_data);
        decryptor_wrong.add_associated_data(&associated_data2);
        decryptor_wrong.feed(&mut wrong_decrypted);

        assert!(!decryptor_wrong.verify_tag(&tag));

        let mut missing_decrypted = message.clone();
        let mut decryptor_missing = implementation::XChaCha20Poly1305Decryptor::new(&key, &nonce);
        decryptor_missing.add_associated_data(&associated_data2);
        decryptor_missing.feed(&mut missing_decrypted);

        assert!(!decryptor_missing.verify_tag(&tag));

        let mut message2 = b"Another secret".to_vec();
        let tag2 = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.add_associated_data(&associated_data1);
            streamer.add_associated_data(&associated_data2);
            streamer.feed(&mut message2);
        });

        let original_message2 = b"Another secret".to_vec();

        let mut decrypted2 = message2.clone();
        let result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag2, |streamer| {
            streamer.add_associated_data(&associated_data1);
            streamer.add_associated_data(&associated_data2);
            streamer.feed(&mut decrypted2);
        });

        assert!(result.is_some());
        assert_eq!(decrypted2, original_message2);
    }

    #[test]
    fn test_wrong_order_decryption() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];

        let data1 = b"First chunk of the message".to_vec();
        let data2 = b"Second chunk of the message".to_vec();

        let mut ciphertext1 = data1.clone();
        let mut ciphertext2 = data2.clone();

        let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.feed(&mut ciphertext1);
            streamer.feed(&mut ciphertext2);
        });

        let mut decrypt1 = ciphertext1.clone();
        let mut decrypt2 = ciphertext2.clone();

        let mut decryptor = implementation::XChaCha20Poly1305Decryptor::new(&key, &nonce);
        decryptor.feed(&mut decrypt1);
        decryptor.feed(&mut decrypt2);

        assert!(decryptor.verify_tag(&tag));
        assert_eq!(decrypt1, data1);
        assert_eq!(decrypt2, data2);
    }

    #[test]
    fn test_manual_implementation_use() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];
        let plaintext1 = b"First manual chunk".to_vec();
        let plaintext2 = b"Second manual chunk".to_vec();

        let mut ciphertext1 = plaintext1.clone();
        let mut ciphertext2 = plaintext2.clone();

        let mut encryptor = XChaCha20Poly1305Encryptor::new(&key, &nonce);
        encryptor.feed(&mut ciphertext1);
        encryptor.feed(&mut ciphertext2);
        let tag = encryptor.finalize_tag();

        let mut decrypted1 = ciphertext1.clone();
        let mut decrypted2 = ciphertext2.clone();

        let mut decryptor = XChaCha20Poly1305Decryptor::new(&key, &nonce);
        decryptor.feed(&mut decrypted1);
        decryptor.feed(&mut decrypted2);

        assert!(decryptor.verify_tag(&tag));
        assert_eq!(decrypted1, plaintext1);
        assert_eq!(decrypted2, plaintext2);

        let mut macro_ciphertext1 = plaintext1.clone();
        let mut macro_ciphertext2 = plaintext2.clone();

        let macro_tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.feed(&mut macro_ciphertext1);
            streamer.feed(&mut macro_ciphertext2);
        });

        assert_eq!(tag, macro_tag);
        assert_eq!(ciphertext1, macro_ciphertext1);
        assert_eq!(ciphertext2, macro_ciphertext2);
    }

    #[test]
    fn test_simplified_decrypt_macro_syntax() {
        let key = [0x42; 32];
        let nonce = [0x24; 24];
        let plaintext1 = b"First chunk for simplified syntax".to_vec();
        let plaintext2 = b"Second chunk for simplified syntax".to_vec();

        let mut ciphertext1 = plaintext1.clone();
        let mut ciphertext2 = plaintext2.clone();

        let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
            streamer.feed(&mut ciphertext1);
            streamer.feed(&mut ciphertext2);
        });

        let mut decrypt1 = ciphertext1.clone();
        let mut decrypt2 = ciphertext2.clone();

        let result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, |streamer| {
            streamer.feed(&mut decrypt1);
            streamer.feed(&mut decrypt2);
        });

        assert!(result.is_some());
        assert_eq!(decrypt1, plaintext1);
        assert_eq!(decrypt2, plaintext2);

        let mut bad_tag = tag;
        bad_tag[0] ^= 1;

        let mut tampered_decrypt1 = ciphertext1.clone();
        let mut tampered_decrypt2 = ciphertext2.clone();

        let tampered_result = xchacha20_poly1305_decrypt!(&key, &nonce, &bad_tag, |streamer| {
            streamer.feed(&mut tampered_decrypt1);
            streamer.feed(&mut tampered_decrypt2);
        });

        assert!(tampered_result.is_none());
    }
}
