use crate::authenticate::Authenticator;
use crate::decrypt::Decryptor;
use crate::encrypt::Encryptor;
use crate::tag::Tagger;
use crate::*;

#[test]
fn test_basic_encryption_decryption() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let plaintext = b"This is a secret message".to_vec();

    let mut ciphertext = plaintext.clone();
    let tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut ciphertext);
    });

    assert_ne!(ciphertext, plaintext);

    let mut decrypted = ciphertext.clone();
    let is_authentic = decrypt!(&key, &nonce, &tag, |streamer| {
        streamer.feed(&mut decrypted);
    });

    assert!(is_authentic);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_tampered_tag_detection() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let plaintext = b"This is a secret message".to_vec();

    let mut ciphertext = plaintext.clone();
    let tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut ciphertext);
    });

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;

    let mut decrypted = ciphertext.clone();

    let verification = authenticate!(&key, &nonce, &bad_tag, |streamer| {
        streamer.feed(&mut decrypted);
    });

    assert!(!verification);
}

#[test]
fn test_tampered_ciphertext_detection() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let plaintext = b"This is a secret message".to_vec();

    let mut ciphertext = plaintext.clone();
    let tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut ciphertext);
    });

    let mut tampered_ciphertext = ciphertext.clone();
    tampered_ciphertext[0] ^= 1;

    let verification = authenticate!(&key, &nonce, &tag, |streamer| {
        streamer.feed(&mut tampered_ciphertext);
    });

    assert!(!verification);
}

#[test]
fn test_streaming_encryption() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let plaintext1 = b"First chunk of data".to_vec();
    let plaintext2 = b"Second chunk of data".to_vec();

    let mut ciphertext1 = plaintext1.clone();
    let mut ciphertext2 = plaintext2.clone();

    let tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut ciphertext1);
        streamer.feed(&mut ciphertext2);
    });

    let mut decrypted1 = ciphertext1.clone();
    let mut decrypted2 = ciphertext2.clone();

    let mut authenticator = Authenticator::new(&key, &nonce);
    authenticator.feed(&decrypted1);
    authenticator.feed(&decrypted2);

    assert!(authenticator.verify_tag(&tag));

    let mut decryptor = Decryptor::new(&key, &nonce);
    decryptor.feed(&mut decrypted1);
    decryptor.feed(&mut decrypted2);

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
    let tag1 = encrypt!(&key1, &nonce1, |streamer| {
        streamer.feed(&mut ciphertext1);
    });

    let mut ciphertext2 = plaintext.clone();
    let tag2 = encrypt!(&key2, &nonce2, |streamer| {
        streamer.feed(&mut ciphertext2);
    });

    assert_ne!(ciphertext1, ciphertext2);
    assert_ne!(tag1, tag2);

    let mut cross_ciphertext = ciphertext2.clone();
    let cross_verify = authenticate!(&key1, &nonce1, &tag1, |streamer| {
        streamer.feed(&mut cross_ciphertext);
    });
    assert!(!cross_verify);

    let mut decryption1 = ciphertext1.clone();
    let authentic1 = decrypt!(&key1, &nonce1, &tag1, |streamer| {
        streamer.feed(&mut decryption1);
    });
    assert!(authentic1);
    assert_eq!(decryption1, plaintext);

    let mut decryption2 = ciphertext2.clone();
    let authentic2 = decrypt!(&key2, &nonce2, &tag2, |streamer| {
        streamer.feed(&mut decryption2);
    });
    assert!(authentic2);
    assert_eq!(decryption2, plaintext);
}

#[test]
fn test_streaming_verify_decrypt() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let plaintext1 = b"First chunk of data".to_vec();
    let plaintext2 = b"Second chunk of data".to_vec();

    let mut ciphertext1 = plaintext1.clone();
    let mut ciphertext2 = plaintext2.clone();

    let tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut ciphertext1);
        streamer.feed(&mut ciphertext2);
    });

    let mut decrypted1 = ciphertext1.clone();
    let mut decrypted2 = ciphertext2.clone();

    let is_authentic = decrypt!(&key, &nonce, &tag, |streamer| {
        streamer.feed(&mut decrypted1);
        streamer.feed(&mut decrypted2);
    });

    assert!(is_authentic);
    assert_eq!(decrypted1, plaintext1);
    assert_eq!(decrypted2, plaintext2);
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

    let tag = encrypt!(&key, &nonce, |streamer| {
        for chunk in chunks.iter_mut() {
            streamer.feed(chunk);
        }
    });

    for (original, encrypted) in original_chunks.iter().zip(chunks.iter()) {
        assert_ne!(original, encrypted);
    }

    let mut decryptor = Decryptor::new(&key, &nonce);
    for chunk in chunks.iter_mut() {
        decryptor.feed(chunk);
    }
    let verification = decryptor.verify_tag(&tag);
    assert!(verification);

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

    let tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut chunk1);
        streamer.feed(&mut chunk2);
        streamer.feed(&mut chunk3);
    });

    let mut decrypt1 = chunk1.clone();
    let mut decrypt2 = chunk2.clone();

    let verification = authenticate!(&key, &nonce, &tag, |streamer| {
        streamer.feed(&mut decrypt1);
        streamer.feed(&mut decrypt2);
    });

    assert!(!verification);
}

#[test]
fn test_with_associated_data() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];

    let mut message = b"Secret message".to_vec();
    let associated_data1 = b"Associated metadata 1".to_vec();
    let associated_data2 = b"Associated metadata 2".to_vec();

    let mut encryptor = encrypt::Encryptor::new(&key, &nonce);
    encryptor.add_associated_data(&associated_data1);
    encryptor.add_associated_data(&associated_data2);

    encryptor.feed(&mut message);
    let tag = encryptor.finalize_tag();

    let original_message = b"Secret message".to_vec();

    let mut decrypted_message = message.clone();
    let mut authenticator = authenticate::Authenticator::new(&key, &nonce);
    authenticator.add_associated_data(&associated_data1);
    authenticator.add_associated_data(&associated_data2);
    authenticator.feed(&decrypted_message);

    assert!(authenticator.verify_tag(&tag));

    let mut decryptor = decrypt::Decryptor::new(&key, &nonce);
    decryptor.feed(&mut decrypted_message);
    assert_eq!(decrypted_message, original_message);

    let wrong_message = message.clone();
    let mut authenticator_wrong = authenticate::Authenticator::new(&key, &nonce);
    let wrong_data = b"Wrong data".to_vec();
    authenticator_wrong.add_associated_data(&wrong_data);
    authenticator_wrong.add_associated_data(&associated_data2);
    authenticator_wrong.feed(&wrong_message);

    assert!(!authenticator_wrong.verify_tag(&tag));

    let missing_message = message.clone();
    let mut authenticator_missing = authenticate::Authenticator::new(&key, &nonce);
    authenticator_missing.add_associated_data(&associated_data2);
    authenticator_missing.feed(&missing_message);

    assert!(!authenticator_missing.verify_tag(&tag));

    let mut message2 = b"Another secret".to_vec();
    let mut encryptor2 = encrypt::Encryptor::new(&key, &nonce);
    encryptor2.add_associated_data(&associated_data1);
    encryptor2.add_associated_data(&associated_data2);
    encryptor2.feed(&mut message2);
    let tag2 = encryptor2.finalize_tag();

    let original_message2 = b"Another secret".to_vec();

    let mut decrypted2 = message2.clone();
    let mut decryptor2 = decrypt::Decryptor::new(&key, &nonce);
    decryptor2.add_associated_data(&associated_data1);
    decryptor2.add_associated_data(&associated_data2);
    decryptor2.feed(&mut decrypted2);

    let is_authentic = decryptor2.verify_tag(&tag2);
    assert!(is_authentic);
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

    let tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut ciphertext1);
        streamer.feed(&mut ciphertext2);
    });

    let mut decrypt1 = ciphertext1.clone();
    let mut decrypt2 = ciphertext2.clone();

    let mut decryptor = decrypt::Decryptor::new(&key, &nonce);
    decryptor.feed(&mut decrypt1);
    decryptor.feed(&mut decrypt2);
    let is_authentic = decryptor.verify_tag(&tag);

    assert!(is_authentic);
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

    let mut encryptor = Encryptor::new(&key, &nonce);
    encryptor.feed(&mut ciphertext1);
    encryptor.feed(&mut ciphertext2);
    let tag = encryptor.finalize_tag();

    let mut decrypted1 = ciphertext1.clone();
    let mut decrypted2 = ciphertext2.clone();

    let mut decryptor = Decryptor::new(&key, &nonce);
    decryptor.feed(&mut decrypted1);
    decryptor.feed(&mut decrypted2);
    let is_authentic = decryptor.verify_tag(&tag);

    assert!(is_authentic);
    assert_eq!(decrypted1, plaintext1);
    assert_eq!(decrypted2, plaintext2);

    let mut macro_ciphertext1 = plaintext1.clone();
    let mut macro_ciphertext2 = plaintext2.clone();

    let macro_tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut macro_ciphertext1);
        streamer.feed(&mut macro_ciphertext2);
    });

    assert_eq!(tag, macro_tag);
    assert_eq!(ciphertext1, macro_ciphertext1);
    assert_eq!(ciphertext2, macro_ciphertext2);
}

#[test]
fn test_combined_decrypt_authentication() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let plaintext = b"This is a secret message".to_vec();

    let mut ciphertext = plaintext.clone();
    let tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut ciphertext);
    });

    let mut decrypted = ciphertext.clone();
    let is_authentic = decrypt!(&key, &nonce, &tag, |streamer| {
        streamer.feed(&mut decrypted);
    });

    assert!(is_authentic);
    assert_eq!(decrypted, plaintext);

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    let mut tampered = ciphertext.clone();

    let tampered_result = decrypt!(&key, &nonce, &bad_tag, |streamer| {
        streamer.feed(&mut tampered);
    });

    assert!(!tampered_result);
}

#[test]
fn test_tag_generation() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let data = b"This is data for tag generation".to_vec();

    let tag = tag!(&key, &nonce, |tagger| {
        tagger.feed(&data);
    });

    assert_eq!(tag.len(), 16);

    let verification = authenticate!(&key, &nonce, &tag, |authenticator| {
        authenticator.feed(&data);
    });

    assert!(verification);

    let mut tampered_data = data.clone();
    tampered_data[0] ^= 1;

    let verification_tampered = authenticate!(&key, &nonce, &tag, |authenticator| {
        authenticator.feed(&tampered_data);
    });

    assert!(!verification_tampered);
}

#[test]
fn test_streaming_tag_generation() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let data1 = b"First chunk for tagging".to_vec();
    let data2 = b"Second chunk for tagging".to_vec();
    let data3 = b"Third chunk for tagging".to_vec();

    let tag = tag!(&key, &nonce, |tagger| {
        tagger.feed(&data1);
        tagger.feed(&data2);
        tagger.feed(&data3);
    });

    assert_eq!(tag.len(), 16);

    let verification = authenticate!(&key, &nonce, &tag, |authenticator| {
        authenticator.feed(&data1);
        authenticator.feed(&data2);
        authenticator.feed(&data3);
    });

    assert!(verification);
}

#[test]
fn test_tag_equivalence() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let data = b"Testing tag equivalence".to_vec();

    let tag1 = tag!(&key, &nonce, |tagger| {
        tagger.feed(&data);
    });

    let mut authenticator = Authenticator::new(&key, &nonce);
    authenticator.feed(&data);
    let tag2 = authenticator.verify_tag(&tag1);

    assert!(tag2);

    let mut tagger = Tagger::new(&key, &nonce);
    tagger.feed(&data);
    let tag3 = tagger.finalize_tag();

    assert_eq!(tag1, tag3);
}
