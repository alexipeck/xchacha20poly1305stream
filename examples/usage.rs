use xchacha20poly1305stream::{decrypt, encrypt, verify};

fn main() {
    println!("\n===== BASIC ENCRYPTION AND DECRYPTION =====");

    let key = [0x42; 32];
    let nonce = [0x24; 24];

    let mut data = b"This is a secret message".to_vec();
    println!("Original plaintext: {:?}", String::from_utf8_lossy(&data));

    let tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut data);
    });

    println!("Ciphertext: {:?}", data);
    println!("Authentication tag: {:?}", tag);

    // Example 1: Using decrypt for both decryption and authentication in one step
    let mut decrypted_text = data.clone();
    let is_authentic = decrypt!(&key, &nonce, &tag, |streamer| {
        streamer.feed(&mut decrypted_text);
    });

    if is_authentic {
        println!(
            "Successfully decrypted: {:?}",
            String::from_utf8_lossy(&decrypted_text)
        );
        println!("Authentication successful");
    } else {
        println!("Authentication failed - decryption insecure");
    }

    // Example 2: Using verify macro only (for verification without decryption)
    let verification = verify!(&key, &nonce, &tag, |streamer| {
        streamer.feed(&data);
    });

    if verification {
        println!("Data is authentic");
    } else {
        println!("Data has been tampered with");
    }

    println!("\n===== SECURITY TESTS =====");

    // Tampered tag example
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;

    let mut decrypted_tampered_tag = data.clone();
    let tampered_tag_result = decrypt!(&key, &nonce, &bad_tag, |streamer| {
        streamer.feed(&mut decrypted_tampered_tag);
    });

    if tampered_tag_result {
        println!("SECURITY FAILURE - tampered tag was accepted");
    } else {
        println!("Security working correctly - tampered tag rejected");
    }

    // Tampered data example
    let mut tampered_ciphertext = data.clone();
    tampered_ciphertext[0] ^= 1;

    let tampered_data_result = decrypt!(&key, &nonce, &tag, |streamer| {
        streamer.feed(&mut tampered_ciphertext);
    });

    if tampered_data_result {
        println!("SECURITY FAILURE - tampered ciphertext was accepted");
    } else {
        println!("Security working correctly - tampered ciphertext rejected");
    }

    println!("\n===== STREAMING EXAMPLE =====");

    let mut chunk1 = b"First chunk of data".to_vec();
    let mut chunk2 = b"Second chunk of data".to_vec();

    println!("Original chunk1: {:?}", String::from_utf8_lossy(&chunk1));
    println!("Original chunk2: {:?}", String::from_utf8_lossy(&chunk2));

    let streaming_tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut chunk1);
        streamer.feed(&mut chunk2);
    });

    println!("Encrypted chunks successfully");

    // Clone for decryption
    let mut decrypted1 = chunk1.clone();
    let mut decrypted2 = chunk2.clone();

    let stream_is_authentic = decrypt!(&key, &nonce, &streaming_tag, |streamer| {
        streamer.feed(&mut decrypted1);
        streamer.feed(&mut decrypted2);
    });

    if stream_is_authentic {
        println!("Authentication successful and data decrypted");
        println!(
            "Decrypted chunk 1: {:?}",
            String::from_utf8_lossy(&decrypted1)
        );
        println!(
            "Decrypted chunk 2: {:?}",
            String::from_utf8_lossy(&decrypted2)
        );
    } else {
        println!("Authentication failed");
    }
}
