use xchacha20poly1305stream::{decrypt, encrypt, verify};

fn main() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];

    let mut data = b"This is a secret message".to_vec();
    println!("Original plaintext: {:?}", String::from_utf8_lossy(&data));

    let tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut data);
    });

    println!("Ciphertext: {:?}", data);
    println!("Authentication tag: {:?}", tag);

    let mut decrypted_text = data.clone();

    // Verify first
    let verification = verify!(&key, &nonce, &tag, |streamer| {
        streamer.feed(&mut decrypted_text);
    });

    if verification {
        // Then decrypt if verified
        decrypt!(&key, &nonce, |streamer| {
            streamer.feed(&mut decrypted_text);
        });

        println!(
            "Decrypted text: {:?}",
            String::from_utf8_lossy(&decrypted_text)
        );
        println!("Authentication successful");
    } else {
        println!("Authentication failed");
    }

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;

    let mut decrypted_tampered_tag = data.clone();

    // Try to verify data with tampered tag
    let tampered_verification = verify!(&key, &nonce, &bad_tag, |streamer| {
        streamer.feed(&mut decrypted_tampered_tag);
    });

    if tampered_verification {
        println!("Something went wrong - tampered tag was accepted");
    } else {
        println!("Security working correctly - tampered tag rejected");
    }

    let mut tampered_ciphertext = data.clone();
    tampered_ciphertext[0] ^= 1;

    // Try to verify tampered ciphertext
    let tampered_data_verification = verify!(&key, &nonce, &tag, |streamer| {
        streamer.feed(&mut tampered_ciphertext);
    });

    if tampered_data_verification {
        println!("Something went wrong - tampered ciphertext was accepted");
    } else {
        println!("Security working correctly - tampered ciphertext rejected");
    }
}
