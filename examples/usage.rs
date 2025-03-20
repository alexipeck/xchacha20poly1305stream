use xchacha20poly1305stream::{xchacha20_poly1305_decrypt, xchacha20_poly1305_encrypt};

fn main() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];

    let mut data = b"This is a secret message".to_vec();
    println!("Original plaintext: {:?}", String::from_utf8_lossy(&data));

    let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut data);
    });

    println!("Ciphertext: {:?}", data);
    println!("Authentication tag: {:?}", tag);

    let mut decrypted_text = data.clone();

    let decryption_result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, |streamer| {
        streamer.feed(&mut decrypted_text);
    });

    match decryption_result {
        Some(_) => {
            println!(
                "Decrypted text: {:?}",
                String::from_utf8_lossy(&decrypted_text)
            );
            println!("Authentication successful");
        }
        None => println!("Authentication failed"),
    }

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;

    let mut decrypted_tampered_tag = data.clone();

    let tampered_result = xchacha20_poly1305_decrypt!(&key, &nonce, &bad_tag, |streamer| {
        streamer.feed(&mut decrypted_tampered_tag);
    });

    match tampered_result {
        Some(_) => println!("Something went wrong - tampered data was accepted"),
        None => println!("Security working correctly - tampered tag rejected"),
    }

    let mut tampered_ciphertext = data.clone();
    tampered_ciphertext[0] ^= 1;

    let tampered_data_result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, |streamer| {
        streamer.feed(&mut tampered_ciphertext);
    });

    match tampered_data_result {
        Some(_) => println!("Something went wrong - tampered ciphertext was accepted"),
        None => println!("Security working correctly - tampered ciphertext rejected"),
    }
}
