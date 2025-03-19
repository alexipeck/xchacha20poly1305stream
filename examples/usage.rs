use xchacha20poly1305stream::{xchacha20_poly1305_decrypt, xchacha20_poly1305_encrypt};

fn main() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];

    let mut plaintext = b"This is a secret message".to_vec();
    println!(
        "Original plaintext: {:?}",
        String::from_utf8_lossy(&plaintext)
    );

    let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
        let mut ciphertext = plaintext.clone();
        streamer.encrypt_chunk(&mut ciphertext);
        println!("Ciphertext: {:?}", ciphertext);

        plaintext = ciphertext;
    });

    println!("Authentication tag: {:?}", tag);

    let decryption_result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, &plaintext);

    match decryption_result {
        Some(decrypted) => {
            println!("Decrypted text: {:?}", String::from_utf8_lossy(&decrypted));
            println!("Authentication successful");
        }
        None => println!("Authentication failed"),
    }

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;

    let tampered_result = xchacha20_poly1305_decrypt!(&key, &nonce, &bad_tag, &plaintext);

    match tampered_result {
        Some(_) => println!("Something went wrong - tampered data was accepted"),
        None => println!("Security working correctly"),
    }

    let mut tampered_ciphertext = plaintext.clone();
    tampered_ciphertext[0] ^= 1;

    let tampered_data_result =
        xchacha20_poly1305_decrypt!(&key, &nonce, &tag, &tampered_ciphertext);

    match tampered_data_result {
        Some(_) => println!("Something went wrong - tampered ciphertext was accepted"),
        None => println!("Security working correctly"),
    }
}
