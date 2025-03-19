# XChaCha20Poly1305 Stream

A Rust implementation of XChaCha20Poly1305 for streaming encryption and authentication.

## Features

- Streaming API for handling large data in chunks
- XChaCha20 for encryption (256-bit key, 192-bit nonce)
- Poly1305 for authentication
- Constant-time tag verification

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
xchacha20poly1305stream = "0.1.0"
```

## Running Tests

To run the test suite:

```bash
cargo test
```

This will execute all tests including:
- Basic encryption/decryption
- Tampered tag detection
- Tampered ciphertext detection
- Streaming encryption
- Different keys and nonces

## Usage Example

```rust
use xchacha20poly1305stream::{xchacha20_poly1305_decrypt, xchacha20_poly1305_encrypt};

// Initialize key and nonce
let key = [0x42; 32];
let nonce = [0x24; 24];

// Prepare data
let mut data = b"This is a secret message".to_vec();

// Encrypt data
let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
    streamer.encrypt_chunk(&mut data);
});

// Decrypt data
let decryption_result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, &data);

match decryption_result {
    Some(decrypted) => println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted)),
    None => println!("Authentication failed"),
}
```

## Streaming Example

For handling large data in chunks:

```rust
let key = [0x42; 32];
let nonce = [0x24; 24];

let mut chunk1 = b"First chunk".to_vec();
let mut chunk2 = b"Second chunk".to_vec();

// Encrypt chunks
let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
    streamer.encrypt_chunk(&mut chunk1);
    streamer.encrypt_chunk(&mut chunk2);
});

// Create decryptor for verification and decryption
let mut decryptor = XChaCha20Poly1305Decryptor::new(&key, &nonce);

// Authenticate chunks (without decrypting yet)
decryptor.authenticate_chunk(&chunk1);
decryptor.authenticate_chunk(&chunk2);

// Verify authentication tag
if decryptor.verify_tag(&tag) {
    // Only decrypt if authentication passed
    decryptor.decrypt_chunk(&mut chunk1);
    decryptor.decrypt_chunk(&mut chunk2);
}
```

## License

MIT
