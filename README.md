# XChaCha20Poly1305 Stream

A Rust implementation of XChaCha20Poly1305 for streaming encryption and authentication. This library allows processing data in chunks, making it suitable for encrypting and decrypting large files or data streams without loading everything into memory.

## Features

- **Streaming API**: Process data in chunks with minimal memory footprint
- **XChaCha20**: Secure encryption with extended nonces (256-bit key, 192-bit nonce)
- **Poly1305**: Strong message authentication
- **Constant-time tag verification**: Protects against timing attacks
- **Associated data support**: Authenticate non-encrypted metadata alongside your encrypted content

## Installation

This crate is not currently available on crates.io but may be in the future.

## API Overview

The library provides three main macros:

- `xchacha20_poly1305_encrypt!`: Encrypts data in chunks and returns an authentication tag
- `xchacha20_poly1305_decrypt!`: Decrypts data in chunks and verifies the authentication tag
- `xchacha20_poly1305_decrypt_simple!`: Simplified version of the decrypt macro

## Usage Examples

### Basic Example

```rust
use xchacha20poly1305stream::{xchacha20_poly1305_decrypt, xchacha20_poly1305_encrypt};

let key = [0x42; 32];
let nonce = [0x24; 24];

let mut data = b"This is a secret message".to_vec();

let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
    streamer.feed(&mut data);
});

let decryption_result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, |streamer| {
    streamer.feed(&mut data);
});

if decryption_result.is_some() {
    println!("Successfully decrypted: {}", String::from_utf8_lossy(&data));
} else {
    println!("Authentication failed");
}
```

### Streaming Example

```rust
let key = [0x42; 32];
let nonce = [0x24; 24];

let mut chunk1 = b"First chunk of data".to_vec();
let mut chunk2 = b"Second chunk of data".to_vec();

let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
    streamer.feed(&mut chunk1);
    streamer.feed(&mut chunk2);
});

let result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, |streamer| {
    streamer.feed(&mut chunk1);
    streamer.feed(&mut chunk2);
});

if result.is_some() {
    println!("Authentication successful");
} else {
    println!("Authentication failed");
}
```

### Using Associated Data

```rust
let key = [0x42; 32];
let nonce = [0x24; 24];

let mut message = b"Secret message".to_vec();
let associated_data = b"Public metadata".to_vec();

let tag = xchacha20_poly1305_encrypt!(&key, &nonce, |streamer| {
    streamer.add_associated_data(&associated_data);
    streamer.feed(&mut message);
});

let result = xchacha20_poly1305_decrypt!(&key, &nonce, &tag, |streamer| {
    streamer.add_associated_data(&associated_data);
    streamer.feed(&mut message);
});

// Authentication will fail if associated data doesn't match
```

## Security Notes

- Always use a unique nonce for each encryption with the same key
- The order of operations matters:
  - Call `add_associated_data` before `feed` for both encryption and decryption
  - Process data chunks in the same order during decryption as during encryption
- Authentication will fail if any part of the ciphertext, tag, or associated data is tampered with

## Performance Considerations

- The streaming approach allows processing files of any size with constant memory usage
- For optimal performance with large files, use chunk sizes between 4KB and 64KB
- The library processes data in-place to minimize memory allocations

## Running Tests

To run the test suite:

```bash
cargo test
```

The tests cover:
- Basic encryption/decryption
- Tampered tag detection
- Tampered ciphertext detection
- Streaming encryption
- Associated data handling

## License

MIT
