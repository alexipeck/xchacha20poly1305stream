use xchacha20poly1305stream::xchacha20_poly1305_stream;

fn main() {
    let key = [7u8; 32];
    let nonce = [2u8; 24];
    let mut data = vec![1u8, 2, 3, 4, 5];

    let tag = xchacha20_poly1305_stream!(&key, &nonce, |streamer| {
        streamer.apply_keystream(&mut data);
    });

    println!("{:02x?}", tag);
}
