use xchacha20poly1305stream::encrypt;

fn main() {
    let key = [7u8; 32];
    let nonce = [2u8; 24];
    let mut data = vec![1u8, 2, 3, 4, 5];

    let tag = encrypt!(&key, &nonce, |streamer| {
        streamer.feed(&mut data);
    });

    println!("{:02x?}", tag);
}
