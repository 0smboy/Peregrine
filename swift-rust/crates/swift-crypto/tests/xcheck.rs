#[test]
fn xcheck_python_crypto() {
    let key = [1u8; 32];
    let iv = [2u8; 16];
    let pt = b"the quick brown fox ".repeat(3);
    let ct = swift_crypto::crypto::encrypt(&key, &iv, &pt).unwrap();
    let ct_hex: String = ct.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(ct_hex, "16c677d355ca836bbed617c77c75059fc3c2a874eb51ec4d3a5d27ab9f86d0046e658cc767095a9708bd354cfc1f0adcf20368169e5c5a1aabbb7832",
        "Rust ciphertext must match Python crypto_utils");
    // offset decrypt from byte 10
    let dec = swift_crypto::crypto::decrypt(&key, &iv, 10, &ct[10..]).unwrap();
    assert_eq!(dec, pt[10..].to_vec(), "offset decrypt");
}
