use cipher::*;
use charfreq::BASE_DIR;
use std::fs::File;
use std::path::PathBuf;
use base64;
use hex;
use std::io::Read;

#[test]
pub fn pad_test() {
    let inp = "YELLOW SUBMARINE";

    let v = pad(inp.as_ref(), 20);
    assert_eq!(v.len(), 20);
    assert_eq!(v[v.len()-1], 4);
}

#[test]
pub fn cbc_mode_test() {
    let infile = BASE_DIR.to_owned() + "/tests/data/10.txt";

    let path = PathBuf::from(infile);
    let mut f = File::open(path).unwrap();

    let mut contents = String::new();
    f.read_to_string(&mut contents);

    let decoded = base64::decode(&contents).unwrap();
    let v = decrypt_aes_cbc(decoded.as_ref(), "YELLOW SUBMARINE");
    let res = String::from_utf8(v).unwrap();
    assert!(res.contains("funky"));
}

pub fn cbc_detect() {
    let plain = [0u8; 48];

    for i in 0..25 {
        let res = encrypt_random_mode(plain.as_ref());
        let cipher = res.cipher;

        let second_blk = cipher[16..32];
        let third_blk = cipher[32..48];

        if (second_blk == third_blk) {
            assert!(res.is_mode(CipherMode::ECB));
        } else {
            assert!(res.is_mode(CipherMode::CBC));
        }
    }
}