extern crate base64;

use hex::{FromHex, FromHexError, ToHex};
use base64::encode;

pub fn hex_to_base64(input: &str) -> Result<String, FromHexError> {
    match Vec::from_hex(input) {
        Ok(vec) => {
            for b in &vec {
                println!("{}", *b as char);
            }
            let output = base64::encode(&vec);
            return Ok(output);
        }
        Err(e) => {
            return Err(e);
        }
    }
}

pub fn xor_bytes(v1: &[u8], v2: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();

    let combined = v1.iter().zip(v2.iter());
    for (b1, b2) in combined {
        out.push(b1 ^ b2);
    }
    return out;
}


fn magnitude(v: &[u32]) -> f32 {
    let mut out: u32 = 0;

    for b in v {
        let x = *b;
        out += x * x;
    }

    return (out as f32).sqrt();
}

pub fn cosign_similarity(v1: &[u32], v2: &[u32]) -> f32 {
    debug_assert!(v1.len() == v2.len());
    let it = v1.iter().zip(v2.iter());

    let mut res: u32 = 0;
    for (x, y) in it {
        res += (*x * *y);
    }
    return res as f32/(magnitude(v1) * magnitude(v2));
}

pub struct CharFrequency([u32; 256]);

impl CharFrequency {
    pub fn from_text(text: &[u8]) -> CharFrequency {
        let mut freq = [0 as u32; 256];

        for b in text {
            freq[*b as usize] += 1;
        }
        return CharFrequency(freq);
    }

    pub fn score(&self, base: &CharFrequency) -> f32 {
        return cosign_similarity(&self.0, &base.0);
    }
}

pub fn repeating_key_xor(text: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();

    let mut index = 0 as usize;
    let key_len = key.len();
    while index < text.len() {
        output.push(text[index] ^ key[index % key_len]);
        index += 1;
    }

    return output;
}

pub fn hamming_distance(buf1: &[u8], buf2: &[u8]) -> u32 {
    let b1 = buf1.into_iter();
    let b2 = buf2.into_iter();

    let mut distance = 0u32;
    for (v1, v2) in b1.zip(b2) {
        let x = *v1 ^ *v2;
        distance += x.count_ones();
    }
    return distance;
}

pub fn transpose(buf: &[u8], slice_len: u32) -> Vec<Vec<u8>> {
    let l = slice_len;

    let index = 0u32;
    while index < buf.len() {

    }
    unimplemented!()


}


#[test]
fn popcount_test() {
    assert_eq!(0b11100000u8.count_ones(), 3);
    assert_eq!(0b11100001u8.count_ones(), 4);
    assert_eq!(0b01100001u8.count_ones(), 3);
}

#[test]
fn hammiing_test() {
    assert_eq!(hamming_distance("this is a test".as_ref(), "wokka wokka!!!".as_ref()), 37);
}

