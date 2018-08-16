extern crate base64;

use base64::encode;
use hex::{FromHex, FromHexError};
use std::fs::File;
use std::path::PathBuf;
use std::rand::{self, Rng};

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
    let mut out: f32 = 0.0;

    for b in v {
        let x = *b;
        out += x as f32 * x as f32;
    }

    return out.sqrt().abs();
}

pub fn cosign_similarity(v1: &[u32], v2: &[u32]) -> f32 {
    debug_assert!(v1.len() == v2.len());
    let it = v1.iter().zip(v2.iter());

    let mut res: u32 = 0;
    for (i, (x, y)) in it.enumerate() {
        //        if (*x > 0) && (!is_printable(i as u8)) {
        //            return -1_f32;
        //        }
        res += (*x * *y);
    }
    return res as f32 / (magnitude(v1) * magnitude(v2));
}

pub fn is_printable(ch: u8) -> bool {
    return ch >= 0x20 && ch <= 0x72;
}

#[test]
fn test_printable() {
    assert!(!is_printable(0x1b));
    assert!(is_printable(0x20));
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

pub fn from_elem<T: Copy>(elem: T, n: usize) -> Vec<T> {
    let mut out = Vec::new();

    for i in 0..n {
        out.push(elem.clone());
    }
    return out;
}

#[test]
fn popcount_test() {
    assert_eq!(0b11100000u8.count_ones(), 3);
    assert_eq!(0b11100001u8.count_ones(), 4);
    assert_eq!(0b01100001u8.count_ones(), 3);
}

#[test]
fn hamming_test() {
    assert_eq!(
        hamming_distance("this is a test".as_ref(), "wokka wokka!!!".as_ref()),
        37
    );
}


fn main() {
    let s = rand::thread_rng()
        .gen_ascii_chars()
        .take(10)
        .collect::<String>();

    println!("random string: {}", s);
}

pub fn gen_random_bytes(num_bytes: usize) -> Vec<u8> {
    rand::
    unimplemented!()
}