extern crate hex;
extern crate base64;

pub mod util;
pub mod keylength;

use util::*;
use keylength::*;
use std::fs::File;
use std::path::PathBuf;
use std::io::BufReader;
use std::io::prelude::*;

use hex::{FromHex, FromHexError, ToHex};
use std::collections::HashSet;
use std::iter::FromIterator;

#[test]
fn hex_base64_test() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    let output = hex_to_base64(hex).unwrap();
    let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(expected_output, &output);
}

#[test]
fn test_fixed_xor() {
    let input1 = "1c0111001f010100061a024b53535009181c";
    let input2 = "686974207468652062756c6c277320657965";

    let v1 = Vec::from_hex(input1).unwrap();
    let v2 = Vec::from_hex(input2).unwrap();

    let out = xor_bytes(v1.as_ref(), v2.as_ref());
    let output = hex::encode(out);
    assert_eq!(output, "746865206b696420646f6e277420706c6179");
}

fn to_plain_text(input: &[u8]) -> (f32, String) {

    let v1 = Vec::from_hex(input).unwrap();

    let mut b: u8 = 0;
    let mut max_score = 0.0 as f32;
    let mut max_score_string = "".to_owned();

    let base_freq = CharFrequency::from_text("To manage large amounts of data, modern web applications often
follow a two-stack architecture, with a front-end application stack
fulfilling application semantics and a back-end database management
system (DBMS) storing persistent data and processing data retrieval
requests. To help developers construct such database-backed
web applications, Object Relational Mapping (ORM) frameworks
have become increasingly popular, with implementations in all
common general-purpose languages: the Ruby on Rails framework
(Rails) for Ruby [22], Django for Python [9], and Hibernate for Java
[14]. These ORM frameworks allow developers to program such
database-backed web applications in a DBMS oblivious way, as the
frameworks expose APIs for developers to operate persistent data
stored in the DBMS as if they are regular heap objects, with regularlooking
method calls transparently translated to SQL queries by
frameworks when executed.".to_ascii_lowercase().as_ref());

    while (b <= 255) {
        let key = from_elem(b, input.len());
        let decrypted = xor_bytes(v1.as_ref(), key.as_ref());
        let freq = CharFrequency::from_text(decrypted.as_ref());

        let score = freq.score(&base_freq);

        if score > max_score {
            max_score = score;
            max_score_string  =  std::str::from_utf8(decrypted.as_ref()).unwrap_or("").to_owned();
        }

        if (b == 255) {
            break;
        }
        b += 1;
    }

    return  (max_score, max_score_string);
}

#[test]
fn single_byte_xor_cipher() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let (max_score, max_score_string) = to_plain_text(input.as_ref());

    assert_eq!(max_score_string, "Cooking MC's like a pound of bacon")
}

#[test]
fn detect_single_char_xor() {
    let input_file = "/home/dhaya/projects/cryptopals/work/cryptopals/tests/data/4.txt";

    let file = PathBuf::from(input_file);
    let mut f = File::open(file).expect("file cannot be opened");

    let s: String = "ASdasd".to_owned();

    let mut scores = vec![];

    for line in BufReader::new(f).lines() {
        let l = line.expect("error");
        println!("Text is {}", l);
        let score = to_plain_text(l.as_ref());
        scores.push(score);
    }
    scores.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap().reverse());
    assert_eq!(scores[0].1, "Now that the party is jumping\n");
}


#[test]
fn repeating_xor_test() {
    let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";

    let key = "ICE";

    let v = repeating_key_xor(input.as_ref(), key.as_ref());
    let output = hex::encode(v);

    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    assert_eq!(output, expected);
}

fn break_repeating_key() {
    let encrypted = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    let buf  = hex::decode(encrypted).unwrap();
    let keylengths = possible_keylengths(buf.as_ref());
    keylengths.iter().for_each(|x| println!("{}", x));
}


fn from_elem<T: Copy>(elem: T, n: usize) -> Vec<T> {
    let mut out = Vec::new();

    for i in 0..n {
        out.push(elem.clone());
    }
    return out;
}



fn hotels() {
    let n = 5;
    let d = 2;

    let xis: [i32; 5] = [4, 8, 11, 18, 19];
    let mut his: HashSet<i32> = HashSet::new();

    for x in xis.iter() {
        his.insert(x.clone());
    }

    let mut hs: HashSet<i32> = HashSet::new();

    for x in xis.iter() {
        let mut valid_left = true;
        let mut valid_right = true;

        let pleft = x - d;
        let pright = x + d;

        for h in xis.iter() {
            let dist: i32 = pleft - h;

            if dist.abs() < d {
                valid_left = false;
            }
        }

        for h in xis.iter() {
            let dist: i32 = pright - h;

            if dist.abs() < d {
                valid_right = false;
            }
        }


        if valid_left {
            hs.insert(pleft);
        }
        if valid_right {
            hs.insert(pright);
        }
    }


    let diff: Vec<&i32> = hs.difference(&his).collect();

    println!("{}", diff.len());
    for x in &hs {
        println!("{}", x);
    }
}

fn main() {
    //break_repeating_key();
    hotels();
}
