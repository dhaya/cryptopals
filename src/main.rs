extern crate hex;
extern crate base64;
#[macro_use]
extern crate lazy_static;
extern crate openssl;

mod util;
mod charfreq;
mod cipher;

mod tests {
    use util::*;
    use std::fs::File;
    use std::path::PathBuf;
    use std::io::BufReader;
    use std::io::prelude::*;

    use hex::{FromHex, FromHexError, ToHex, encode, decode};
    use std::collections::HashSet;
    use std::iter::FromIterator;
    use charfreq::*;
    use cipher::*;
    use base64;


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
        let output = encode(out);
        assert_eq!(output, "746865206b696420646f6e277420706c6179");
    }



    fn hex_decrypt(input: &[u8]) -> DecryptResult<u8> {
        let v1 = Vec::from_hex(input).unwrap();
        let cipher = SingleCharCipher {
            text: v1
        };

        return cipher.decrypt();
    }

    #[test]
    fn single_byte_xor_cipher() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let result = hex_decrypt(input.as_ref());

        assert_eq!(result.decrypted, "Cooking MC's like a pound of bacon")
    }

    #[test]
    fn detect_single_char_xor() {
        let input_file = BASE_DIR.to_owned() + "/tests/data/4.txt";

        let file = PathBuf::from(input_file);
        let mut f = File::open(file).expect("file cannot be opened");

        let mut scores: Vec<DecryptResult<u8>> = vec![];

        for line in BufReader::new(f).lines() {
            let l = line.expect("error");
            println!("Text is {}", l);
            let result = hex_decrypt(l.as_ref());
            scores.push(result);
        }
        scores.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap().reverse());
        assert_eq!(scores[0].decrypted, "Now that the party is jumping\n");
    }


    #[test]
    fn repeating_xor_test() {
        let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";

        let key = "ICE";
        let v = RepeatingKeyCipher::encrypt(input.as_ref(), key.as_ref());

        let output = encode(v.text);

        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(output, expected);
    }

    pub fn break_repeating_key() {
        let encrypted = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let buf  = decode(encrypted).unwrap();

        let cipher = RepeatingKeyCipher::from_encrypted_text(Vec::from(buf));
        let res = cipher.decrypt();

        println!("{}", res.decrypted);
    }

    #[test]
    pub fn break_repeating_key_test() {
        let input_file = BASE_DIR.to_owned() + "/tests/data/6a.txt";

        let path = PathBuf::from(input_file);
        let mut file = File::open(path).unwrap();
        let mut content = String::new();

        file.read_to_string(&mut content);

        let buf = base64::decode(&content).unwrap();
        let cipher = RepeatingKeyCipher::from_encrypted_text(Vec::from(buf));
        let res = cipher.decrypt();

        println!("{}", res.decrypted);
        println!("{}", res.score);
        println!("{}", res.key.len());
        println!("{}", String::from_utf8(res.key.clone()).unwrap());
        assert_eq!("Terminator X: Bring the noise", String::from_utf8(res.key).unwrap());
    }

    #[test]
    pub fn aes_ecb_decrypt() {
        let input_file = BASE_DIR.to_owned() + "/tests/data/7.txt";
        let path = PathBuf::from(input_file);
        let mut f = File::open(path).unwrap();

        let mut content = String::new();
        f.read_to_string(&mut content);

        let buf = base64::decode(&content).unwrap();
        let key = "YELLOW SUBMARINE";
        let res = decrpyt_aes(buf.as_ref(), key);

        assert!(res.contains("Samson"));
    }

    #[test]
    pub fn identify_aes_mode() {
        let input_file = BASE_DIR.to_owned() + "/tests/data/8.txt";
        let path = PathBuf::from(input_file);

        let mut f = File::open(path).unwrap();

        let mut max = 0u32;
        let mut max_line = "".to_owned();

        for line in BufReader::new(f).lines() {
            let l = line.unwrap();
            let cipher = decode( &l).unwrap();
            let blocks = Block::blocks(&cipher);

            let mut same = 0u32;
            for (i, b) in blocks.iter().enumerate() {
                for j in (i+1..blocks.len()) {
                    if blocks[i].distance(&blocks[j]) == 0 {
                        same += 1;
                    }
                }
            }

            if same > max {
                max = same;
                max_line = l;
            }
        }
        println!("{}", max);
        println!("{}", max_line);
        assert_eq!(max_line, "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
    }
}


fn main() {
    self::tests::identify_aes_mode();
}