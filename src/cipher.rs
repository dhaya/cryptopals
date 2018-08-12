use util::*;
use charfreq::*;
use std::cmp;
use openssl::symm::{decrypt, Cipher};
use std::num;

pub struct SingleCharCipher {
    pub text: Vec<u8>
}

pub struct DecryptResult<T> {
    pub decrypted: String,
    pub score: f32,
    pub key: T
}

impl SingleCharCipher {
    pub fn from_encrypted_text(buf: &[u8]) -> Self {
        SingleCharCipher {
            text: Vec::from(buf)
        }
    }

    pub fn encrypt(buf: &[u8], key: u8) -> Self {
        let key_buf = from_elem(key, buf.len());
        let encrypted = xor_bytes(buf, key_buf.as_ref());

        return SingleCharCipher {
            text: encrypted
        }
    }

    pub fn decrypt(&self) -> DecryptResult<u8> {
        let mut b: u8 = 0;
        let mut max_score = 0.0 as f32;
        let mut max_score_string = "".to_owned();
        let mut key_byte: u8 = 0;

        while (b <= 255) {
            let key = from_elem(b, self.text.len());
            let decrypted = xor_bytes(self.text.as_ref(), key.as_ref());
            let freq = CharFrequency::from_text(decrypted.as_ref());

            let score = freq.score(&BASE_FREQ);

            if score > max_score {
                max_score = score;
                max_score_string = ::std::str::from_utf8(decrypted.as_ref()).unwrap_or("").to_owned();
                key_byte = b;
            }

            if (b < 255) {
                b += 1;
            } else {
                break;
            }
        }
        return DecryptResult {
            decrypted: max_score_string,
            score: max_score,
            key: key_byte
        }
    }
}

pub struct RepeatingKeyCipher {
    pub text: Vec<u8>
}


impl RepeatingKeyCipher {
    pub fn from_encrypted_text(encrypted: Vec<u8>) -> Self {
        return RepeatingKeyCipher {
            text: encrypted
        }
    }

    pub fn encrypt(buf: &[u8], key: &[u8]) -> Self {
        let mut output = Vec::new();

        let mut index = 0 as usize;
        let key_len = key.len();
        while index < buf.len() {
            output.push(buf[index] ^ key[index % key_len]);
            index += 1;
        }

        return RepeatingKeyCipher::from_encrypted_text(output);
    }

    pub fn decrypt_with_key(&self, key: &[u8]) -> Vec<u8> {
        return RepeatingKeyCipher::encrypt(self.text.as_ref(), key).text;
    }


    pub fn possible_keylengths(&self, buf: &[u8]) -> Vec<usize> {
        let n = buf.len();
        let max = cmp::min(40, n/4);

        let mut scores: Vec<(f32, usize)> = vec![];

        for keysize in 2..max {
            let mut hd: Vec<u32> = vec![];
            for i in 0..4 {
                for j in i+1..4 {
                    let first = i * keysize;
                    let second = j * keysize;

                    let dist = hamming_distance(&buf[first..first+keysize], &buf[second..second+keysize]);
                    hd.push(dist);
                }
            }
            let sum: u32 = hd.iter().sum();
            let score: f32 = sum as f32 / (hd.len() as f32);
            scores.push((score/(keysize as f32), keysize));
        }
        scores.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        for (i, (score, ks)) in scores.iter().enumerate() {
            println!("{}, {}, {}", i, score, ks);
        }
        return scores.iter().map(|x| x.1).collect();
    }


    fn transpose(&self, buf: &[u8], slice_len: usize) -> Vec<SingleCharCipher> {
        fn collect_bytes(buf: &[u8], step: usize) -> SingleCharCipher {
            let mut result: Vec<u8> = Vec::new();

            let len = buf.len();

            let s = (len / step) + 1;

            for i in 0..s {
                let index = i * step;
                if (index <= len - 1) {
                    result.push(buf[index]);
                }
            }

            return SingleCharCipher {
                text: result
            }
        }

        let mut result: Vec<SingleCharCipher> = Vec::new();

        for i in 0..slice_len {
            result.push(collect_bytes(&buf[i..], slice_len));
        }
        return result;
    }

    fn break_cipher(&self, len: usize) -> DecryptResult<Vec<u8>> {
        let cipher = &self.text;
        let slices = self.transpose(cipher, len);

        let mut keys: Vec<u8> = vec![];
        let mut score: f32 = 0f32;

        for slice in slices {
            let dr = slice.decrypt();
            keys.push(dr.key);
            score += dr.score;
        }
        return DecryptResult {
            decrypted: "".to_owned(),
            score: score,
            key: keys
        };
    }

    pub fn decrypt(&self) -> DecryptResult<Vec<u8>> {
        let cipher = &self.text;

        let keylengths = self.possible_keylengths(cipher);
        let mut best_score: f32 = 0f32;
        let mut best_res: Option<DecryptResult<Vec<u8>>> = None;

        for len in keylengths.iter().take(3) {
            println!("Trying key len {}", len);

            let decrypt_res = self.break_cipher(*len);
            if (decrypt_res.score > best_score) {
                best_score = decrypt_res.score;
                best_res = Some(decrypt_res);
            }
        }
        let result = best_res.unwrap();

        let decrypted = self.decrypt_with_key(result.key.as_ref());
        return DecryptResult {
            decrypted: String::from_utf8(decrypted).unwrap(),
            key: result.key,
            score: result.score
        }
    }
}

pub fn decrpyt_aes(text: &[u8], key: &str) -> String {
    let cipher = Cipher::aes_128_ecb();

    let res = decrypt(cipher, key.as_ref(), None, text);
    return String::from_utf8(res.unwrap()).unwrap();
}

pub struct Block<'a>(&'a [u8]);

impl<'a> Block<'a> {
    pub fn from_buf(buf: &'a [u8]) -> Self {
        return Block(buf);
    }

    pub fn distance(&self, other: &Block) -> u32 {
        return hamming_distance(self.0, other.0);
    }

    pub fn blocks(buf: &[u8]) -> Vec<Block> {
        assert!((buf.len() % 16) == 0);
        let size = 16usize;
        let num_blocks = buf.len() as usize / size;

        let mut res: Vec<Block> = Vec::new();

        for b in 0..num_blocks {
            let block = Block::from_buf(&buf[b*size..(b+1)*size]);
            res.push(block);
        }

        return res;
    }
}



