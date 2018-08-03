use std::cmp;

use util;

pub fn possible_keylengths<>(buf: &[u8]) -> Vec<usize> {
    let n = buf.len();
    let max = cmp::min(40, n/4);

    let mut scores: Vec<(f32, usize)> = vec![];

    for keysize in 2..max {
        let mut hd: Vec<u32> = vec![];
        for i in 0..4 {
            for j in i+1..4 {
                let first = i * keysize;
                let second = j * keysize;

                let dist = util::hamming_distance(&buf[first..first+keysize], &buf[second..second+keysize]);
                hd.push(dist);
            }
        }
        let sum: u32 = hd.iter().sum();
        let score: f32 = sum as f32 / (hd.len() as f32);
        scores.push((score/keysize as f32, keysize));
    }
    scores.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap().reverse());
    return scores.iter().map(|x| x.1).collect();
}

fn decrypt(encrypted: String) -> String {
    let buf = encrypted.as_ref();
    let key_lengths = possible_keylengths(buf);
    unimplemented!();
}