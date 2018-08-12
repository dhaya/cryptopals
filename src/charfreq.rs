use std::fs::File;
use std::path::PathBuf;
use std::io::Read;
use super::util::*;

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

pub const BASE_DIR: &'static str = env!("CARGO_MANIFEST_DIR");

pub fn base_frequency() -> Result<CharFrequency, ::std::io::Error> {
    let file = PathBuf::from(BASE_DIR.to_owned() + "/res/english.txt");
    let mut f = File::open(file)?;

    let mut contents = String::new();
    f.read_to_string(&mut contents);
    return Ok(CharFrequency::from_text(contents.to_ascii_lowercase().as_ref()));
}

lazy_static! {
    pub(crate) static ref BASE_FREQ: CharFrequency = base_frequency().unwrap();
}
