use validator_circuits::Commitment;
use std::{fs::{create_dir_all, File}, io::{self, BufReader, Read, Write}, path::PathBuf, time::Instant};
use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() {
    println!("Generating Commitment...");
    let start = Instant::now();
    let commitment = Commitment::from_rnd();
    println!("(finished in {:?})", start.elapsed());
    println!("commitment_root: {:?}", commitment.root());
    println!();

    println!("Generating Commitment Reveal...");
    let start = Instant::now();
    let reveal = commitment.reveal(100);
    println!("(finished in {:?})", start.elapsed());
    println!("commitment_reveal: {:?}", reveal.reveal);
    println!();

    println!("Saving Commitment to File...");
    let bytes = commitment.to_bytes().unwrap();
    save_file(&bytes).unwrap();
    println!("byte_size: {:?}", bytes.len());
    println!();

    println!("Loading Commitment from File...");
    let bytes = read_file().unwrap();
    let commitment = Commitment::from_bytes(&bytes).unwrap();
    println!("(finished in {:?})", start.elapsed());
    println!("commitment_root: {:?}", commitment.root());
}

const COMMITMENT_OUTPUT_FOLDER: &str = "commitment";
const COMMITMENT_OUTPUT_FILE: &str = "secret.bin";

fn save_file(bytes: &Vec<u8>) -> io::Result<()> {
    let mut path = PathBuf::from(COMMITMENT_OUTPUT_FOLDER);
    path.push(COMMITMENT_OUTPUT_FILE);

    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let mut file = File::create(&path)?;
    file.write_all(&bytes)?;
    file.flush()?;

    Ok(())
}

fn read_file() -> io::Result<Vec<u8>> {
    let mut path = PathBuf::from(COMMITMENT_OUTPUT_FOLDER);
    path.push(COMMITMENT_OUTPUT_FILE);

    let file = File::open(&path)?;
    let mut reader = BufReader::with_capacity(32 * 1024, file);
    let mut buffer: Vec<u8> = Vec::new();
    reader.read_to_end(&mut buffer)?;

    Ok(buffer)
}
