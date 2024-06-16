use clap::{arg, command, Parser};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = String::from("null"))]
    name: String,

    #[arg(short, long, default_value_t = 1)]
    count: u8,

    number: i64,
}


fn main() {
    let args = Args::parse();

    // Use the library function to convert the number
    let hex_string = int_to_hex(args.number);

    // Print the result
    println!("{}", hex_string);
}

pub fn int_to_hex(num: i64) -> String {
    format!("0x{:X}", num)
}
