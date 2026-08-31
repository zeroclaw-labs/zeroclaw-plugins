//! Print the Metaplex metadata PDA for a mint. Used by demo.sh to pre-fetch the
//! metadata account for the file-backed (network-free) demo path.
//! Usage: print_pda <mint>
fn main() {
    let mint = std::env::args().nth(1).expect("usage: print_pda <mint>");
    match solana_token_risk::metadata::metadata_pda(&mint) {
        Some(pda) => println!("{pda}"),
        None => std::process::exit(1),
    }
}
