extern crate checksec;
extern crate goblin;
extern crate memmap2;

use checksec::pe::Properties;
use goblin::pe::PE;
use memmap2::Mmap;
use std::{env, fs};

fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() == 2
        && let Ok(fp) = fs::File::open(&argv[1])
        && let Ok(buf) = unsafe { Mmap::map(&fp) }
        && let Ok(pe) = PE::parse(&buf)
    {
        println!("aslr: {}", pe.has_aslr());
        println!("gs: {}", pe.has_gs(&buf));
    }
}
