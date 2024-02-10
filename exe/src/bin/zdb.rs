use std::error::Error;
use zfs::phys;

fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", phys::sector::SHIFT);

    Ok(())
}
