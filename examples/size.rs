extern crate termion;

use termion::terminal_size;

fn main() {
    termion::init();

    println!("Size is {:?}", terminal_size().unwrap())
}
