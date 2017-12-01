extern crate termion;

use termion::terminal_size;

fn main() {
    let _init = termion::init();

    println!("Size is {:?}", terminal_size().unwrap())
}
