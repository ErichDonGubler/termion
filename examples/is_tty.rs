extern crate termion;

use std::fs;

fn main() {
    let _init = termion::init();

    if termion::is_tty(&fs::File::create("/dev/stdout").unwrap()) {
        println!("This is a TTY!");
    } else {
        println!("This is not a TTY :(");
    }
}
