pub extern crate winapi;
pub extern crate widestring;

pub use self::tty::WindowsConOut as Termios;

pub mod attr;
pub mod size;
pub mod tty;
