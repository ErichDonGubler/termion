use std::io;
use ::sys::winapi::shared::minwindef::{DWORD};
use ::sys::winapi::um::consoleapi::{SetConsoleMode};
use ::sys::winapi::um::wincon::{
    ENABLE_PROCESSED_OUTPUT, ENABLE_WRAP_AT_EOL_OUTPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING
};

use super::Termios;

pub fn get_terminal_attr() -> io::Result<Termios> {
    let console_out = Termios::new()?;
    Ok(console_out)
}

pub fn set_terminal_attr(termios: &Termios) -> io::Result<(DWORD)> {
    if unsafe { SetConsoleMode(termios.handle, termios.mode) } == 0 {
        Err(::std::io::Error::last_os_error())
    } else {
        Ok(termios.mode)
    }
}

pub fn raw_terminal_attr(termios: &mut Termios) {
    termios.mode = termios.mode | ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
}
