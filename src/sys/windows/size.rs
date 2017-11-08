use std::io;

/// Get the size of the terminal.
pub fn terminal_size() -> io::Result<(u16, u16)> {

    // Should this use "get_tty()"? As it is, it mirrors the
    // unix version in useing stdout.

    use ::sys::kernel32::GetConsoleScreenBufferInfo;
    use ::sys::winapi::TRUE;
    use std::mem;
    use ::sys::tty::{get_std_handle, StdStream};

    let stdout_handle = get_std_handle(StdStream::OUT)?;

    unsafe {
        let mut csbi = mem::zeroed();
        if GetConsoleScreenBufferInfo(stdout_handle, &mut csbi) == TRUE {
            Ok(((csbi.srWindow.Right - csbi.srWindow.Left + 1) as u16,
                (csbi.srWindow.Bottom - csbi.srWindow.Top + 1) as u16))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "Unable to get the terminal size."))
        }
    }
}
