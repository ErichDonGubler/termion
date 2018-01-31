// it'll be an api-breaking change to do it later
use std::io;
use std::os::windows::prelude::*;
use ::sys::widestring::WideString;
use ::sys::winapi::_core::ptr::null_mut;
use ::sys::winapi::ctypes::c_void;
use ::sys::winapi::shared::minwindef::{FALSE, DWORD, LPVOID, HLOCAL};
use ::sys::winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode, GetNumberOfConsoleInputEvents};
use ::sys::winapi::um::fileapi::{OPEN_EXISTING, ReadFile, CreateFileW};
use ::sys::winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use ::sys::winapi::um::processenv::GetStdHandle;
use ::sys::winapi::um::winbase::{STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, LocalFree};
use ::sys::winapi::um::winnt::{LPWSTR, HANDLE, GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ};
use ::sys::winapi::um::wincon::{
    ENABLE_PROCESSED_OUTPUT, ENABLE_WRAP_AT_EOL_OUTPUT, ENABLE_LINE_INPUT,
    ENABLE_PROCESSED_INPUT,  ENABLE_ECHO_INPUT,         ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    PeekConsoleInputW
};

pub struct PreInitState {
    do_cleanup: bool,
    current_out_mode: DWORD,
    current_in_mode: DWORD,
}

impl Drop for PreInitState {
    fn drop(&mut self) {
        if self.do_cleanup {
            set_console_mode(StdStream::OUT, self.current_out_mode).ok();
            set_console_mode(StdStream::IN, self.current_in_mode).ok();
        }
    }
}

pub fn init() -> PreInitState {
    do_init().unwrap_or(PreInitState {
        do_cleanup: false,
        current_out_mode: 0,
        current_in_mode: 0,
    })
}

fn do_init() -> Result<PreInitState, io::Error> {
    // there are many other console hosts on windows that might actually do something
    // rational with the output escape codes, so if the setup fails, carry on rather
    // than reporting an error. The assumption is that the cleanup in the drop trait
    // will always be able to set the flags that are currently set.
    let current_out_mode = get_console_mode(StdStream::OUT)?;
    let current_in_mode = get_console_mode(StdStream::IN)?;

    let new_out_mode = current_out_mode | ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT |
                       ENABLE_VIRTUAL_TERMINAL_PROCESSING;

    // ignore failure here and hope we are in a capable third party console
    set_console_mode(StdStream::OUT, new_out_mode).ok();

    // TODO: it seems like ENABLE_VIRTUAL_TERMINAL_INPUT causes ^C to be passed
    // through in the input stream, overiding ENABLE_PROCESSED_INPUT.
    // ENABLE_VIRTUAL_TERMINAL_INPUT is only used for mouse event handling at this
    // point. I'm not sure what the desired behaviour is but if that is not the same
    // maybe it would be simpler
    // to start a thread and wait for the mouse events using the windows console
    // api and post them back in a similar fashion to the async reader.

    let new_in_mode = current_in_mode | ENABLE_PROCESSED_INPUT;
    let new_in_mode = new_in_mode & !ENABLE_ECHO_INPUT;

    // ignore failure here and hope we are in a capable third party console
    set_console_mode(StdStream::IN, new_in_mode).ok();

    println!("cim {:x}, com {:x}", current_in_mode, current_out_mode);

    Ok(PreInitState {
        do_cleanup: true,
        current_out_mode,
        current_in_mode,
    })
}

#[derive(Copy, Clone)]
pub enum StdStream {
    IN,
    OUT,
}

pub fn get_std_handle(strm: StdStream) -> io::Result<HANDLE> {
    let which_handle = match strm {
        StdStream::IN => STD_INPUT_HANDLE,
        StdStream::OUT => STD_OUTPUT_HANDLE,
    };

    unsafe {
        match GetStdHandle(which_handle) {
            x if x != INVALID_HANDLE_VALUE => Ok(x),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

pub fn set_console_mode(strm: StdStream, new_mode: DWORD) -> io::Result<DWORD> {
    let prev = get_console_mode(strm)?;
    unsafe {
        let handle = get_std_handle(strm)?;
        if SetConsoleMode(handle, new_mode) == FALSE {
            Err(io::Error::last_os_error())
        } else {
            Ok(prev)
        }
    }
}

pub fn get_console_mode(strm: StdStream) -> io::Result<DWORD> {
    unsafe {
        let handle = get_std_handle(strm)?;
        let mut mode: DWORD = 0;
        if GetConsoleMode(handle, &mut mode) == FALSE {
            Err(io::Error::last_os_error())
        } else {
            Ok(mode)
        }
    }
}

pub fn set_raw_input_mode(enable: bool) -> bool {
    get_console_mode(StdStream::IN)
        .map(|current_mode| {
                 let new_mode = if enable {
                     current_mode & !ENABLE_LINE_INPUT
                 } else {
                     current_mode | ENABLE_LINE_INPUT
                 };
                 set_console_mode(StdStream::IN, new_mode)
             })
        .is_ok()
}

// TODO: provide an implementation of this, perhaps just delegating to the atty crate?
pub fn is_tty<T: AsRawHandle>(stream: &T) -> bool {
    let stream = stream.as_raw_handle() as *mut c_void;

    if stream == INVALID_HANDLE_VALUE {
        return false;
    };

    let mut read: DWORD = 0;
    if unsafe { PeekConsoleInputW(stream as *mut c_void, null_mut(), 0, &mut read) == 0 } {
        return false;
    };

    return true;
}

/// Get the TTY device.
///
/// This allows for getting stdio representing _only_ the TTY, and not other streams.
#[cfg(target_os = "windows")]
pub fn get_tty() -> io::Result<String> {
    let widestr: WideString;

    // UTF-16 encoded CONIN$ file
    let conin_file: Vec<u16> = "CONIN$\0".encode_utf16().collect();
    let hconin    : HANDLE   = unsafe { CreateFileW(conin_file.as_ptr(),
        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, null_mut(), OPEN_EXISTING, 0, null_mut()
    ) };

    if hconin == INVALID_HANDLE_VALUE {
        return Ok("".to_string());
    };

    let mut events: DWORD = 0;
    if unsafe { GetNumberOfConsoleInputEvents(hconin, &mut events) } == 0 {
        unsafe {
            CloseHandle(hconin);
        }
        return Ok("".to_string());
    }

    let mut dw_out: DWORD = 0;
    if unsafe { GetConsoleMode(hconin, &mut dw_out) } == 0 {
        return Ok("".to_string());
    }

    unsafe {
        SetConsoleMode(hconin, dw_out & ENABLE_LINE_INPUT);
    }

    let mut file_buffer: LPWSTR = null_mut();
    let mut file_read  : DWORD  = 0;

    unsafe {
        ReadFile(hconin, (&mut file_buffer as *mut LPWSTR) as LPVOID, events, &mut file_read, null_mut());

        widestr = WideString::from_ptr(file_buffer, file_read as usize);
        LocalFree(file_buffer as HLOCAL);
    }

    Ok(widestr.to_string_lossy())
}
