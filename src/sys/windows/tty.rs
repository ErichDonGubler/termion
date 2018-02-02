// it'll be an api-breaking change to do it later
use std::io;
use std::os::windows::prelude::*;
use std::mem::zeroed;
use std::mem::size_of;
use std::ffi::CStr;
use ::sys::winapi::_core::ptr::null_mut;
use ::sys::winapi::ctypes::c_void;
use ::sys::winapi::shared::minwindef::{FALSE, DWORD};
use ::sys::winapi::shared::ntdef::{NULL};
use ::sys::winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode, GetNumberOfConsoleInputEvents};
use ::sys::winapi::um::fileapi::{OPEN_EXISTING, CreateFileW};
use ::sys::winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use ::sys::winapi::um::consoleapi::{ReadConsoleInputW};
use ::sys::winapi::um::processenv::GetStdHandle;
use ::sys::winapi::um::winbase::{STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, WAIT_FAILED};
use ::sys::winapi::um::minwinbase::{SECURITY_ATTRIBUTES};
use ::sys::winapi::um::winnt::{CHAR, HANDLE, GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ};
use ::sys::winapi::um::wincon::{
    ENABLE_PROCESSED_OUTPUT, ENABLE_WRAP_AT_EOL_OUTPUT, ENABLE_LINE_INPUT,
    ENABLE_PROCESSED_INPUT,  ENABLE_ECHO_INPUT,         ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    INPUT_RECORD,            KEY_EVENT_RECORD,          PeekConsoleInputW
};

extern "system" {
    pub fn WaitForSingleObject(
        hHandle: HANDLE,
        dwMilliseconds: DWORD,
    ) -> DWORD;
}

pub const WAIT_TIMEOUT: DWORD = 258;

#[allow(missing_docs)]
pub struct PreInitState {
    do_cleanup: bool,
    current_out_mode: DWORD,
    current_in_mode: DWORD,
}

#[allow(missing_docs)]
impl Drop for PreInitState {
    fn drop(&mut self) {
        if self.do_cleanup {
            set_console_mode(StdStream::OUT, self.current_out_mode).ok();
            set_console_mode(StdStream::IN, self.current_in_mode).ok();
        }
    }
}

#[allow(missing_docs)]
pub fn init() -> PreInitState {
    do_init().unwrap_or(PreInitState {
        do_cleanup: false,
        current_out_mode: 0,
        current_in_mode: 0,
    })
}

#[allow(missing_docs)]
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
#[allow(missing_docs)]
pub enum StdStream {
    IN,
    OUT,
}

#[allow(missing_docs)]
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

#[allow(missing_docs)]
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

#[allow(missing_docs)]
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

#[allow(missing_docs)]
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
#[allow(missing_docs)]
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
#[allow(unused_variables)]
pub fn get_tty() -> io::Result<String> {
    let mut secat = SECURITY_ATTRIBUTES {
        nLength              : size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor : NULL,
        bInheritHandle       : FALSE,
    };

    // UTF-16 encoded CONIN$ file
    let conin_file: Vec<u16> = "CONIN$\0".encode_utf16().collect();
    let hconin    : HANDLE   = unsafe { CreateFileW(conin_file.as_ptr(),
        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, &mut secat, OPEN_EXISTING, 0, null_mut()
    ) };

    if hconin == INVALID_HANDLE_VALUE {
        return Ok("".to_string());
    };

    let mut dw_out: DWORD = 0;
    if unsafe { GetConsoleMode(hconin, &mut dw_out) } == 0 {
        unsafe { CloseHandle(hconin) };
        return Ok("".to_string());
    } else {
        unsafe { SetConsoleMode(hconin, dw_out & ENABLE_LINE_INPUT) };
    }

    let input_wait: DWORD = unsafe { WaitForSingleObject(hconin, 2000) };
    if input_wait == WAIT_TIMEOUT || input_wait == WAIT_FAILED {
        unsafe { CloseHandle(hconin) };
        return Ok("".to_string());
    }

    let mut events: DWORD = 0;
    if unsafe { GetNumberOfConsoleInputEvents(hconin, &mut events) } == 0 || events == 0 {
        unsafe { CloseHandle(hconin) };
        return Ok("".to_string());
    }

    let mut read_buffer: Vec<INPUT_RECORD> = Vec::with_capacity(1);
    let mut read_total : DWORD             = 0;
    let     read_struct: INPUT_RECORD      = unsafe { zeroed() };
    for i in 0..events {
        read_buffer.push(read_struct);
    }
 
    if unsafe { ReadConsoleInputW(hconin, read_buffer.as_mut_ptr(), events, &mut read_total) } == 0 {
        unsafe { CloseHandle(hconin) };
        return Ok("".to_string());
    }

    let mut out: String = "".to_string();
    for x in &read_buffer {
        if x.EventType == 1 {
            let key_event: &KEY_EVENT_RECORD = unsafe { x.Event.KeyEvent() };
            if key_event.bKeyDown == 1 {
                let c_buf    : CHAR  = unsafe { *key_event.uChar.AsciiChar() };
                let c_str    : &CStr = unsafe { CStr::from_ptr(&c_buf) };
                let str_slice: &str  = c_str.to_str().unwrap();
                out.push_str(str_slice);
            }
        }
    }

    unsafe { CloseHandle(hconin) };
    Ok(String::from(out))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_is_tty() {
        println!("Is TTY? {:?}", is_tty(&::std::io::stdin()));
    }

    #[test]
    fn test_get_tty() {
        println!("Events: {:?}", get_tty());
    }
}
