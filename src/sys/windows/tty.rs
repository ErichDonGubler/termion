// it'll be an api-breaking change to do it later
use std::io;
use std::os::windows::prelude::*;
use ::sys::winapi::ctypes::c_void;
use ::sys::winapi::_core::ptr::null_mut;
use ::sys::winapi::shared::minwindef::{BOOL, FALSE, DWORD, LPVOID};
use ::sys::winapi::um::consoleapi::{ReadConsoleW, GetConsoleMode, SetConsoleMode};
use ::sys::winapi::um::fileapi::{OPEN_EXISTING, CreateFileW};
use ::sys::winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use ::sys::winapi::um::processenv::GetStdHandle;
use ::sys::winapi::um::winbase::{STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use ::sys::winapi::um::winnt::{LPWSTR, HANDLE, GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE};
use ::sys::winapi::um::wincon::{
    ENABLE_PROCESSED_OUTPUT,       ENABLE_WRAP_AT_EOL_OUTPUT, ENABLE_LINE_INPUT,
    ENABLE_PROCESSED_INPUT,        ENABLE_ECHO_INPUT,         ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    ENABLE_VIRTUAL_TERMINAL_INPUT, PeekConsoleInputW
};

/// Enum std stream type
///
/// This can be passed around to easily evaluate which type of stream (or stream data)
/// should be returned by a callee.
#[derive(Copy, Clone, PartialEq)]
pub enum StdStream {
    IN,
    OUT,
}

/// No longer needed
///
/// Sources using this need to be replaced with WindowsConIn/WindowsConOut implenentations
pub struct PreInitState {
    do_cleanup: bool,
    current_out_mode: DWORD,
    current_in_mode: DWORD,
}

/// No longer needed
///
/// Sources using this need to be replaced with WindowsConIn/WindowsConOut implenentations
impl Drop for PreInitState {
    fn drop(&mut self) {
        if self.do_cleanup {
            set_console_mode(StdStream::OUT, self.current_out_mode).ok();
            set_console_mode(StdStream::IN, self.current_in_mode).ok();
        }
    }
}

/// No longer needed
///
/// Sources using this need to be replaced with WindowsConIn/WindowsConOut implenentations
pub fn init() -> PreInitState {
    do_init().unwrap_or(PreInitState {
        do_cleanup: false,
        current_out_mode: 0,
        current_in_mode: 0,
    })
}

/// No longer needed
///
/// Sources using this need to be replaced with WindowsConIn/WindowsConOut implenentations
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

    Ok(PreInitState {
        do_cleanup: true,
        current_out_mode,
        current_in_mode,
    })
}

/// No longer needed
///
/// Sources using this need to be replaced with WindowsConIn/WindowsConOut implenentations
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

/// No longer needed
///
/// Sources using this need to be replaced with WindowsConIn/WindowsConOut implenentations
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

/// No longer needed
///
/// Sources using this need to be replaced with WindowsConIn/WindowsConOut implenentations
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

/// Checks to see if a stream handle is a valid reference to a windows console
///
/// This calls the win32 api function PeekConsoleInputW to check if there are
/// events to be proessed. If this function returns FALSE, then the stream
/// is not valid. If the stream is a valid handle to the windows console, 
/// this function will return TRUE and all events will be preserved so they 
/// can be parsed later.
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

/// Contains handle and mode information for STDOUT
///
/// This struct implements the copy trait, so that it works correctly
/// with the raw functionality. In raw.rs, a backup (copy) is created before
/// the console modes (attributes) are changed. As such, the drop trait
/// is not implemented for this structure and therefore CloseHandle must
/// be called manually.
#[derive(Copy, Clone, Debug)]
pub struct WindowsConOut {
    pub handle: HANDLE,
    pub mode: DWORD,
}

/// Contains handle, buffer and mode information for STDIN
///
/// When this structure is initialized with new(), a handle to the console,
/// will be obtained automatically. Unlike WindowsConStruct, the handle
/// will also be automatically closed (by calling CloseHandle) when it is dropped.
#[derive(Debug)]
struct WindowsConIn {
    handle: HANDLE,
    buffered_utf8 : Vec<u8>,
    buffered_utf16: Vec<u16>,
    prev_mode: DWORD,
}

/// Returns a STDIN or STDOUT HANDLE to the Windows console
///
/// This function uses the special Windows variables CONIN$ and CONOUT$
/// to get it's console handles. When these variables are used with CreateFile,
/// a handle to the actual console device will be returned regardless of redirections.
pub fn get_tty_handle(tty: StdStream) -> io::Result<HANDLE> {
    let console_file: Vec<u16>;
    let console_share: DWORD;

    if tty == StdStream::IN {
        console_file = "CONIN$\0".encode_utf16().collect(); // UTF-16 encoded CONIN$ file
        console_share = FILE_SHARE_READ;
    } else {
        console_file = "CONOUT$\0".encode_utf16().collect(); // UTF-16 encoded CONOUT$ file
        console_share = FILE_SHARE_WRITE;
    }

    let console_handle: HANDLE = unsafe { 
        CreateFileW(console_file.as_ptr(), 
            GENERIC_READ | GENERIC_WRITE, console_share, null_mut(), OPEN_EXISTING, 0, null_mut()
        ) 
    };

    if console_handle == INVALID_HANDLE_VALUE {
        Err(::std::io::Error::last_os_error())
    } else {
        Ok(console_handle)
    }
}

/// Implementation for WindowsConOut
impl WindowsConOut {
    /// Creates a new WindowsConOut structure
    ///
    /// Populates the new structure with a valid Windows Console handle and
    /// the original mode (set by Windows)
    pub fn new() -> io::Result<WindowsConOut> {
        let console_handle = get_tty_handle(StdStream::OUT)?;

        let mut dw_out: DWORD = 0;
        if unsafe { GetConsoleMode(console_handle, &mut dw_out) } == FALSE {
            return Err(::std::io::Error::last_os_error());
        }

        Ok(WindowsConOut {
            handle: console_handle,
            mode: dw_out
        })
    }
}

/// Implementation for WindowsConIn
impl WindowsConIn {
    /// How many bytes should be read per iteration?
    const MAX_BYTES_TO_READ: usize = 1024;

    /// Created a new WindowsConIn structure
    ///
    /// The new structure will contain a valid Windows console handle,
    /// initialized buffers for reading input and the original console mode
    /// (set by windows)
    fn new() -> io::Result<WindowsConIn> {
        let console_handle = get_tty_handle(StdStream::IN)?;

        let mut mode: DWORD = 0;
        if unsafe { GetConsoleMode(console_handle, &mut mode) } == FALSE {
            return Err(io::Error::last_os_error())
        }

        Ok(WindowsConIn {
            handle: console_handle,
            buffered_utf16: Vec::with_capacity(WindowsConIn::MAX_BYTES_TO_READ),
            buffered_utf8: Vec::with_capacity(WindowsConIn::MAX_BYTES_TO_READ),
            prev_mode: mode,
        })
    }

    /// Changes the Console's input mode
    ///
    /// The attributes (mode) set by this method ensures that input can be captured
    /// by the process and not the system. This will also disable Ctrl+C, so that
    /// the process can determine how to quit on it's own.
    fn set_mode(self) -> io::Result<Self> {
        // https://docs.microsoft.com/en-us/windows/console/setconsolemode
        let new_in_mode = self.prev_mode & ENABLE_ECHO_INPUT & ENABLE_LINE_INPUT;
        let new_in_mode = new_in_mode | ENABLE_PROCESSED_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT;

        if unsafe { SetConsoleMode(self.handle, new_in_mode) } == FALSE {
            Err(io::Error::last_os_error())
        } else {
            Ok(self)
        }
    }

    /// Read input from STDIN
    ///
    /// TODO: Verbose description
    fn buffer_into_utf8(&mut self) -> io::Result<()> {
        let hconin = &self.handle;

        self.buffered_utf16.clear();
        self.buffered_utf8.clear();

        let mut utf_16_chars_read: DWORD = 0;
        let succeeded: BOOL  = unsafe {
            ReadConsoleW(
                *hconin,
                (self.buffered_utf16.as_mut_ptr() as LPWSTR) as LPVOID,
                WindowsConIn::MAX_BYTES_TO_READ as DWORD,
                &mut utf_16_chars_read, null_mut()
            )
        };

        if succeeded == FALSE {
            return Err(::std::io::Error::last_os_error())?;
        }

        unsafe { self.buffered_utf16.set_len(utf_16_chars_read as usize); }
        let utf8_from_console = String::from_utf16_lossy(&self.buffered_utf16);

        // XXX: Could probably optimize better with WideStringToMultiByte
        self.buffered_utf8.extend_from_slice(&utf8_from_console.into_bytes()[..]);

        Ok(())
    }
}

impl ::std::io::Read for WindowsConIn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.buffer_into_utf8()?;
        use std::io::Write;
        let mut buf = buf;
        Ok(buf.write(&self.buffered_utf8)?)
    }
}

impl Drop for WindowsConIn {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe { 
                SetConsoleMode(self.handle, self.prev_mode);
                CloseHandle(self.handle);
            }
        }
    }
}

/// Get the TTY device.
///
/// This allows for getting stdio representing _only_ the TTY, and not other streams.
pub fn get_tty() -> io::Result<Box<io::Read>> {
    Ok(Box::new(WindowsConIn::new()?.set_mode()?))
}
