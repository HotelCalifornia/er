#[cfg(windows)]
extern crate winapi;

use std::error::Error;
use winapi::shared::basetsd::{DWORD_PTR, PSIZE_T, SIZE_T};
use winapi::shared::minwindef::{BOOL, DWORD, LPCVOID, LPDWORD, LPVOID};
use winapi::um::consoleapi::CreatePseudoConsole;
use winapi::um::fileapi::WriteFile;
use winapi::um::handleapi::CloseHandle;
use winapi::um::minwinbase::{LPSECURITY_ATTRIBUTES, LPOVERLAPPED};
use winapi::um::namedpipeapi::CreatePipe;
use winapi::um::processthreadsapi::{
    CreateProcessW, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
    LPPROCESS_INFORMATION, LPPROC_THREAD_ATTRIBUTE_LIST, LPSTARTUPINFOW,
};
use winapi::um::wincon::{GetConsoleScreenBufferInfo, PCONSOLE_SCREEN_BUFFER_INFO};
use winapi::um::wincontypes::{COORD, HPCON};
use winapi::um::winnt::{HANDLE, LPCWSTR, LPWSTR, PHANDLE, PVOID};

type RET = Result<(), Box<dyn Error>>;

#[cfg(windows)]
pub fn create_pipe(read: PHANDLE, write: PHANDLE, attr: LPSECURITY_ATTRIBUTES, size: DWORD) -> RET {
    match unsafe { CreatePipe(read, write, attr, size) } {
        0 => Err("Failed to create pipe!".into()),
        _ => Ok(()),
    }
}

#[cfg(windows)]
pub fn get_console_screen_buffer_info(
    console_output: HANDLE,
    console_sb_inf: PCONSOLE_SCREEN_BUFFER_INFO,
) -> RET {
    match unsafe { GetConsoleScreenBufferInfo(console_output, console_sb_inf) } {
        0 => Err("Failed to get console screen buffer info!".into()),
        _ => Ok(()),
    }
}

#[cfg(windows)]
pub fn create_pseudoconsole(
    size: COORD,
    input: HANDLE,
    output: HANDLE,
    flags: DWORD,
    pc: *mut HPCON,
) -> RET {
    match unsafe { CreatePseudoConsole(size, input, output, flags, pc) } {
        winapi::shared::winerror::S_OK => Ok(()),
        _ => Err("Failed to create pseudoconsole!".into()),
    }
}

#[cfg(windows)]
pub fn close_handle(handle: HANDLE) -> RET {
    match unsafe { CloseHandle(handle) } {
        0 => Err(format!("Failed to close handle {:?}", handle).into()),
        _ => Ok(()),
    }
}

#[cfg(windows)]
pub fn init_proc_thread_attr_list(
    attr_list: LPPROC_THREAD_ATTRIBUTE_LIST,
    attr_count: DWORD,
    flags: DWORD,
    size: PSIZE_T,
) -> RET {
    match unsafe { InitializeProcThreadAttributeList(attr_list, attr_count, flags, size) } {
        0 => Err("Failed to initialize process thread attribute list!".into()),
        _ => Ok(()),
    }
}

#[cfg(windows)]
pub fn update_proc_thread_attr(
    attr_list: LPPROC_THREAD_ATTRIBUTE_LIST,
    flags: DWORD,
    attr: DWORD_PTR,
    val: PVOID,
    size: SIZE_T,
    prev: PVOID,
    ret_size: PSIZE_T,
) -> RET {
    match unsafe { UpdateProcThreadAttribute(attr_list, flags, attr, val, size, prev, ret_size) } {
        0 => Err("Failed to update process thread attribute!".into()),
        _ => Ok(()),
    }
}

#[cfg(windows)]
pub fn create_process(
    app_name: LPCWSTR,
    cmd_line: LPWSTR,
    proc_attr: LPSECURITY_ATTRIBUTES,
    thread_attr: LPSECURITY_ATTRIBUTES,
    inherit_handles: BOOL,
    flags: DWORD,
    env: LPVOID,
    curr_dir: LPCWSTR,
    startup_info: LPSTARTUPINFOW,
    proc_info: LPPROCESS_INFORMATION,
) -> RET {
    match unsafe {
        CreateProcessW(
            app_name,
            cmd_line,
            proc_attr,
            thread_attr,
            inherit_handles,
            flags,
            env,
            curr_dir,
            startup_info,
            proc_info,
        )
    } {
        0 => Err("Failed to create process!".into()),
        _ => Ok(()),
    }
}

#[cfg(windows)]
pub fn write_file(
    file: HANDLE,
    buffer: LPCVOID,
    to_write: DWORD,
    written: LPDWORD,
    overlapped: LPOVERLAPPED
) -> RET {
    match unsafe {
        WriteFile(file, buffer, to_write, written, overlapped)
    } {
        0 => Err("Failed to write to file!".into()),
        _ => Ok(()),
    }
}
