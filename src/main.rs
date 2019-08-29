#[cfg(windows)]
extern crate winapi;

mod win;

use std::io::Read;
use std::convert::TryInto;
use std::error::Error;
use winapi::shared::minwindef::{DWORD, LPCVOID};
use winapi::um::winbase::{STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use winapi::um::winnt::{HANDLE, PHANDLE};

// #[macro_use] extern crate native_windows_gui as nwg;
//
// use nwg::{Event, Ui, simple_message, fatal_message, dispatch_events};
//
// #[derive(Debug, Clone, Hash)]
// pub enum AppId {
//     MainWindow,
//     NameInput,
//     HelloButton,
//     Label(u8),
//     SayHello,
//     MainFont,
//     TextFont
// }
//
// use AppId::*;
//
// nwg_template!(
//     head: setup_ui<AppId>,
//     controls: [
//         (MainWindow, nwg_window!(title="Example"; size=(280, 105))),
//         (Label(0), nwg_label!(
//             parent=MainWindow;
//             text="Your name: ";
//             position=(5, 15); size=(80, 25);
//             font=Some(TextFont)
//         )),
//         (NameInput, nwg_textinput!(
//             parent=MainWindow;
//             position=(85,13); size=(185,22);
//             font=Some(TextFont)
//         )),
//         (HelloButton, nwg_button!(
//             parent=MainWindow;
//             text="Hello World!";
//             position=(5, 45); size=(270, 50);
//             font=Some(MainFont)
//         ))
//     ];
//     events: [
//         (HelloButton, SayHello, Event::Click, |ui, _, _, _| {
//             let your_name = nwg_get!(ui; (NameInput, nwg::TextInput));
//             simple_message("Hello", &format!("Hello {}!", your_name.get_text()));
//         })
//     ];
//     resources: [
//         (MainFont, nwg_font!(family="Arial"; size=27)),
//         (TextFont, nwg_font!(family="Arial"; size=17))
//     ];
//     values: []
// );

fn get_std_handle(handle_id: winapi::shared::minwindef::DWORD) -> Result<HANDLE, Box<dyn Error>> {
    let handle: HANDLE = unsafe { winapi::um::processenv::GetStdHandle(handle_id) };
    match handle {
        winapi::um::handleapi::INVALID_HANDLE_VALUE => Err("Failed to get handle!".into()),
        _ => Ok(handle),
    }
}

// use std::collections::HashMap;
// fn get_std_io_handles() -> HashMap<winapi::shared::minwindef::DWORD, Result<HANDLE, Box<dyn Error>>>
// {
//     let handle_ids = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
//
//     let mut handles = HashMap::new();
//
//     for id in handle_ids.iter() {
//         match get_std_handle(*id) {
//             Err(e) => {
//                 handles.insert(*id, Err(e));
//             }
//             Ok(handle) => {
//                 handles.insert(*id, Ok(handle));
//             }
//         }
//     }
//
//     handles
// }
//
// fn get_std_io_name(id: winapi::shared::minwindef::DWORD) -> &'static str {
//     match id {
//         STD_INPUT_HANDLE => "STDIN",
//         STD_OUTPUT_HANDLE => "STDOUT",
//         STD_ERROR_HANDLE => "STDERR",
//         _ => "generic handle",
//     }
// }

fn create_pty_pipes() -> Result<[HANDLE; 4], Box<dyn Error>> {
    let mut write: HANDLE = winapi::um::handleapi::INVALID_HANDLE_VALUE;
    let mut pty_write: HANDLE = winapi::um::handleapi::INVALID_HANDLE_VALUE;
    let mut read: HANDLE = winapi::um::handleapi::INVALID_HANDLE_VALUE;
    let mut pty_read: HANDLE = winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
    let mut attr: SECURITY_ATTRIBUTES = Default::default();

    win::api::create_pipe(&mut pty_write, &mut read, &mut attr, 0)?;
    win::api::create_pipe(&mut write, &mut pty_read, &mut attr, 0)?;

    Ok([write, read, pty_write, pty_read])
}

fn get_console_size() -> Result<winapi::um::wincontypes::COORD, Box<dyn Error>> {
    let mut console_size: winapi::um::wincontypes::COORD = Default::default();
    let mut console_sb_inf: winapi::um::wincon::CONSOLE_SCREEN_BUFFER_INFO = Default::default();

    win::api::get_console_screen_buffer_info(get_std_handle(STD_OUTPUT_HANDLE)?, &mut console_sb_inf)?;

    console_size.X = console_sb_inf.srWindow.Right - console_sb_inf.srWindow.Left + 1;
    console_size.Y = console_sb_inf.srWindow.Bottom - console_sb_inf.srWindow.Top + 1;

    Ok(console_size)
}

fn create_pseudoconsole_and_pipes(
    pc: *mut winapi::um::wincontypes::HPCON,
) -> Result<[HANDLE; 2], Box<dyn Error>> {
    let fds = create_pty_pipes()?;
    let console_size = get_console_size()?;

    win::api::create_pseudoconsole(console_size, fds[2], fds[3], 0, pc)?;

    if fds[3] == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        win::api::close_handle(fds[3])?;
    }
    if fds[2] == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        win::api::close_handle(fds[2])?;
    }

    Ok([fds[0], fds[1]])
}

fn startup_info(
    pc: winapi::um::wincontypes::HPCON,
) -> Result<winapi::um::winbase::STARTUPINFOEXW, Box<dyn Error>> {
    let mut si: winapi::um::winbase::STARTUPINFOEXW = Default::default();
    si.StartupInfo.cb = std::mem::size_of::<winapi::um::winbase::STARTUPINFOEXW>()
        .try_into()
        .unwrap();

    let mut bytes: usize = 0;
    win::api::init_proc_thread_attr_list(std::ptr::null_mut(), 1, 0, &mut bytes)?;

    // std::alloc::Layout::<winapi::um::processthreadsapi::STARTUPINFOW>::new()
    let layout = std::alloc::Layout::from_size_align(bytes, 1).unwrap();
    let a_list = unsafe { std::alloc::alloc(layout) };
    si.lpAttributeList = a_list as winapi::um::processthreadsapi::LPPROC_THREAD_ATTRIBUTE_LIST;

    // XXX: 0x00020016 is PROC_THREAD_ATTRIBUTE_PRSUEDOCONSOLE, but that's not defined in winapi_rs
    win::api::update_proc_thread_attr(
        si.lpAttributeList,
        0,
        0x00020016,
        pc,
        std::mem::size_of_val(&pc),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )?;

    unsafe { std::alloc::dealloc(a_list, layout) };

    Ok(si)
}

#[cfg(windows)]
fn main() {
    // let app: Ui<AppId>;
    //
    // match Ui::new() {
    //     Ok(_app) => { app = _app; },
    //     Err(e) => { fatal_message("Fatal Error", &format!("{:?}", e)); }
    // }
    //
    // if let Err(e) = setup_ui(&app) {
    //     fatal_message("Fatal Message", &format!("{:?}", e));
    // }
    //
    // dispatch_events();
    // use winapi::um::winbase::{STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE}; // TODO: error handle
    // let handles = get_std_io_handles();
    //
    // for (k, v) in &handles {
    //     match v {
    //         Err(e) => { panic!("{:?} (handle was {})", e, get_std_io_name(*k)); },
    //         Ok(_) => {}
    //     }
    // }
    use std::io;

    let mut pc: winapi::um::wincontypes::HPCON = winapi::um::handleapi::INVALID_HANDLE_VALUE;
    let fds: [HANDLE; 2] = create_pseudoconsole_and_pipes(&mut pc).unwrap();
    let inp = fds[0];
    let out = fds[1];
    let op = true;
    let pc_ref = std::sync::Arc::new(std::sync::Mutex::new(pc));
    let pc_lock_write = std::sync::Arc::clone(&pc_ref);
    let pc_lock_read = std::sync::Arc::clone(&pc_ref);
    let write_pty = std::thread::spawn(move || {
        let mut written: DWORD = 0;
        while op {{
            let mut pcon = pc_lock_write.lock().unwrap();
            for b in io::stdin().bytes() {
                win::api::write_file((*pcon) as HANDLE, b.unwrap() as LPCVOID, 1, &mut written, std::ptr::null_mut());
            }
        }}
    });

    let read_pty = std::thread::spawn(|| {
        while op {

        }
    });

    let mut si = startup_info(pc).unwrap();
    let mut pi: winapi::um::processthreadsapi::PROCESS_INFORMATION = Default::default();
    win::api::create_process(
        std::ptr::null_mut(),
        win::to_wstring("C:\\windows\\system32\\cmd.exe").as_mut_ptr(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        winapi::shared::minwindef::FALSE,
        winapi::um::winbase::EXTENDED_STARTUPINFO_PRESENT,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut si.StartupInfo,
        &mut pi,
    )
    .unwrap();

    write_pty.join().unwrap();
    read_pty.join().unwrap();
}

#[cfg(not(windows))]
fn main() {}
