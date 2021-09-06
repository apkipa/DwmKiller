use bindings::{
    Windows::Data::Xml::Dom::XmlDocument,
    Windows::Foundation::TypedEventHandler,
    Windows::Win32::Foundation::{CloseHandle, HANDLE, HINSTANCE, MAX_PATH, PWSTR},
    Windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_ADJUST_PRIVILEGES,
        LookupPrivilegeValueW, AdjustTokenPrivileges, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES,
        SE_PRIVILEGE_ENABLED,
    },
    Windows::Win32::Storage::StructuredStorage::{
        PROPVARIANT_0_0_0_abi, PROPVARIANT_0_0_abi, PROPVARIANT, PROPVARIANT_0,
    },
    Windows::Win32::System::Com::{CoCreateInstance, IPersistFile, CLSCTX_INPROC_SERVER},
    Windows::Win32::System::Diagnostics::Debug::{GetLastError, FACILITY_WIN32, WIN32_ERROR},
    Windows::Win32::System::Diagnostics::ToolHelp::{
        PROCESSENTRY32W, CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
    },
    Windows::Win32::System::LibraryLoader::GetModuleFileNameW,
    Windows::Win32::System::OleAutomation::VT_LPWSTR,
    Windows::Win32::System::PropertiesSystem::{IPropertyStore, PROPERTYKEY},
    Windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken, OpenProcess, TerminateProcess,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    },
    Windows::Win32::System::SystemServices::LUID,
    Windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
    Windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED},
    Windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID,
    Windows::Win32::UI::Shell::{IShellLinkW, ShellLink},
    Windows::UI::Notifications::{
        ToastNotification, ToastNotificationManager, NotificationData,
    },
};

use std::os::windows::prelude::*;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;
use std::{alloc, mem, slice, ptr};
use std::{
    ffi::{OsStr, OsString},
    mem::MaybeUninit,
    sync::{Arc, Mutex},
};
use std::ptr::addr_of_mut;
use windows::{Guid, Interface, HRESULT};

macro_rules! enclose {
    ( ($( $x:ident ),*) $y:expr ) => {
        {
            $(let $x = $x.clone();)*
            $y
        }
    };
}

const PKEY_AppUserModel_ID: PROPERTYKEY = PROPERTYKEY {
    fmtid: Guid::from_values(
        0x9F4C2855,
        0x9F79,
        0x4B39,
        [0xA8, 0xD0, 0xE1, 0xD4, 0x2D, 0xE1, 0xD5, 0xF3],
    ),
    pid: 5,
};

const fn hresult_from_win32_error(e: WIN32_ERROR) -> HRESULT {
    let e = e.0;
    let e = if e as i32 <= 0 {
        e
    } else {
        (e & 0x0000FFFF) | (FACILITY_WIN32.0 << 16) | 0x80000000
    };
    HRESULT(e)
}

fn hresult_from_last_error() -> HRESULT {
    hresult_from_win32_error(unsafe { GetLastError() })
}

fn osstr_to_vec_u16_with_zero(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

fn osstr_from_slice_with_zero(s: &[u16]) -> OsString {
    let len = s.iter().position(|i| *i == 0).unwrap_or(s.len());
    OsString::from_wide(&s[..len])
}

unsafe fn osstr_from_ptr(ptr: *const u16, maxlen: usize) -> OsString {
    let len = (0..maxlen).position(|i| *ptr.add(i) == 0).unwrap_or(maxlen);
    OsString::from_wide(slice::from_raw_parts(ptr, len))
}

// Panic: The function will panic when allocation fails or size_fn returns 0
fn call_system_api_with_osstr<FS, FB, E>(size_hint_fn: FS, body_fn: FB) -> Result<OsString, E>
where
    FS: FnOnce() -> usize, // usize: Buffer size (including '\0')
    FB: FnOnce(*mut u16, usize) -> Result<usize, E>, // usize: Acutal size (not including '\0')
{
    unsafe {
        let buf_len = size_hint_fn();
        assert!(buf_len > 0);
        let mem_size = mem::size_of::<u16>().checked_mul(buf_len).unwrap();
        let mem_layout = alloc::Layout::from_size_align(mem_size, mem::align_of::<u16>()).unwrap();
        let str_buf = alloc::alloc(mem_layout) as *mut u16;
        if str_buf.is_null() {
            let noun_postfix = if mem_size == 1 { "" } else { "s" };
            panic!(
                "Memory allocation of {} byte{} failed",
                mem_size, noun_postfix
            );
        }
        // Assuming body_fn fills in a 0-terminated string
        let ret_val = body_fn(str_buf, buf_len).map(|actual_len| {
            let slice = slice::from_raw_parts(str_buf, actual_len);
            OsString::from_wide(slice)
        });
        alloc::dealloc(str_buf as _, mem_layout);
        ret_val
    }
}

fn create_shortcut(path: &str) -> windows::Result<()> {
    unsafe {
        let exe_path = call_system_api_with_osstr(
            || MAX_PATH as _,
            |ptr, size| -> windows::Result<usize> {
                match GetModuleFileNameW(HINSTANCE::NULL, PWSTR(ptr), size as _) {
                    0 => Err(hresult_from_last_error().into()),
                    len => Ok(len as _),
                }
            },
        )?;
        dbg!(&exe_path);

        let shell_link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
        shell_link.SetPath(PWSTR(osstr_to_vec_u16_with_zero(&exe_path).as_mut_ptr()))?;
        shell_link.SetArguments("")?;
        let property_store: IPropertyStore = shell_link.cast()?;
        // !!! Workaround for InitPropVariantFromString
        let mut property_var_str: Vec<u16> = APP_AUMID.encode_utf16().collect();
        let property_var = PROPVARIANT {
            Anonymous: PROPVARIANT_0 {
                Anonymous: PROPVARIANT_0_0_abi {
                    vt: VT_LPWSTR.0 as u16,
                    wReserved1: 0,
                    wReserved2: 0,
                    wReserved3: 0,
                    Anonymous: PROPVARIANT_0_0_0_abi {
                        pwszVal: PWSTR(property_var_str.as_mut_ptr()),
                    },
                },
            },
        };
        // !!! Workaround end
        property_store.SetValue(&PKEY_AppUserModel_ID, &property_var)?;
        property_store.Commit()?;
        let persist_file: IPersistFile = shell_link.cast()?;
        persist_file.Save(path, true)?;

        Ok(())
    }
}

fn is_elevated() -> bool {
    unsafe {
        let mut handle = MaybeUninit::<HANDLE>::uninit();

        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, handle.as_mut_ptr()) == false {
            return false;
        }

        let handle = handle.assume_init();
        let mut elevation = MaybeUninit::<TOKEN_ELEVATION>::uninit();
        let mut ret_size = MaybeUninit::uninit();
        if GetTokenInformation(
            handle,
            TokenElevation,
            elevation.as_mut_ptr() as _,
            std::mem::size_of::<TOKEN_ELEVATION>() as _,
            ret_size.as_mut_ptr(),
        ) == false
        {
            CloseHandle(handle);
            return false;
        }

        CloseHandle(handle);
        let elevation = elevation.assume_init();

        elevation.TokenIsElevated != 0
    }
}

fn get_process_id_from_name(name: &str) -> windows::Result<Option<u32>> {
    unsafe {
        let mut entry = MaybeUninit::<PROCESSENTRY32W>::uninit();
        addr_of_mut!((*entry.as_mut_ptr()).dwSize).write(mem::size_of::<PROCESSENTRY32W>() as _);
        let handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if handle.is_invalid() {
            return Err(hresult_from_last_error().into());
        }
        if Process32FirstW(handle, entry.as_mut_ptr()) == false {
            return Err(hresult_from_last_error().into());
        }
        let mut entry = entry.assume_init();
        if osstr_from_slice_with_zero(&entry.szExeFile) == name {
            CloseHandle(handle);
            return Ok(Some(entry.th32ProcessID));
        }
        while Process32NextW(handle, addr_of_mut!(entry)) != false {
            if osstr_from_slice_with_zero(&entry.szExeFile) == name {
                CloseHandle(handle);
                return Ok(Some(entry.th32ProcessID));
            }
        }
        CloseHandle(handle);
        Ok(None)
    }
}

fn enable_debug_privilege() -> windows::Result<()> {
    unsafe {
        let mut handle = MaybeUninit::<HANDLE>::uninit();

        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, handle.as_mut_ptr()) == false {
            return Err(hresult_from_last_error().into());
        }

        let handle = handle.assume_init();
        let mut luid = MaybeUninit::<LUID>::uninit();

        if LookupPrivilegeValueW(None, "SeDebugPrivilege", luid.as_mut_ptr()) == false {
            CloseHandle(handle);
            return Err(hresult_from_last_error().into());
        }

        let luid = luid.assume_init();
        let mut tkp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };

        if AdjustTokenPrivileges(handle, false, addr_of_mut!(tkp), 0, ptr::null_mut(), ptr::null_mut()) == false {
            CloseHandle(handle);
            return Err(hresult_from_last_error().into());
        }

        CloseHandle(handle);

        Ok(())
    }
}

const APP_AUMID: &'static str = "ApkipaLimitedCompany.DwmKillerCUI.Main.v0_1_0";

// usize: MB
fn get_dwm_mem_usage() -> windows::Result<usize> {
    unsafe {
        let process_id = get_process_id_from_name("dwm.exe")?.unwrap_or(0);
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id);
        if handle.is_null() {
            return Err(hresult_from_last_error().into());
        }

        let mut counters = MaybeUninit::<PROCESS_MEMORY_COUNTERS>::uninit();

        if K32GetProcessMemoryInfo(handle, counters.as_mut_ptr(), mem::size_of::<PROCESS_MEMORY_COUNTERS>() as _) == false {
            CloseHandle(handle);
            return Err(hresult_from_last_error().into());
        }

        CloseHandle(handle);
        let counters = counters.assume_init();

        Ok(counters.PagefileUsage / 1024 / 1024)
    }
}

fn kill_dwm() -> windows::Result<()> {
    unsafe {
        let process_id = get_process_id_from_name("dwm.exe")?.unwrap_or(0);
        let handle = OpenProcess(PROCESS_TERMINATE, false, process_id);
        if handle.is_null() {
            return Err(hresult_from_last_error().into());
        }

        if TerminateProcess(handle, 1) == false {
            CloseHandle(handle);
            return Err(hresult_from_last_error().into());
        }

        CloseHandle(handle);

        Ok(())
    }
}

fn gen_toast_details_string(mem_limit: usize, cur_mem: usize) -> String {
    format!("dwm.exe 内存占用已达 {} MB，超过了设定的 {} MB。点击以进行重启。", cur_mem, mem_limit)
}

fn gen_toast_notification(mem_limit: usize, cur_mem: usize) -> windows::Result<ToastNotification> {
    // <toast><visual><binding template="ToastText02"><text id="1">title</text><text id="2">text</text></binding></visual></toast>
    let mut xml_str = String::new();
    xml_str += r#"<toast><visual><binding template="ToastText02"><text id="1">"#;
    xml_str += r#"dwm.exe 内存溢出"#;
    xml_str += r#"</text><text id="2">"#;
    // xml_str += &gen_toast_details_string(mem_mb_num);
    xml_str += r#"{details}"#;
    xml_str += r#"</text></binding></visual></toast>"#;
    let toast_xml = XmlDocument::new()?;
    toast_xml.LoadXml(xml_str)?;
    let toast = ToastNotification::CreateToastNotification(toast_xml)?;
    let data = NotificationData::new()?;
    data.Values()?.Insert("details", gen_toast_details_string(mem_limit, cur_mem))?;
    toast.SetData(data)?;
    Ok(toast)
}

fn update_toast_notification(toast: &ToastNotification, mem_limit: usize, cur_mem: usize) -> windows::Result<()> {
    toast.Data()?.Values()?.Insert("details", gen_toast_details_string(mem_limit, cur_mem))?;
    Ok(())
}

struct ToastData {
    toast: ToastNotification,
    mem_limit: usize,
    last_mem: usize,
}

fn main() -> windows::Result<()> {
    // unsafe {
    //     RoInitialize(RO_INIT_MULTITHREADED)?;
    //     SetCurrentProcessExplicitAppUserModelID(APP_AUMID)?;
    // }

    // let shortcut_path = "App.lnk";
    // if !Path::new(shortcut_path).exists() {
    //     create_shortcut(shortcut_path)?;
    // }

    enable_debug_privilege()?;

    println!("DwmKiller v{}\n", env!("CARGO_PKG_VERSION"));

    const DWM_INITIAL_MEM_LIMIT: usize = 500;

    if !is_elevated() {
        eprintln!("错误：权限不足。请以管理员权限运行此应用。");
        sleep(Duration::from_secs(3));
        return Ok(());
    }

    let manager = ToastNotificationManager::CreateToastNotifierWithId(APP_AUMID)?;
    let toast_mutex = Arc::new(Mutex::new(ToastData {
        toast: gen_toast_notification(DWM_INITIAL_MEM_LIMIT, 0)?,
        mem_limit: DWM_INITIAL_MEM_LIMIT,
        last_mem: 0,
    }));
    let activated_handler = TypedEventHandler::new(
        enclose! { (manager, toast_mutex) move |_, _| {
            let mut unlocked = toast_mutex.lock().unwrap();
            println!("信息：通知已被激活。");
            let _ = manager.Hide(&unlocked.toast);
            if kill_dwm().is_err() {
                eprintln!("错误：无法终止 dwm.exe。请手动杀死进程。");
                return Ok(());
            }
            unlocked.last_mem = 0;
            unlocked.mem_limit = DWM_INITIAL_MEM_LIMIT;
            Ok(())
        }},
    );
    let dismissed_handler = TypedEventHandler::new(
        enclose! { (manager, toast_mutex) move |_, _| {
            let mut unlocked = toast_mutex.lock().unwrap();
            println!("信息：通知已被忽略。");
            let _ = manager.Hide(&unlocked.toast);
            unlocked.last_mem = 0;
            // Increase limit by 100 MB
            unlocked.mem_limit += 100;
            Ok(())
        }},
    );
    let try_update_toast_closure = enclose! { (toast_mutex, activated_handler, dismissed_handler) move || {
        let mut unlocked = toast_mutex.lock().unwrap();
        if unlocked.last_mem >= unlocked.mem_limit {
            // Already approached the limit, ignore for now
            return false;
        }
        let cur_mem = get_dwm_mem_usage().unwrap_or_else(|e| {
            eprintln!("错误：无法获取 dwm.exe 内存占用 ({:?})。", e);
            0
        });
        unlocked.last_mem = cur_mem;
        println!("当前内存用量：{} / {} MB", cur_mem, unlocked.mem_limit);
        if cur_mem >= unlocked.mem_limit {
            unlocked.toast = gen_toast_notification(unlocked.mem_limit, cur_mem).unwrap();
            // update_toast_notification(&unlocked.toast, unlocked.mem_limit, cur_mem).unwrap();
            unlocked.toast.Activated(&activated_handler).unwrap();
            unlocked.toast.Dismissed(&dismissed_handler).unwrap();
            return true;
        }
        false
    }};

    loop {
        if try_update_toast_closure() {
            let unlocked = toast_mutex.lock().unwrap();
            let _ = manager.Hide(&unlocked.toast);
            manager.Show(&unlocked.toast)?;
        }

        sleep(Duration::from_secs(60));
    }
}
