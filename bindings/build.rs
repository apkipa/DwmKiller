fn main() {
    windows::build! {
        Windows::UI::Notifications::{
            Notification, ToastNotificationManager, ToastNotifier, ToastNotification,
            ToastTemplateType, ToastNotificationActionTriggerDetail, ToastNotificationHistory,
            NotificationData,
        },
        Windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID,
        Windows::Win32::System::LibraryLoader::GetModuleFileNameW,
        Windows::Win32::Foundation::{HINSTANCE, MAX_PATH, CloseHandle},
        Windows::Win32::System::Com::{CoCreateInstance, IPersistFile},
        Windows::Win32::System::WinRT::RoInitialize,
        Windows::Win32::System::PropertiesSystem::IPropertyStore,
        Windows::Win32::UI::Shell::{ShellLink, IShellLinkW},
        Windows::Win32::System::Diagnostics::Debug::{GetLastError, FACILITY_CODE},
        Windows::Win32::System::Diagnostics::ToolHelp::{
            PROCESSENTRY32W, CreateToolhelp32Snapshot, Process32FirstW, Process32NextW
        },
        Windows::Win32::System::OleAutomation::VARENUM,
        Windows::Data::Xml::Dom::XmlDocument,
        Windows::Foundation::{TypedEventHandler, Collections::{IMapView, IKeyValuePair, IMap}},
        Windows::Win32::System::Threading::{OpenProcessToken, GetCurrentProcess, OpenProcess, TerminateProcess},
        Windows::Win32::System::ProcessStatus::K32GetProcessMemoryInfo,
        Windows::Win32::Security::{
            GetTokenInformation, TOKEN_ELEVATION, LookupPrivilegeValueW, AdjustTokenPrivileges,
        },
    }
}
