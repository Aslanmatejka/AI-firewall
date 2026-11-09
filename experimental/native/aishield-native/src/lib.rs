//! Native Windows hooks for AI Firewall.
//!
//! - Screenshot exclusion via SetWindowDisplayAffinity
//! - WFP user-mode stub (kernel driver Phase 3)

mod wfp;

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE};

pub use wfp::{block_outbound_ip, unblock_outbound_ip};

/// Exclude a window from screen capture (Windows 10 2004+).
pub fn exclude_from_capture(hwnd: isize) -> bool {
    unsafe {
        SetWindowDisplayAffinity(HWND(hwnd), WDA_EXCLUDEFROMCAPTURE).is_ok()
    }
}

/// Re-allow capture for a previously protected window.
pub fn allow_capture(hwnd: isize) -> bool {
    unsafe {
        SetWindowDisplayAffinity(HWND(hwnd), windows::Win32::UI::WindowsAndMessaging::WDA_NONE).is_ok()
    }
}

#[no_mangle]
pub extern "C" fn aishield_exclude_from_capture(hwnd: isize) -> bool {
    exclude_from_capture(hwnd)
}

#[no_mangle]
pub extern "C" fn aishield_allow_capture(hwnd: isize) -> bool {
    allow_capture(hwnd)
}

#[no_mangle]
pub extern "C" fn aishield_wfp_block_ip(ip: *const u8, len: usize) -> bool {
    if ip.is_null() || len == 0 {
        return false;
    }
    let slice = unsafe { std::slice::from_raw_parts(ip, len) };
    match std::str::from_utf8(slice) {
        Ok(s) => block_outbound_ip(s),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_invalid_hwnd_returns_false() {
        assert!(!exclude_from_capture(0));
    }
}
