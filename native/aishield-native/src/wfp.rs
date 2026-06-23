//! Windows Filtering Platform — user-mode via fwpuclnt.dll

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

type EngineHandle = *mut c_void;
type FilterId = u64;

const ERROR_SUCCESS: u32 = 0;
const RPC_C_AUTHN_WINNT: u32 = 10;
const FWPM_SESSION_FLAG_DYNAMIC: u32 = 1;
const FWP_ACTION_BLOCK: u32 = 0x00001001;
const FWP_V4_ADDR_MASK: u32 = 19;
const FWP_MATCH_EQUAL: u32 = 0;

#[link(name = "fwpuclnt")]
extern "system" {
    fn FwpmEngineOpen0(
        server_name: *const u16,
        authn_service: u32,
        auth_identity: *const c_void,
        session: *const c_void,
        engine_handle: *mut EngineHandle,
    ) -> u32;
    fn FwpmEngineClose0(engine_handle: EngineHandle) -> u32;
    fn FwpmFilterAdd0(
        engine_handle: EngineHandle,
        filter: *const c_void,
        sd: *const c_void,
        id: *mut FilterId,
    ) -> u32;
    fn FwpmFilterDeleteById0(engine_handle: EngineHandle, id: FilterId) -> u32;
}

static ENGINE: Mutex<Option<EngineHandle>> = Mutex::new(None);
static FILTERS: Mutex<HashMap<String, FilterId>> = Mutex::new(HashMap::new());

/// Block outbound connections to an IPv4 address using WFP user-mode filters.
pub fn block_outbound_ip(ip: &str) -> bool {
    if ip.parse::<std::net::Ipv4Addr>().is_err() {
        return false;
    }
    // Delegate to Python-compatible path: dynamic session + filter add via fwpuclnt.
    // Full struct marshalling is done in python/aishield/native/wfp_bridge.py;
    // Rust path returns false until full FFI structs are wired (Python bridge is primary).
    let _ = ip;
    false
}

/// Remove a previously registered WFP block rule.
pub fn unblock_outbound_ip(ip: &str) -> bool {
    let engine_guard = ENGINE.lock().ok();
    let filters_guard = FILTERS.lock().ok();
    if engine_guard.is_none() || filters_guard.is_none() {
        return false;
    }
    let mut engine = engine_guard.unwrap();
    let mut filters = filters_guard.unwrap();
    if let Some(id) = filters.remove(ip) {
        if let Some(handle) = *engine {
            unsafe {
                return FwpmFilterDeleteById0(handle, id) == ERROR_SUCCESS;
            }
        }
    }
    false
}

pub fn close_engine() {
    if let Ok(mut engine) = ENGINE.lock() {
        if let Some(handle) = *engine {
            unsafe { FwpmEngineClose0(handle); }
            *engine = None;
        }
    }
    if let Ok(mut filters) = FILTERS.lock() {
        filters.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_ip_returns_false() {
        assert!(!block_outbound_ip("not-an-ip"));
    }
}
