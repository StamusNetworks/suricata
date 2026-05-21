/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

use std::ffi::CString;

use crate::applayer::{self, *};
use crate::core::{self, ALPROTO_UNKNOWN, AppProto, Flow, IPPROTO_UDP};
use crate::radius::parser::*;

static mut ALPROTO_RADIUS: AppProto = ALPROTO_UNKNOWN;

const RADIUS_MIN_LEN: u32 = 20;

pub struct RadiusTransaction {
    id: u64,
    pub code: u8,
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub avps: Vec<RadiusAvp>,
    tx_data: applayer::AppLayerTxData,
}

impl Transaction for RadiusTransaction {
    fn id(&self) -> u64 {
        self.id
    }
}

impl RadiusTransaction {
    fn new(id: u64, msg: RadiusParsedMessage) -> Self {
        Self {
            id,
            code: msg.header.code,
            identifier: msg.header.identifier,
            authenticator: msg.header.authenticator,
            avps: msg.avps,
            tx_data: applayer::AppLayerTxData::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(code: u8, identifier: u8, avps: Vec<RadiusAvp>) -> Self {
        Self {
            id: 1,
            code,
            identifier,
            authenticator: [0u8; 16],
            avps,
            tx_data: applayer::AppLayerTxData::new(),
        }
    }
}

#[derive(Default)]
pub struct RadiusState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: Vec<RadiusTransaction>,
}

impl State<RadiusTransaction> for RadiusState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&RadiusTransaction> {
        self.transactions.get(index)
    }
}

impl RadiusState {
    pub fn new() -> Self {
        Default::default()
    }

    fn add_transaction(&mut self, msg: RadiusParsedMessage) {
        self.tx_id += 1;
        let tx = RadiusTransaction::new(self.tx_id, msg);
        self.transactions.push(tx);
    }

    pub fn parse(&mut self, input: &[u8]) -> bool {
        match parse_radius_message(input) {
            Some(msg) => {
                self.add_transaction(msg);
                true
            }
            None => false,
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&RadiusTransaction> {
        self.transactions.iter().find(|tx| tx.id == tx_id + 1)
    }

    fn free_tx(&mut self, tx_id: u64) {
        let internal_id = tx_id + 1;
        self.transactions.retain(|tx| tx.id != internal_id);
    }
}

/// Pure validation logic extracted for unit testing.
fn probe(input: &[u8]) -> bool {
    if input.len() < 20 {
        return false;
    }
    let code = input[0];
    if !matches!(code, 1 | 2 | 3 | 4 | 5 | 11) {
        return false;
    }
    let length = u16::from_be_bytes([input[2], input[3]]);
    length >= 20 && length <= 4096
}

// ── FFI callbacks ────────────────────────────────────────────────────────────

unsafe extern "C" fn radius_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input.is_null() {
        return ALPROTO_UNKNOWN;
    }
    let slice = build_slice!(input, input_len as usize);
    if probe(slice) {
        return ALPROTO_RADIUS;
    }
    ALPROTO_UNKNOWN
}

extern "C" fn radius_tx_get_alstate_progress(
    _tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    1
}

extern "C" fn radius_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = RadiusState::new();
    let boxed = Box::new(state);
    Box::into_raw(boxed) as *mut _
}

unsafe extern "C" fn radius_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(Box::from_raw(state as *mut RadiusState));
}

unsafe extern "C" fn radius_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, RadiusState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn radius_parse(
    _flow: *const core::Flow, state: *mut std::os::raw::c_void, _pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, RadiusState);
    if state.parse(stream_slice.as_slice()) {
        AppLayerResult::ok()
    } else {
        AppLayerResult::err()
    }
}

unsafe extern "C" fn radius_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, RadiusState);
    match state.get_tx(tx_id) {
        Some(tx) => tx as *const _ as *mut _,
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn radius_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, RadiusState);
    state.tx_id
}

export_tx_data_get!(radius_get_tx_data, RadiusTransaction);
export_state_data_get!(radius_get_state_data, RadiusState);

// ── Parser registration ───────────────────────────────────────────────────────

const PARSER_NAME: &[u8] = b"radius\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterRadiusParser() {
    SCLogDebug!("Registering RADIUS parser.");
    let ports = CString::new("[1812,1813]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: ports.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(radius_probing_parser),
        probe_tc: Some(radius_probing_parser),
        min_depth: 0,
        max_depth: RADIUS_MIN_LEN as u16,
        state_new: radius_state_new,
        state_free: radius_state_free,
        tx_free: radius_state_tx_free,
        parse_ts: radius_parse,
        parse_tc: radius_parse,
        get_tx_count: radius_state_get_tx_count,
        get_tx: radius_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: radius_tx_get_alstate_progress,
        get_eventinfo: None,
        get_eventinfo_byid: None,
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<RadiusState, RadiusTransaction>),
        get_tx_data: radius_get_tx_data,
        get_state_data: radius_get_state_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_RADIUS = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detector and parser disabled for RADIUS.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(code: u8, identifier: u8, length: u16) -> Vec<u8> {
        let mut buf = vec![0u8; length as usize];
        buf[0] = code;
        buf[1] = identifier;
        buf[2] = (length >> 8) as u8;
        buf[3] = (length & 0xff) as u8;
        buf
    }

    #[test]
    fn test_state_parse_valid_adds_one_tx() {
        let mut state = RadiusState::new();
        let pkt = make_packet(1, 42, 20);
        assert!(state.parse(&pkt));
        assert!(state.get_tx(0).is_some());
        let tx = state.get_tx(0).unwrap();
        assert_eq!(tx.code, 1);
        assert_eq!(tx.identifier, 42);
    }

    #[test]
    fn test_state_parse_short_returns_false() {
        let mut state = RadiusState::new();
        let pkt = vec![0u8; 19];
        assert!(!state.parse(&pkt));
        assert!(state.get_tx(0).is_none());
    }

    #[test]
    fn test_state_parse_two_packets_two_txs() {
        let mut state = RadiusState::new();
        let pkt = make_packet(1, 1, 20);
        assert!(state.parse(&pkt));
        assert!(state.parse(&pkt));
        assert_eq!(state.tx_id, 2);
        assert!(state.get_tx(0).is_some());
        assert!(state.get_tx(1).is_some());
    }

    #[test]
    fn test_probe_valid_access_request() {
        let pkt = make_packet(1, 1, 20);
        assert!(probe(&pkt));
    }

    #[test]
    fn test_probe_short_input() {
        assert!(!probe(&[0u8; 19]));
        assert!(!probe(&[]));
    }

    #[test]
    fn test_probe_unknown_code_zero() {
        let pkt = make_packet(0, 1, 20);
        assert!(!probe(&pkt));
    }

    #[test]
    fn test_probe_unknown_code_99() {
        let pkt = make_packet(99, 1, 20);
        assert!(!probe(&pkt));
    }

    #[test]
    fn test_probe_length_too_large() {
        let mut buf = vec![0u8; 20];
        buf[0] = 1;
        buf[2] = (4097u16 >> 8) as u8;
        buf[3] = (4097u16 & 0xff) as u8;
        assert!(!probe(&buf));
    }

    #[test]
    fn test_probe_all_known_codes() {
        for code in [1u8, 2, 3, 4, 5, 11] {
            let pkt = make_packet(code, 1, 20);
            assert!(probe(&pkt), "code {} should be accepted", code);
        }
    }
}
