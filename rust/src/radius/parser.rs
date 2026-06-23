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

//! RADIUS wire-format parsing (RFC 2865 / RFC 2866).

use nom7::bytes::streaming::take;
use nom7::combinator::{complete, verify};
use nom7::multi::many0;
use nom7::number::streaming::{be_u16, be_u32, be_u8};
use nom7::IResult;

pub struct RadiusAvp {
    pub key: String,
    pub value: String,
}

pub struct RadiusHeader {
    pub code: u8,
    pub identifier: u8,
    pub length: u16,
    pub authenticator: [u8; 16],
}

pub struct RadiusParsedMessage {
    pub header: RadiusHeader,
    pub avps: Vec<RadiusAvp>,
}

pub fn parse_radius_header(input: &[u8]) -> IResult<&[u8], RadiusHeader> {
    let (i, code) = be_u8(input)?;
    let (i, identifier) = be_u8(i)?;
    let (i, length) = be_u16(i)?;
    let (i, auth_bytes) = take(16_usize)(i)?;
    let mut authenticator = [0u8; 16];
    authenticator.copy_from_slice(auth_bytes);
    Ok((i, RadiusHeader { code, identifier, length, authenticator }))
}

/// Parse a single TLV (type, length, value). `length` includes the 2-byte header.
fn parse_tlv(input: &[u8]) -> IResult<&[u8], (u8, &[u8])> {
    let (i, attr_type) = be_u8(input)?;
    let (i, attr_len) = verify(be_u8, |&v| v >= 2)(i)?;
    let (i, value) = take((attr_len - 2) as usize)(i)?;
    Ok((i, (attr_type, value)))
}

/// Parse the attribute TLV list following the 20-byte RADIUS header.
/// A malformed TLV (under-length or overrun) stops `many0` and returns the
/// attributes decoded so far.
pub fn parse_avps(data: &[u8]) -> IResult<&[u8], Vec<RadiusAvp>> {
    let (rem, tlvs) = many0(complete(parse_tlv))(data)?;
    let mut avps = Vec::with_capacity(tlvs.len());
    for (attr_type, value) in tlvs {
        if attr_type == 26 {
            avps.extend(decode_vsa(value));
        } else {
            avps.push(decode_avp(attr_type, value));
        }
    }
    Ok((rem, avps))
}

fn parse_vsa(value: &[u8]) -> IResult<&[u8], Vec<RadiusAvp>> {
    let (i, vendor_id) = be_u32(value)?;
    let (rem, sub_tlvs) = many0(complete(parse_tlv))(i)?;
    let avps = sub_tlvs
        .into_iter()
        .map(|(vtype, data)| RadiusAvp {
            key: format!("vendor.{}.{}", vendor_id, vtype),
            value: decode_vsa_value(vendor_id, vtype, data),
        })
        .collect();
    Ok((rem, avps))
}

/// Decode a Vendor-Specific attribute (type 26, RFC 2865 §5.26).
/// Each sub-attribute becomes a separate entry keyed `vendor.{vendor_id}.{vendor_type}`.
/// Falls back to a single hex-encoded entry when the payload is too short or has no
/// parseable sub-attributes.
fn decode_vsa(value: &[u8]) -> Vec<RadiusAvp> {
    match parse_vsa(value) {
        Ok((_, avps)) if !avps.is_empty() => avps,
        _ => vec![RadiusAvp {
            key: "vendor_specific".into(),
            value: hex_encode(value),
        }],
    }
}

fn decode_vsa_value(vendor_id: u32, vtype: u8, data: &[u8]) -> String {
    match (vendor_id, vtype) {
        (10415, 1) => String::from_utf8_lossy(data).into_owned(), // 3GPP IMSI
        _ => hex_encode(data),
    }
}

fn decode_avp(attr_type: u8, value: &[u8]) -> RadiusAvp {
    match attr_type {
        1 => RadiusAvp {
            key: "user_name".into(),
            value: String::from_utf8_lossy(value).into_owned(),
        },
        4 => RadiusAvp {
            key: "nas_ip_address".into(),
            value: decode_ipv4(value),
        },
        5 => RadiusAvp {
            key: "nas_port".into(),
            value: decode_u32_decimal(value),
        },
        6 => RadiusAvp {
            key: "service_type".into(),
            value: if value.len() >= 4 {
                service_type_str(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
                    .to_string()
            } else {
                hex_encode(value)
            },
        },
        8 => RadiusAvp {
            key: "framed_ip_address".into(),
            value: decode_ipv4(value),
        },
        18 => RadiusAvp {
            key: "reply_message".into(),
            value: String::from_utf8_lossy(value).into_owned(),
        },
        24 => RadiusAvp {
            key: "state".into(),
            value: hex_encode(value),
        },
        30 => RadiusAvp {
            key: "called_station_id".into(),
            value: String::from_utf8_lossy(value).into_owned(),
        },
        31 => RadiusAvp {
            key: "calling_station_id".into(),
            value: String::from_utf8_lossy(value).into_owned(),
        },
        32 => RadiusAvp {
            key: "nas_identifier".into(),
            value: String::from_utf8_lossy(value).into_owned(),
        },
        40 => RadiusAvp {
            key: "acct_status_type".into(),
            value: if value.len() >= 4 {
                acct_status_type_str(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
                    .to_string()
            } else {
                hex_encode(value)
            },
        },
        44 => RadiusAvp {
            key: "acct_session_id".into(),
            value: String::from_utf8_lossy(value).into_owned(),
        },
        55 => RadiusAvp {
            key: "event_timestamp".into(),
            value: if value.len() >= 4 {
                format_unix_ts_iso(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
            } else {
                hex_encode(value)
            },
        },
        61 => RadiusAvp {
            key: "nas_port_type".into(),
            value: if value.len() >= 4 {
                nas_port_type_str(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
                    .to_string()
            } else {
                hex_encode(value)
            },
        },
        77 => RadiusAvp {
            key: "connect_info".into(),
            value: String::from_utf8_lossy(value).into_owned(),
        },
        79 => RadiusAvp {
            key: "eap_message".into(),
            value: hex_encode(value),
        },
        87 => RadiusAvp {
            key: "nas_port_id".into(),
            value: String::from_utf8_lossy(value).into_owned(),
        },
        _ => RadiusAvp {
            key: attr_type.to_string(),
            value: hex_encode(value),
        },
    }
}

fn decode_ipv4(value: &[u8]) -> String {
    if value.len() >= 4 {
        format!("{}.{}.{}.{}", value[0], value[1], value[2], value[3])
    } else {
        hex_encode(value)
    }
}

fn decode_u32_decimal(value: &[u8]) -> String {
    if value.len() >= 4 {
        u32::from_be_bytes([value[0], value[1], value[2], value[3]]).to_string()
    } else {
        hex_encode(value)
    }
}

/// Convert a Unix epoch timestamp (seconds) to ISO 8601 UTC string.
fn format_unix_ts_iso(epoch_secs: u32) -> String {
    let secs = epoch_secs as u64;
    let ss = secs % 60;
    let mm = (secs / 60) % 60;
    let hh = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, m, d) = epoch_days_to_ymd(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
}

/// Gregorian calendar algorithm (Howard Hinnant) — days since 1970-01-01 to (year, month, day).
fn epoch_days_to_ymd(days: u64) -> (u32, u32, u32) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

pub fn parse_radius_message(input: &[u8]) -> Option<RadiusParsedMessage> {
    if input.len() < 20 {
        return None;
    }
    let (_, header) = parse_radius_header(input).ok()?;
    if header.length < 20 || header.length > 4096 {
        return None;
    }
    let total = header.length as usize;
    if total > input.len() {
        return None;
    }
    let (_, avps) = parse_avps(&input[20..total]).ok()?;
    Some(RadiusParsedMessage { header, avps })
}

/// Human-readable RADIUS message type (RFC 2865 §3).
pub fn code_str(code: u8) -> &'static str {
    match code {
        1 => "access_request",
        2 => "access_accept",
        3 => "access_reject",
        4 => "accounting_request",
        5 => "accounting_response",
        11 => "access_challenge",
        _ => "unknown",
    }
}

/// Human-readable NAS-Port-Type (RFC 2865 §5.41).
pub fn nas_port_type_str(v: u32) -> &'static str {
    match v {
        0 => "async",
        1 => "sync",
        5 => "virtual",
        11 => "isdn_sync",
        15 => "ethernet",
        19 => "wireless_802_11",
        _ => "unknown",
    }
}

/// Human-readable Acct-Status-Type (RFC 2866 §5.1).
pub fn acct_status_type_str(v: u32) -> &'static str {
    match v {
        1 => "start",
        2 => "stop",
        3 => "interim_update",
        7 => "accounting_on",
        8 => "accounting_off",
        _ => "unknown",
    }
}

/// Human-readable Service-Type (RFC 2865 §5.6).
pub fn service_type_str(v: u32) -> &'static str {
    match v {
        1 => "login",
        2 => "framed",
        3 => "callback_login",
        4 => "callback_framed",
        5 => "outbound",
        6 => "administrative",
        7 => "nas_prompt",
        8 => "authenticate_only",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(code: u8, identifier: u8, length: u16) -> [u8; 20] {
        let mut buf = [0u8; 20];
        buf[0] = code;
        buf[1] = identifier;
        buf[2] = (length >> 8) as u8;
        buf[3] = (length & 0xff) as u8;
        // authenticator bytes 4..20 remain zero
        buf
    }

    #[test]
    fn test_parse_header_basic() {
        let data = make_header(1, 42, 20);
        let (_, hdr) = parse_radius_header(&data).unwrap();
        assert_eq!(hdr.code, 1);
        assert_eq!(hdr.identifier, 42);
        assert_eq!(hdr.length, 20);
        assert_eq!(hdr.authenticator, [0u8; 16]);
    }

    #[test]
    fn test_parse_header_truncated() {
        // 19 bytes — not enough for the 20-byte fixed header
        let data = [0u8; 19];
        assert!(parse_radius_header(&data).is_err());
    }

    #[test]
    fn test_parse_message_length_too_small() {
        // length field says 19, which is below the 20-byte minimum
        let mut data = make_header(1, 1, 19);
        data[2] = 0;
        data[3] = 19;
        assert!(parse_radius_message(&data).is_none());
    }

    #[test]
    fn test_parse_message_length_too_large() {
        let mut data = make_header(1, 1, 4097);
        data[2] = (4097u16 >> 8) as u8;
        data[3] = (4097u16 & 0xff) as u8;
        assert!(parse_radius_message(&data).is_none());
    }

    #[test]
    fn test_parse_message_input_too_short() {
        let data = [0u8; 15];
        assert!(parse_radius_message(&data).is_none());
    }

    #[test]
    fn test_parse_avps_user_name() {
        // User-Name attr: type=1, len=7, value="alice"
        let buf: &[u8] = &[1, 7, b'a', b'l', b'i', b'c', b'e'];
        let (_, avps) = parse_avps(buf).unwrap();
        assert_eq!(avps.len(), 1);
        assert_eq!(avps[0].key, "user_name");
        assert_eq!(avps[0].value, "alice");
    }

    #[test]
    fn test_parse_avps_nas_ip_address() {
        // NAS-IP-Address attr: type=4, len=6, value=192.168.1.1
        let buf: &[u8] = &[4, 6, 192, 168, 1, 1];
        let (_, avps) = parse_avps(buf).unwrap();
        assert_eq!(avps.len(), 1);
        assert_eq!(avps[0].key, "nas_ip_address");
        assert_eq!(avps[0].value, "192.168.1.1");
    }

    #[test]
    fn test_parse_avps_reply_message() {
        let msg = b"Access denied";
        let mut buf = vec![18u8, (2 + msg.len()) as u8];
        buf.extend_from_slice(msg);
        let (_, avps) = parse_avps(&buf).unwrap();
        assert_eq!(avps.len(), 1);
        assert_eq!(avps[0].key, "reply_message");
        assert_eq!(avps[0].value, "Access denied");
    }

    #[test]
    fn test_parse_avps_unknown_type_skipped_gracefully() {
        // type=99 (unknown): type=99, len=4, value=[0xde,0xad]
        // followed by type=1 (User-Name): type=1, len=7, value="alice"
        let buf: &[u8] = &[99, 4, 0xde, 0xad, 1, 7, b'a', b'l', b'i', b'c', b'e'];
        let (_, avps) = parse_avps(buf).unwrap();
        assert_eq!(avps.len(), 2);
        assert_eq!(avps[0].key, "99");
        assert_eq!(avps[0].value, "dead");
        assert_eq!(avps[1].key, "user_name");
        assert_eq!(avps[1].value, "alice");
    }

    #[test]
    fn test_parse_avps_duplicate_attr() {
        // Two User-Name attributes — both should appear in the Vec
        let buf: &[u8] = &[
            1, 7, b'a', b'l', b'i', b'c', b'e',
            1, 5, b'b', b'o', b'b',
        ];
        let (_, avps) = parse_avps(buf).unwrap();
        assert_eq!(avps.len(), 2);
        assert_eq!(avps[0].value, "alice");
        assert_eq!(avps[1].value, "bob");
    }

    #[test]
    fn test_parse_avps_tlv_overrun_stops_safely() {
        // First attr: type=1, len=100 — overruns a 10-byte buffer
        // Should stop without panic; no entries decoded
        let buf: &[u8] = &[1, 100, b'x', b'y', b'z'];
        let (_, avps) = parse_avps(buf).unwrap();
        assert_eq!(avps.len(), 0);
    }

    #[test]
    fn test_parse_avps_tlv_overrun_after_valid() {
        // First attr valid, second overruns — only first decoded
        let buf: &[u8] = &[
            1, 4, b'a', b'b',   // valid: User-Name "ab"
            4, 100, 1, 2,        // overruns: NAS-IP-Address with declared len=100
        ];
        let (_, avps) = parse_avps(buf).unwrap();
        assert_eq!(avps.len(), 1);
        assert_eq!(avps[0].key, "user_name");
    }

    #[test]
    fn test_code_str_known() {
        assert_eq!(code_str(1), "access_request");
        assert_eq!(code_str(2), "access_accept");
        assert_eq!(code_str(3), "access_reject");
        assert_eq!(code_str(4), "accounting_request");
        assert_eq!(code_str(5), "accounting_response");
        assert_eq!(code_str(11), "access_challenge");
    }

    #[test]
    fn test_code_str_unknown() {
        assert_eq!(code_str(99), "unknown");
        assert_eq!(code_str(0), "unknown");
    }

    #[test]
    fn test_nas_port_type_str() {
        assert_eq!(nas_port_type_str(15), "ethernet");
        assert_eq!(nas_port_type_str(19), "wireless_802_11");
        assert_eq!(nas_port_type_str(99), "unknown");
    }

    #[test]
    fn test_acct_status_type_str() {
        assert_eq!(acct_status_type_str(1), "start");
        assert_eq!(acct_status_type_str(2), "stop");
        assert_eq!(acct_status_type_str(3), "interim_update");
        assert_eq!(acct_status_type_str(99), "unknown");
    }

    #[test]
    fn test_parse_vsa_single_subattr() {
        // VSA: type=26, len=12, vendor-id=9(Cisco), vendor-type=1, vendor-len=6, data=[0x01,0x02,0x03,0x04]
        // Outer length = 2 (AVP header) + 4 (vendor-id) + 6 (sub-TLV) = 12
        // Vendor 9 has no IMSI shortcut, so the value is hex-encoded.
        let mut buf = vec![26u8, 12u8];
        buf.extend_from_slice(&9u32.to_be_bytes()); // vendor-id
        buf.push(1); // vendor-type
        buf.push(6); // vendor-len (2 + 4 data bytes)
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let (_, avps) = parse_avps(&buf).unwrap();
        assert_eq!(avps.len(), 1);
        assert_eq!(avps[0].key, "vendor.9.1");
        assert_eq!(avps[0].value, "01020304");
    }

    #[test]
    fn test_parse_vsa_multiple_subattrs() {
        // Two sub-attributes within one VSA AVP. Vendor 9 keeps the hex-encode path
        // (vendor 10415 sub-type 1 would trigger IMSI string decode).
        let mut buf = vec![26u8, 14u8];
        buf.extend_from_slice(&9u32.to_be_bytes()); // vendor-id
        buf.push(1); buf.push(4); buf.extend_from_slice(&[0xaa, 0xbb]); // sub-attr 1
        buf.push(2); buf.push(4); buf.extend_from_slice(&[0xcc, 0xdd]); // sub-attr 2
        // Length: 2 (type+len) + 4 (vendor-id) + 4 + 4 = 14
        let (_, avps) = parse_avps(&buf).unwrap();
        assert_eq!(avps.len(), 2);
        assert_eq!(avps[0].key, "vendor.9.1");
        assert_eq!(avps[0].value, "aabb");
        assert_eq!(avps[1].key, "vendor.9.2");
        assert_eq!(avps[1].value, "ccdd");
    }

    #[test]
    fn test_event_timestamp_iso() {
        // 2024-01-01T00:00:00Z = 1704067200
        let ts: u32 = 1704067200;
        let mut buf = vec![55u8, 6u8];
        buf.extend_from_slice(&ts.to_be_bytes());
        let (_, avps) = parse_avps(&buf).unwrap();
        assert_eq!(avps.len(), 1);
        assert_eq!(avps[0].key, "event_timestamp");
        assert_eq!(avps[0].value, "2024-01-01T00:00:00Z");
    }

    #[test]
    fn test_vsa_3gpp_imsi_decoded_as_string() {
        // VSA vendor 10415, sub-type 1 → IMSI as ASCII string
        let imsi = b"234302012345678";
        let vlen = (2 + imsi.len()) as u8;
        // Outer AVP length = 2 (AVP header) + 4 (vendor-id) + vlen (sub-TLV)
        let outer_len = 2 + 4 + vlen;
        let mut buf = vec![26u8, outer_len];
        buf.extend_from_slice(&10415u32.to_be_bytes());
        buf.push(1); buf.push(vlen);
        buf.extend_from_slice(imsi);
        let (_, avps) = parse_avps(&buf).unwrap();
        assert_eq!(avps.len(), 1);
        assert_eq!(avps[0].key, "vendor.10415.1");
        assert_eq!(avps[0].value, "234302012345678");
    }

    #[test]
    fn test_service_type_str() {
        assert_eq!(service_type_str(2), "framed");
        assert_eq!(service_type_str(1), "login");
        assert_eq!(service_type_str(99), "unknown");
    }
}
