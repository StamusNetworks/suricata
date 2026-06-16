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

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::radius::parser::code_str;
use crate::radius::radius::RadiusTransaction;

fn log(tx: &RadiusTransaction, js: &mut JsonBuilder, log_credentials: bool) -> Result<(), JsonError> {
    js.open_object("radius")?;

    js.set_string("code", code_str(tx.code))?;
    js.set_uint("code_id", tx.code as u64)?;
    js.set_uint("identifier", tx.identifier as u64)?;

    let auth_hex: String = tx.authenticator.iter().map(|b| format!("{:02x}", b)).collect();
    js.set_string("authenticator", &auth_hex)?;

    if let Some(avp) = tx.avps.iter().find(|a| a.key == "acct_status_type") {
        js.set_string("acct_status_type", &avp.value)?;
    }

    js.open_array("avp")?;
    for avp in &tx.avps {
        if !log_credentials
            && (avp.key == "user_name" || avp.key == "reply_message")
        {
            continue;
        }
        js.start_object()?;
        js.set_string("key", &avp.key)?;
        js.set_string("value", &avp.value)?;
        js.close()?;
    }
    js.close()?; // avp array

    js.close()?; // radius object
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCRadiusLogJson(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder, log_credentials: bool,
) -> bool {
    let tx = cast_pointer!(tx, RadiusTransaction);
    log(tx, js, log_credentials).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radius::parser::RadiusAvp;
    use crate::radius::radius::RadiusTransaction;

    fn make_tx(code: u8, identifier: u8, avps: Vec<RadiusAvp>) -> RadiusTransaction {
        RadiusTransaction::new_for_test(code, identifier, avps)
    }

    #[test]
    fn test_log_basic_ok() {
        let tx = make_tx(1, 42, vec![
            RadiusAvp { key: "user_name".into(), value: "alice".into() },
            RadiusAvp { key: "nas_ip_address".into(), value: "10.0.0.1".into() },
        ]);
        let mut js = JsonBuilder::try_new_object().unwrap();
        assert!(log(&tx, &mut js, true).is_ok());
    }

    #[test]
    fn test_log_credentials_suppressed() {
        let tx = make_tx(1, 1, vec![
            RadiusAvp { key: "user_name".into(), value: "alice".into() },
            RadiusAvp { key: "reply_message".into(), value: "denied".into() },
            RadiusAvp { key: "nas_ip_address".into(), value: "10.0.0.1".into() },
        ]);
        let mut js = JsonBuilder::try_new_object().unwrap();
        assert!(log(&tx, &mut js, false).is_ok());
    }

    #[test]
    fn test_log_credentials_included() {
        let tx = make_tx(1, 1, vec![
            RadiusAvp { key: "user_name".into(), value: "alice".into() },
        ]);
        let mut js = JsonBuilder::try_new_object().unwrap();
        assert!(log(&tx, &mut js, true).is_ok());
    }

    #[test]
    fn test_log_unknown_avp_ok() {
        let tx = make_tx(4, 7, vec![
            RadiusAvp { key: "99".into(), value: "deadbeef".into() },
        ]);
        let mut js = JsonBuilder::try_new_object().unwrap();
        assert!(log(&tx, &mut js, true).is_ok());
    }

    #[test]
    fn test_log_empty_avps_ok() {
        let tx = make_tx(2, 1, vec![]);
        let mut js = JsonBuilder::try_new_object().unwrap();
        assert!(log(&tx, &mut js, true).is_ok());
    }

    #[test]
    fn test_log_acct_status_type_hoisted() {
        let tx = make_tx(4, 1, vec![
            RadiusAvp { key: "acct_status_type".into(), value: "start".into() },
        ]);
        let mut js = JsonBuilder::try_new_object().unwrap();
        assert!(log(&tx, &mut js, true).is_ok());
    }
}
