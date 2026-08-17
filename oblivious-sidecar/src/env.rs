//! Environment parsing shared by the `obsd` and `pingd` binaries.
//!
//! It lives in the library rather than in each binary for two reasons. The logic was duplicated
//! byte-for-byte (including its safety comment), so a hardening fix had to be applied twice and the
//! copies would drift. And a parse inlined in `main` is unreachable from Rust unit tests, which left
//! the fail-closed behaviour below — the whole point of these helpers — with no test at all.

/// How a 32-byte key env var resolved.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyVar {
    /// The variable was not set. The caller may fall back to a dev key, but must SAY SO.
    Unset,
    /// The variable was set and parsed to 32 bytes.
    Parsed(Box<[u8; 32]>),
    /// The variable was set but is not 64 hex chars. FAIL — see [`hex_key_var`].
    Malformed,
}

/// Parse a 64-hex-char value into a 32-byte key, distinguishing UNSET from MALFORMED.
///
/// That distinction is the point. Collapsing them — `hex_key(var).unwrap_or(DEV_KEY)`, which both
/// binaries previously did — means a one-character typo in `PINGD_NOTIFY_KEY` silently runs the
/// notify front on the hardcoded dev key published in this source. The process starts clean, logs
/// nothing wrong, and `NotificationServer::signal` deliberately returns a uniform `SignalResponse`
/// for tokens it cannot open, so it also ACKs every signal while delivering no bits at all — and
/// anyone reading the repo can forge a bit for any label. A caller must therefore treat
/// [`KeyVar::Malformed`] as fatal, exactly as an unknown `OBSD_SERVICES` value is fatal.
pub fn hex_key_var(value: Option<&str>) -> KeyVar {
    match value {
        None => KeyVar::Unset,
        // is_ascii ensures 1 byte per char, so the slicing below cannot split a char.
        Some(s) if s.len() == 64 && s.is_ascii() => {
            let mut out = [0u8; 32];
            for (i, byte) in out.iter_mut().enumerate() {
                match u8::from_str_radix(&s[2 * i..2 * i + 2], 16) {
                    Ok(b) => *byte = b,
                    Err(_) => return KeyVar::Malformed,
                }
            }
            KeyVar::Parsed(Box::new(out))
        }
        Some(_) => KeyVar::Malformed,
    }
}

/// Which services `obsd` should serve. `Ok(true)` = store + notify, `Ok(false)` = store only.
///
/// An unrecognised value is an ERROR, never a default: a typo in a deployment unit
/// (`OBSD_SERVICES=stor`) would otherwise re-co-host the notify front and silently reinstate the
/// write↔bit correlation the split exists to remove — a privacy regression that starts up clean.
pub fn serve_notify(value: Option<&str>) -> Result<bool, String> {
    match value {
        None | Some("both") => Ok(true),
        Some("store") => Ok(false),
        Some(other) => Err(format!(
            "OBSD_SERVICES must be `both` or `store`, got `{other}`"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_notify_accepts_the_two_valid_roles_and_the_default() {
        assert_eq!(serve_notify(None), Ok(true));
        assert_eq!(serve_notify(Some("both")), Ok(true));
        assert_eq!(serve_notify(Some("store")), Ok(false));
    }

    #[test]
    fn serve_notify_rejects_anything_else_rather_than_defaulting() {
        // `stor` is the typo that matters: defaulting it to `both` re-co-hosts the notify front.
        for bad in ["stor", "", "STORE", "store ", "notify", "both,store"] {
            assert!(
                serve_notify(Some(bad)).is_err(),
                "OBSD_SERVICES=`{bad}` must be rejected, not defaulted"
            );
        }
    }

    #[test]
    fn hex_key_var_reports_unset_separately_from_malformed() {
        assert_eq!(hex_key_var(None), KeyVar::Unset);
    }

    #[test]
    fn hex_key_var_parses_64_hex_chars() {
        let key = "00".repeat(31) + "ff";
        match hex_key_var(Some(&key)) {
            KeyVar::Parsed(k) => {
                assert_eq!(k[31], 0xff);
                assert_eq!(k[0], 0x00);
            }
            other => panic!("expected Parsed, got {other:?}"),
        }
    }

    #[test]
    fn hex_key_var_rejects_every_malformed_shape() {
        for bad in [
            &"ab".repeat(31) as &str,  // 62 chars — too short
            &"ab".repeat(33),          // 66 chars — too long
            &("ab".repeat(31) + "zz"), // right length, non-hex
            &("ab".repeat(31) + "a "), // right length, trailing space
            &("ab".repeat(31) + "é"),  // non-ascii (also not 64 bytes)
            "",
        ] {
            assert_eq!(
                hex_key_var(Some(bad)),
                KeyVar::Malformed,
                "`{bad}` must be Malformed, not silently replaced by a dev key"
            );
        }
    }
}
