//! Environment parsing shared by the `obsd` and `pingd` binaries.
//!
//! It lives in the library rather than in each binary for two reasons. The logic was duplicated
//! byte-for-byte (including its safety comment), so a hardening fix had to be applied twice and the
//! copies would drift. And a parse inlined in `main` is unreachable from Rust unit tests, which left
//! the fail-closed behaviour below — the whole point of these helpers — with no test at all.
//!
//! Every function here takes its value as a parameter rather than reading the environment, so the
//! fail-closed branches are unit-testable without mutating process-global state. The `*_osvar`
//! wrappers are what the binaries actually call; see [`hex_key_osvar`] for why they take `OsStr`.

use std::ffi::OsStr;

/// How a 32-byte key env var resolved.
///
/// Deliberately NOT `#[derive(Debug, PartialEq, Eq)]`. A derived `Debug` would print the key bytes
/// at any `{:?}` — including from this module's own tests — and a derived `PartialEq` would compare
/// secret bytes in variable time, in a crate that reaches for `subtle` precisely to avoid that.
pub enum KeyVar {
    /// The variable was not set. The caller may fall back to a dev key, but must SAY SO.
    Unset,
    /// The variable was set and parsed to 32 bytes.
    ///
    /// Held inline, not boxed: a `Box` would put the key on the heap and the copy left behind when
    /// the caller moves the array out would be freed without being zeroized.
    Parsed([u8; 32]),
    /// The variable was set but is not 64 hex chars. FAIL — see [`hex_key_var`].
    Malformed,
}

impl std::fmt::Debug for KeyVar {
    /// Redacts the key. The whole point of the hand-written impl — a `{:?}` on a `Parsed` must never
    /// put key material in a log or a test failure message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyVar::Unset => f.write_str("Unset"),
            KeyVar::Parsed(_) => f.write_str("Parsed(<redacted>)"),
            KeyVar::Malformed => f.write_str("Malformed"),
        }
    }
}

/// Parse a 64-hex-char value into a 32-byte key, distinguishing UNSET from MALFORMED.
///
/// That distinction is the point. Collapsing them — `hex_key(var).unwrap_or(DEV_KEY)`, which both
/// binaries once did — means a one-character typo in `PINGD_NOTIFY_KEY` silently runs the notify
/// front on the hardcoded dev key published in this source. The process starts clean, logs nothing
/// wrong, and `NotificationServer::signal` deliberately returns a uniform `SignalResponse` for
/// tokens it cannot open, so it also ACKs every signal while delivering no bits at all — and anyone
/// reading the repo can forge a bit for any label. A caller must therefore treat
/// [`KeyVar::Malformed`] as fatal, exactly as an unknown `OBSD_SERVICES` value is fatal.
///
/// The alphabet is checked BEFORE conversion. `u8::from_str_radix` accepts a leading `+`, so the
/// pair `"+f"` would otherwise parse to `0x0f` and a value that is not 64 hex characters would be
/// silently normalised into a key byte — the exact set-but-invalid ⇒ don't-fail path this module
/// exists to close. (`-` is already rejected for unsigned types; only `+` slipped through.)
pub fn hex_key_var(value: Option<&str>) -> KeyVar {
    match value {
        None => KeyVar::Unset,
        // is_ascii_hexdigit implies ASCII, so 1 byte per char and the slicing cannot split a char.
        Some(s) if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) => {
            let mut out = [0u8; 32];
            for (i, byte) in out.iter_mut().enumerate() {
                match u8::from_str_radix(&s[2 * i..2 * i + 2], 16) {
                    Ok(b) => *byte = b,
                    Err(_) => return KeyVar::Malformed,
                }
            }
            KeyVar::Parsed(out)
        }
        Some(_) => KeyVar::Malformed,
    }
}

/// [`hex_key_var`] over a raw environment value.
///
/// Takes `OsStr` because `std::env::var(..).ok()` maps `VarError::NotUnicode` to `None`: a variable
/// that IS set but holds non-UTF-8 bytes would take the `Unset` branch and fall back to the dev key
/// — the precise failure this module fixes for the ASCII case, reachable by another route. Non-UTF-8
/// is set-but-invalid, so it is [`KeyVar::Malformed`], and `None` stays the only Unset path.
pub fn hex_key_osvar(value: Option<&OsStr>) -> KeyVar {
    match value {
        None => KeyVar::Unset,
        Some(v) => match v.to_str() {
            Some(s) => hex_key_var(Some(s)),
            None => KeyVar::Malformed,
        },
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

/// [`serve_notify`] over a raw environment value. Non-UTF-8 is set-but-invalid and fails closed
/// rather than yielding `Ok(true)` and re-co-hosting the notify front — see [`hex_key_osvar`].
pub fn serve_notify_osvar(value: Option<&OsStr>) -> Result<bool, String> {
    match value {
        None => serve_notify(None),
        Some(v) => match v.to_str() {
            Some(s) => serve_notify(Some(s)),
            None => Err("OBSD_SERVICES is set but is not valid UTF-8".to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

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
    fn serve_notify_osvar_fails_closed_on_non_utf8() {
        // A set-but-non-UTF-8 value must NOT reach the `None => Ok(true)` default.
        let raw = OsStr::from_bytes(&[0x73, 0x74, 0xff, 0x6f]); // "st\xffo"
        assert!(
            serve_notify_osvar(Some(raw)).is_err(),
            "non-UTF-8 OBSD_SERVICES must fail closed, not re-co-host the notify front"
        );
        assert_eq!(serve_notify_osvar(None), Ok(true));
    }

    #[test]
    fn hex_key_var_reports_unset_separately_from_malformed() {
        assert!(matches!(hex_key_var(None), KeyVar::Unset));
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
            &("ab".repeat(31) + "+f"), // right length, leading `+` — from_str_radix ACCEPTS this
            &("ab".repeat(31) + "-1"), // right length, leading `-`
            &("ab".repeat(31) + "é"),  // non-ascii (also not 64 bytes)
            "",
        ] {
            assert!(
                matches!(hex_key_var(Some(bad)), KeyVar::Malformed),
                "`{bad}` must be Malformed, not silently replaced by a dev key"
            );
        }
    }

    #[test]
    fn hex_key_osvar_treats_non_utf8_as_malformed_not_unset() {
        // Set-but-non-UTF-8 must be fatal, not a silent fall-back to the published dev key.
        let raw = OsStr::from_bytes(&[0xff; 64]);
        assert!(matches!(hex_key_osvar(Some(raw)), KeyVar::Malformed));
        assert!(matches!(hex_key_osvar(None), KeyVar::Unset));
    }

    #[test]
    fn key_var_debug_never_prints_key_material() {
        let k = hex_key_var(Some(&("ab".repeat(32))));
        assert_eq!(format!("{k:?}"), "Parsed(<redacted>)");
        assert!(!format!("{k:?}").contains("ab"));
    }
}
