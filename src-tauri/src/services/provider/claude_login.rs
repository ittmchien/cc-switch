//! Each Claude Code official card keeps its own OAuth login (issue #4850).
//!
//! Claude Code keeps the login in two places: the credential store (`claudeAiOauth` in the
//! macOS Keychain item `Claude Code-credentials`, or `~/.claude/.credentials.json` elsewhere)
//! and the account profile (`oauthAccount` in `~/.claude.json`). Official cards store nothing
//! account-specific in their row, so switching between two of them used to change nothing.
//!
//! Like the Codex login stash, the logins live on this device only
//! (`~/.cc-switch/claude-login-stash.json`, 0600, never synced), keyed by card id; `active`
//! records which card the live login belongs to. On a switch the live login is saved under its
//! owner, then the target card's saved login is put back, or the live login is cleared so
//! Claude Code asks to sign in (the next switch saves the new login under that card). Other
//! credential keys (`mcpOAuth`, ...) and all other `~/.claude.json` keys are left untouched.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::get_claude_mcp_path;
use crate::error::AppError;
use crate::live::engine::{read_current, DeviceStore};
use crate::live::patch::json::{self, JsonPatch};
use crate::live::patch::KeyPath;

pub(crate) const STASH_FILENAME: &str = "claude-login-stash.json";
const OAUTH_KEY: &str = "claudeAiOauth";
const ACCOUNT_KEY: &str = "oauthAccount";

/// One card's login: the credential entry and the account profile Claude Code shows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Login {
    #[serde(rename = "claudeAiOauth")]
    pub oauth: Value,
    #[serde(
        rename = "oauthAccount",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub account: Option<Value>,
}

impl Login {
    pub fn email(&self) -> Option<&str> {
        self.account
            .as_ref()
            .and_then(|account| account.get("emailAddress"))
            .and_then(Value::as_str)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct LoginStash {
    #[serde(default)]
    pub logins: BTreeMap<String, Login>,
    /// The official card the live login belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
}

/// What a switch does to the live login.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum LiveAction {
    Keep,
    Clear,
    Write(Login),
}

impl LiveAction {
    /// Patch for the credential JSON: only `claudeAiOauth` changes.
    pub fn credentials_patch(&self) -> Option<JsonPatch> {
        self.patch(OAUTH_KEY, |login| Some(login.oauth.clone()))
    }

    /// Patch for `~/.claude.json`: only `oauthAccount` changes.
    pub fn account_patch(&self) -> Option<JsonPatch> {
        self.patch(ACCOUNT_KEY, |login| login.account.clone())
    }

    fn patch(&self, key: &str, value: impl Fn(&Login) -> Option<Value>) -> Option<JsonPatch> {
        let key_path = KeyPath::new(&[key]);
        let value = match self {
            Self::Keep => return None,
            Self::Clear => None,
            Self::Write(login) => value(login),
        };
        Some(match value {
            Some(value) => JsonPatch {
                set: vec![(key_path, value)],
                ..JsonPatch::default()
            },
            None => JsonPatch {
                remove: vec![key_path],
                ..JsonPatch::default()
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Plan {
    pub live: LiveAction,
    pub stash: LoginStash,
}

/// The live login, if Claude Code is signed in (`claudeAiOauth` present).
pub(crate) fn live_login(credentials: &Value, claude_json: &Value) -> Option<Login> {
    let oauth = credentials.get(OAUTH_KEY).filter(|v| !v.is_null())?;
    Some(Login {
        oauth: oauth.clone(),
        account: claude_json
            .get(ACCOUNT_KEY)
            .filter(|v| !v.is_null())
            .cloned(),
    })
}

/// Pure switch plan. `owner` is the official card the live login belongs to (see
/// [`owner`]); `target` is the target card id when it is an official card.
pub(crate) fn plan(
    live: Option<&Login>,
    owner: Option<&str>,
    target: Option<&str>,
    mut stash: LoginStash,
) -> Plan {
    // Save the live login under its owner; signed out means its saved login is gone too.
    if let Some(owner) = owner {
        match live {
            Some(login) => {
                stash.logins.insert(owner.to_string(), login.clone());
            }
            None => {
                stash.logins.remove(owner);
            }
        }
    }
    stash.active = owner.map(str::to_string);

    // Third-party target: its env key overrides the login, which stays where it is.
    let Some(target) = target else {
        return Plan {
            live: LiveAction::Keep,
            stash,
        };
    };
    let live = if owner == Some(target) {
        LiveAction::Keep
    } else if let Some(saved) = stash.logins.get(target) {
        LiveAction::Write(saved.clone())
    } else if owner.is_some() {
        // The live login is another card's (saved above): sign out so Claude Code asks to log in.
        LiveAction::Clear
    } else {
        // Nobody owns the live login yet (state before #4850): the target adopts it.
        LiveAction::Keep
    };
    stash.active = Some(target.to_string());
    Plan { live, stash }
}

/// Who the live login belongs to: the recorded card while it still exists as an official
/// card, otherwise the official card being switched away from.
pub(crate) fn owner(
    stash: &LoginStash,
    is_official_card: impl Fn(&str) -> bool,
    prev_official: Option<&str>,
) -> Option<String> {
    stash
        .active
        .as_deref()
        .filter(|id| is_official_card(id))
        .or(prev_official)
        .map(str::to_string)
}

pub(crate) fn parse_stash(
    path: &std::path::Path,
    bytes: Option<&[u8]>,
) -> Result<LoginStash, AppError> {
    let Some(bytes) = bytes else {
        return Ok(LoginStash::default());
    };
    // A broken stash may still hold logins: stop instead of overwriting it.
    serde_json::from_slice(bytes).map_err(|err| {
        AppError::Message(format!(
            "The Claude login stash {} cannot be parsed ({}). Repair or move the file away and try again. Nothing was written",
            path.display(),
            json_error_position(&err)
        ))
    })
}

/// The live credential JSON (Keychain data or `.credentials.json`); missing is `{}`.
pub(crate) fn parse_credentials(bytes: Option<&[u8]>) -> Result<Value, AppError> {
    let Some(bytes) = bytes else {
        return Ok(Value::Object(serde_json::Map::new()));
    };
    let value: Value = serde_json::from_slice(bytes).map_err(|err| {
        AppError::Message(format!(
            "The Claude Code login cannot be parsed ({}). Nothing was written",
            json_error_position(&err)
        ))
    })?;
    if !value.is_object() {
        return Err(AppError::Message(
            "The Claude Code login is not a JSON object. Nothing was written".into(),
        ));
    }
    Ok(value)
}

/// #4850: serde messages can quote the offending value (a token), so errors only carry the
/// error kind and position.
fn json_error_position(err: &serde_json::Error) -> String {
    format!(
        "{:?} error at line {}, column {}",
        err.classify(),
        err.line(),
        err.column()
    )
}

/// Email of each official card's login (card id → email), for the provider cards. The active
/// card's login is live, so its email comes from `~/.claude.json`.
pub(crate) fn account_emails() -> Result<BTreeMap<String, String>, AppError> {
    let path = DeviceStore::for_device().file(STASH_FILENAME);
    let stash = parse_stash(&path, read_current(&path)?.as_deref())?;
    let mut emails: BTreeMap<String, String> = stash
        .logins
        .iter()
        .filter_map(|(id, login)| Some((id.clone(), login.email()?.to_string())))
        .collect();
    if let Some(active) = &stash.active {
        let claude_json_path = get_claude_mcp_path();
        let claude_json = json::parse(
            &claude_json_path,
            read_current(&claude_json_path)?.as_deref(),
        )?
        .0;
        match claude_json
            .pointer("/oauthAccount/emailAddress")
            .and_then(Value::as_str)
        {
            Some(email) => emails.insert(active.clone(), email.to_string()),
            None => emails.remove(active),
        };
    }
    Ok(emails)
}

/// macOS Keychain access through `/usr/bin/security` with plain argv (#4850). Claude Code
/// creates and rewrites the item with this tool, so the item's access list trusts only it:
/// native Security framework calls from CC Switch prompt on every access. `security -i` is not
/// used either: its ~4 KB line limit split large values into several commands.
/// Errors carry only the operation and the exit code, never argv, output or item data.
#[cfg(target_os = "macos")]
pub(crate) mod keychain {
    use std::process::{Command, Output};

    use crate::error::AppError;

    pub const SERVICE: &str = "Claude Code-credentials";
    /// `security` exit code for "item not found".
    const NOT_FOUND: i32 = 44;

    /// The item's data; `None` when there is no item.
    pub fn read() -> Result<Option<Vec<u8>>, AppError> {
        let output = run(
            "read",
            &[
                "find-generic-password",
                "-a",
                &account()?,
                "-s",
                SERVICE,
                "-w",
            ],
        )?;
        if output.status.code() == Some(NOT_FOUND) {
            return Ok(None);
        }
        check("read", &output)?;
        Ok(Some(decode_printed(output.stdout)))
    }

    /// Create or replace the item's data. Accepted trade-off (same as Claude Code): the hex
    /// is briefly visible in this user's process list while `security` runs; never logged.
    pub fn write(data: &[u8]) -> Result<(), AppError> {
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        let output = run(
            "write",
            &[
                "add-generic-password",
                "-U",
                "-a",
                &account()?,
                "-s",
                SERVICE,
                "-X",
                &hex,
            ],
        )?;
        check("write", &output)
    }

    /// Delete the item; a missing item is not an error.
    pub fn delete() -> Result<(), AppError> {
        let output = run(
            "delete",
            &["delete-generic-password", "-a", &account()?, "-s", SERVICE],
        )?;
        if output.status.code() == Some(NOT_FOUND) {
            return Ok(());
        }
        check("delete", &output)
    }

    /// `-w` prints the data as-is, or as hex when it is not printable (multi-line, non-UTF-8).
    pub(super) fn decode_printed(mut stdout: Vec<u8>) -> Vec<u8> {
        while stdout.last().is_some_and(u8::is_ascii_whitespace) {
            stdout.pop();
        }
        let is_hex =
            !stdout.is_empty() && stdout.len() % 2 == 0 && stdout.iter().all(u8::is_ascii_hexdigit);
        if !is_hex || serde_json::from_slice::<serde_json::Value>(&stdout).is_ok() {
            return stdout;
        }
        stdout
            .chunks(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("ASCII hex digits");
                u8::from_str_radix(text, 16).expect("hex digits")
            })
            .collect()
    }

    /// Claude Code names the item's account after the login user.
    fn account() -> Result<String, AppError> {
        std::env::var("USER")
            .ok()
            .filter(|user| !user.is_empty())
            .ok_or_else(|| {
                AppError::Message("USER is not set; cannot address the Keychain item".into())
            })
    }

    fn run(operation: &str, args: &[&str]) -> Result<Output, AppError> {
        Command::new("/usr/bin/security")
            .args(args)
            .output()
            .map_err(|_| failed(operation, None))
    }

    fn check(operation: &str, output: &Output) -> Result<(), AppError> {
        if output.status.success() {
            return Ok(());
        }
        Err(failed(operation, output.status.code()))
    }

    pub(super) fn failed(operation: &str, code: Option<i32>) -> AppError {
        let code = code.map_or_else(|| "none".to_string(), |code| code.to_string());
        AppError::Message(format!(
            "Keychain {operation} of the Claude Code login failed (security exit code {code})"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::patch::LivePatch;
    use serde_json::json;
    use std::path::Path;

    fn login(who: &str) -> Login {
        Login {
            oauth: json!({"accessToken": format!("access-{who}"), "refreshToken": format!("refresh-{who}")}),
            account: Some(
                json!({"emailAddress": format!("{who}@example.com"), "accountUuid": who}),
            ),
        }
    }

    fn stash(logins: &[(&str, Login)], active: Option<&str>) -> LoginStash {
        LoginStash {
            logins: logins
                .iter()
                .map(|(id, login)| (id.to_string(), login.clone()))
                .collect(),
            active: active.map(str::to_string),
        }
    }

    #[test]
    fn switching_to_a_card_with_a_saved_login_saves_the_live_one_and_restores_it() {
        let alice = login("alice");
        let bob = login("bob");
        let plan = plan(
            Some(&alice),
            Some("a"),
            Some("b"),
            stash(&[("b", bob.clone())], Some("a")),
        );
        assert_eq!(plan.live, LiveAction::Write(bob.clone()));
        assert_eq!(plan.stash, stash(&[("a", alice), ("b", bob)], Some("b")));
    }

    #[test]
    fn switching_to_a_card_without_a_login_signs_out_after_saving_the_live_one() {
        let alice = login("alice");
        let plan = plan(Some(&alice), Some("a"), Some("b"), LoginStash::default());
        assert_eq!(plan.live, LiveAction::Clear);
        assert_eq!(plan.stash, stash(&[("a", alice)], Some("b")));
    }

    #[test]
    fn a_card_that_signed_out_loses_its_saved_login() {
        let bob = login("bob");
        let old_alice = login("alice");
        let plan = plan(
            None,
            Some("a"),
            Some("b"),
            stash(&[("a", old_alice), ("b", bob.clone())], Some("a")),
        );
        assert_eq!(plan.live, LiveAction::Write(bob.clone()));
        assert_eq!(plan.stash, stash(&[("b", bob)], Some("b")));
    }

    #[test]
    fn third_party_target_keeps_the_live_login_and_its_owner() {
        let alice = login("alice");
        let plan = plan(Some(&alice), Some("a"), None, LoginStash::default());
        assert_eq!(plan.live, LiveAction::Keep);
        assert_eq!(plan.stash, stash(&[("a", alice)], Some("a")));
    }

    #[test]
    fn back_from_third_party_to_the_owner_keeps_the_login() {
        let alice = login("alice");
        let plan = plan(
            Some(&alice),
            Some("a"),
            Some("a"),
            stash(&[("a", alice.clone())], Some("a")),
        );
        assert_eq!(plan.live, LiveAction::Keep);
        assert_eq!(plan.stash, stash(&[("a", alice)], Some("a")));
    }

    #[test]
    fn unowned_live_login_is_adopted_by_the_target() {
        // Pre-#4850 state: third-party → official with no stash must not sign the user out.
        let alice = login("alice");
        let plan = plan(Some(&alice), None, Some("a"), LoginStash::default());
        assert_eq!(plan.live, LiveAction::Keep);
        assert_eq!(plan.stash, stash(&[], Some("a")));
    }

    #[test]
    fn owner_falls_back_to_the_previous_official_card_when_the_recorded_one_is_gone() {
        let recorded = stash(&[], Some("deleted"));
        assert_eq!(
            owner(&recorded, |id| id == "a", Some("a")).as_deref(),
            Some("a")
        );
        assert_eq!(owner(&recorded, |id| id == "a", None), None);
        let alive = stash(&[], Some("a"));
        assert_eq!(
            owner(&alive, |id| id == "a", Some("b")).as_deref(),
            Some("a")
        );
    }

    #[test]
    fn live_login_needs_claude_ai_oauth() {
        let creds = json!({"mcpOAuth": {"srv": {"accessToken": "m"}}});
        assert_eq!(live_login(&creds, &json!({"oauthAccount": {}})), None);
        let creds = json!({"claudeAiOauth": {"accessToken": "t"}, "mcpOAuth": {}});
        let got = live_login(&creds, &json!({"oauthAccount": {"emailAddress": "x@y"}})).unwrap();
        assert_eq!(got.email(), Some("x@y"));
    }

    #[test]
    fn patches_only_touch_their_own_key() {
        let bob = login("bob");
        let path = Path::new("creds.json");
        let creds =
            br#"{"claudeAiOauth":{"accessToken":"old"},"mcpOAuth":{"srv":{"accessToken":"m"}}}"#;
        let claude_json =
            br#"{"numStartups":3,"oauthAccount":{"emailAddress":"old@x"},"projects":{}}"#;

        let write = LiveAction::Write(bob.clone());
        let out: Value = serde_json::from_slice(
            &write
                .credentials_patch()
                .unwrap()
                .apply(path, Some(creds))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            out,
            json!({"claudeAiOauth": bob.oauth, "mcpOAuth": {"srv": {"accessToken": "m"}}})
        );
        let out: Value = serde_json::from_slice(
            &write
                .account_patch()
                .unwrap()
                .apply(path, Some(claude_json))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            out,
            json!({"numStartups": 3, "oauthAccount": bob.account, "projects": {}})
        );

        let clear = LiveAction::Clear;
        let out: Value = serde_json::from_slice(
            &clear
                .credentials_patch()
                .unwrap()
                .apply(path, Some(creds))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(out, json!({"mcpOAuth": {"srv": {"accessToken": "m"}}}));
        let out: Value = serde_json::from_slice(
            &clear
                .account_patch()
                .unwrap()
                .apply(path, Some(claude_json))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(out, json!({"numStartups": 3, "projects": {}}));

        // A saved login without a profile removes the stale one.
        let bare = LiveAction::Write(Login {
            account: None,
            ..bob
        });
        let out: Value = serde_json::from_slice(
            &bare
                .account_patch()
                .unwrap()
                .apply(path, Some(claude_json))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(out, json!({"numStartups": 3, "projects": {}}));

        assert!(LiveAction::Keep.credentials_patch().is_none());
        assert!(LiveAction::Keep.account_patch().is_none());
    }

    #[test]
    fn parse_errors_never_quote_the_data() {
        let path = Path::new("stash.json");
        let stash = br#"{"logins":{"a":"sk-ant-secret-token"}}"#;
        let err = parse_stash(path, Some(stash)).unwrap_err().to_string();
        assert!(!err.contains("sk-ant-secret-token"), "{err}");
        let err = parse_credentials(Some(b"\"sk-ant-secret-token\""))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("sk-ant-secret-token"), "{err}");
        let err = parse_credentials(Some(b"{\"claudeAiOauth\": sk-ant-secret-token}"))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("sk-ant-secret-token"), "{err}");
        assert_eq!(parse_credentials(None).unwrap(), json!({}));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_errors_carry_only_the_operation_and_status() {
        assert_eq!(
            keychain::failed("write", Some(45)).to_string(),
            "Keychain write of the Claude Code login failed (security exit code 45)"
        );
        assert_eq!(
            keychain::failed("read", None).to_string(),
            "Keychain read of the Claude Code login failed (security exit code none)"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_output_printed_as_hex_is_decoded() {
        let data = b"{\n  \"claudeAiOauth\": {}\n}".to_vec();
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            keychain::decode_printed(format!("{hex}\n").into_bytes()),
            data
        );
        let plain = br#"{"claudeAiOauth":{}}"#.to_vec();
        assert_eq!(
            keychain::decode_printed([plain.clone(), b"\n".to_vec()].concat()),
            plain
        );
        // Valid JSON made only of hex digits (a number) stays as printed.
        assert_eq!(keychain::decode_printed(b"12".to_vec()), b"12".to_vec());
    }

    #[test]
    fn broken_stash_is_an_error_not_an_empty_stash() {
        let path = Path::new("stash.json");
        assert!(parse_stash(path, Some(b"{not json")).is_err());
        assert_eq!(parse_stash(path, None).unwrap(), LoginStash::default());
        let round = serde_json::to_vec(&stash(&[("a", login("a"))], Some("a"))).unwrap();
        assert_eq!(
            parse_stash(path, Some(&round)).unwrap(),
            stash(&[("a", login("a"))], Some("a"))
        );
    }
}
