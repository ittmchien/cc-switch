//! 写 Claude Code 的 `settings.json`：只替换关键字段和独有字段，其余字节不碰。
//!
//! 写 Claude live 的入口（切换、新增第一个供应商、编辑当前供应商、同步、统一供应商、
//! 进入 / 退出代理）都走这里：先拿应用写锁，再经 `mode::operation` 记下 pending、发布。
//! 不回填、不合并通用配置片段、不注入上下文默认值：用户的设置本来就留在 live 里。

use std::path::{Path, PathBuf};

use crate::app_config::AppType;
use crate::config::{get_claude_config_dir, get_claude_mcp_path, get_claude_settings_path};
use crate::database::Database;
use crate::error::AppError;
use crate::live::engine::{digest, read_current, LiveFile};
use crate::live::patch::json::{self, JsonPatch};
use crate::live::patch::{Guarded, WholeFile};
use crate::live::project::claude::{direct_patch, ClaudeProjection};
use crate::mode::operation::{AppWrite, FileChange, OperationReport};
use crate::mode::state::{op, PendingTarget};
use crate::provider::Provider;

use super::claude_login::{self, LiveAction};

fn app() -> &'static str {
    AppType::Claude.as_str()
}

/// `settings.json`（旧安装可能是 `claude.json`）。里面有 Key，按 0600 写。
pub(crate) fn settings_file() -> LiveFile {
    LiveFile::private(get_claude_settings_path())
}

/// 从 `prev` 切到 `target`：同一个操作里写 live、再把当前供应商改成 `target`。
///
/// `prev` 是 live 现在对应的供应商（直连指针指向的那家），用来删它带进来的独有字段。
pub(crate) fn switch_to(
    db: &Database,
    prev: Option<&Provider>,
    target: &Provider,
) -> Result<OperationReport, AppError> {
    // #4850: switches that touch an official card also swap the OAuth login.
    let prev_official = prev.filter(|provider| is_official(provider));
    if prev_official.is_none() && !is_official(target) {
        return write(db, prev, target, Some(&target.id));
    }
    switch_with_login(db, prev, prev_official, target)
}

/// Official card (Claude.ai login, no API key in the row).
pub(crate) fn is_official(provider: &Provider) -> bool {
    provider.category.as_deref() == Some("official")
}

/// Where Claude Code keeps `claudeAiOauth` on this device.
enum CredentialStore {
    File(PathBuf),
    #[cfg(target_os = "macos")]
    Keychain,
}

impl CredentialStore {
    /// macOS: the Keychain, unless only the plaintext fallback file exists. Tests (and test
    /// homes) always use the file so they never touch the real Keychain.
    fn detect() -> Result<(Self, Option<Vec<u8>>), AppError> {
        let file = get_claude_config_dir().join(".credentials.json");
        #[cfg(target_os = "macos")]
        {
            if !cfg!(test) && std::env::var_os("CC_SWITCH_TEST_HOME").is_none() {
                let item = claude_login::keychain::read()?;
                if item.is_some() || !file.exists() {
                    return Ok((Self::Keychain, item));
                }
            }
        }
        let pre = read_current(&file)?;
        Ok((Self::File(file), pre))
    }
}

/// Switch with `settings.json`, the credential file / `~/.claude.json` login keys and the
/// login stash committed in one operation. The Keychain is not a file: it is written first
/// and put back if the operation is dropped before publishing.
fn switch_with_login(
    db: &Database,
    prev: Option<&Provider>,
    prev_official: Option<&Provider>,
    target: &Provider,
) -> Result<OperationReport, AppError> {
    let patch = direct_patch(
        prev.map(|provider| ClaudeProjection::of(&provider.settings_config))
            .as_ref(),
        &ClaudeProjection::of(&target.settings_config),
    );
    let write = AppWrite::begin(db, app())?;

    let stash_path = write.store.file(claude_login::STASH_FILENAME);
    let stash_pre = read_current(&stash_path)?;
    let stash = claude_login::parse_stash(&stash_path, stash_pre.as_deref())?;
    let owner = claude_login::owner(
        &stash,
        |id| {
            db.get_provider_by_id(id, app())
                .ok()
                .flatten()
                .is_some_and(|provider| is_official(&provider))
        },
        prev_official.map(|provider| provider.id.as_str()),
    );

    let (store, credentials_pre) = CredentialStore::detect()?;
    let claude_json_path = get_claude_mcp_path();
    let claude_json_pre = read_current(&claude_json_path)?;
    let credentials = json::parse(Path::new(".credentials.json"), credentials_pre.as_deref())?.0;
    let claude_json = json::parse(&claude_json_path, claude_json_pre.as_deref())?.0;
    let live = claude_login::live_login(&credentials, &claude_json);

    let plan = claude_login::plan(
        live.as_ref(),
        owner.as_deref(),
        is_official(target).then_some(target.id.as_str()),
        stash.clone(),
    );
    // Nothing to clear in a file that does not exist: don't create an empty one.
    let skip_missing = |pre: &Option<Vec<u8>>| plan.live == LiveAction::Clear && pre.is_none();
    let credentials_patch = plan
        .live
        .credentials_patch()
        .filter(|_| !skip_missing(&credentials_pre));
    let account_patch = plan
        .live
        .account_patch()
        .filter(|_| !skip_missing(&claude_json_pre));
    let stash_patch = (plan.stash != stash)
        .then(|| {
            serde_json::to_vec_pretty(&plan.stash).map(|bytes| Guarded {
                expected_pre: digest(stash_pre.as_deref()),
                then: WholeFile::Write(bytes),
            })
        })
        .transpose()
        .map_err(|e| {
            AppError::Message(format!("Failed to serialize the Claude login stash: {e}"))
        })?;

    let mut changes = vec![FileChange {
        file: settings_file(),
        patch: &patch,
    }];
    #[cfg(target_os = "macos")]
    let mut keychain_pre = None;
    match (&store, &credentials_patch) {
        (CredentialStore::File(path), Some(patch)) => changes.push(FileChange {
            file: LiveFile::private(path),
            patch,
        }),
        #[cfg(target_os = "macos")]
        (CredentialStore::Keychain, Some(patch)) => {
            // Compact JSON: `security -w` prints multi-line data as hex, which Claude Code
            // would not parse.
            let mut next = credentials.clone();
            patch.apply_to(Path::new(".credentials.json"), &mut next)?;
            if next != credentials {
                let bytes = serde_json::to_vec(&next).map_err(|e| {
                    AppError::Message(format!("Failed to serialize credentials: {e}"))
                })?;
                claude_login::keychain::write(&bytes)?;
                keychain_pre = Some(credentials_pre.clone());
            }
        }
        _ => {}
    }
    if let Some(patch) = &account_patch {
        changes.push(FileChange {
            file: LiveFile::shared(&claude_json_path),
            patch,
        });
    }
    if let Some(patch) = &stash_patch {
        changes.push(FileChange {
            file: LiveFile::private(&stash_path),
            patch,
        });
    }

    let result = write.run(
        op::SWITCH,
        &changes,
        PendingTarget::pointer(Some(target.id.clone())),
    );
    // Dropped before publishing (nothing pending to roll forward): put the Keychain back.
    #[cfg(target_os = "macos")]
    {
        if let (Err(err), Some(pre)) = (&result, keychain_pre) {
            if matches!(crate::mode::state::pending(&write.store, app()), Ok(None)) {
                let restored = match pre {
                    Some(bytes) => claude_login::keychain::write(&bytes),
                    None => claude_login::keychain::delete(),
                };
                if let Err(restore_err) = restored {
                    return Err(AppError::Message(format!(
                        "{err}; additionally failed to restore the Claude Code login in the Keychain: {restore_err}"
                    )));
                }
            }
        }
    }
    result
}

/// 把当前供应商 `target` 重新投影到 live，不改指针。`prev` 是 live 现在对应的那一版
/// 行（编辑前的行；没改过就是它自己）。
pub(crate) fn reapply(
    db: &Database,
    prev: Option<&Provider>,
    target: &Provider,
) -> Result<OperationReport, AppError> {
    write(db, prev, target, None)
}

fn write(
    db: &Database,
    prev: Option<&Provider>,
    target: &Provider,
    pointer: Option<&str>,
) -> Result<OperationReport, AppError> {
    let prev = prev.map(|provider| ClaudeProjection::of(&provider.settings_config));
    let patch = direct_patch(
        prev.as_ref(),
        &ClaudeProjection::of(&target.settings_config),
    );
    run(
        db,
        if pointer.is_some() {
            op::SWITCH
        } else {
            op::APPLY
        },
        Some(&patch),
        PendingTarget::pointer(pointer.map(str::to_string)),
    )
}

/// 用 `patch` 改写 `settings.json`，和 `target` 在同一个操作里提交；`patch` 为空时只
/// 落定状态、不读也不写文件。
pub(crate) fn run(
    db: &Database,
    op: &str,
    patch: Option<&JsonPatch>,
    target: PendingTarget,
) -> Result<OperationReport, AppError> {
    // 补丁是按调用方读到的指针算的（要删上一家的独有字段）：先补完上一次的操作。
    let write = AppWrite::begin(db, app())?;
    let changes: Vec<FileChange<'_>> = patch
        .into_iter()
        .map(|patch| FileChange {
            file: settings_file(),
            patch,
        })
        .collect();
    write.run(op, &changes, target)
}
