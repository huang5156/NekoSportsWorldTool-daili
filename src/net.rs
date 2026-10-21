//! 出站代理：单条代理 / 按账号稳定分配的代理池。
//!
//! 目的：多账号时不共用同一个出口 IP。出口选择优先级：
//!
//!   1. 环境变量 `NSWT_PROXY`（青龙等容器里最方便）
//!   2. `config.json` 的 `proxy`
//!   3. `config.json` 的 `proxy_pool` —— 按账号名哈希稳定取一条，同一账号永远走同一出口
//!
//! 只影响本程序发起的 HTTP(S) 请求，不改变任何协议字段或设备指纹。

use std::sync::Mutex;
use std::time::Duration;

/// 单条代理覆盖（优先级最高）。
pub const ENV_PROXY: &str = "NSWT_PROXY";
/// 代理池覆盖（逗号/分号/换行分隔）。
pub const ENV_PROXY_POOL: &str = "NSWT_PROXY_POOL";

/// 默认连通性探测地址；返回出口 IP，便于确认代理真的生效。
pub const PROBE_URL: &str = "https://api.ipify.org?format=json";

const AGENT_TIMEOUT: Duration = Duration::from_secs(30);

static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn set_error(message: String) {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        slot.replace(message);
    }
}

/// 最近一次代理配置错误（界面/日志用来提示，成功后清空）。
pub fn last_error() -> Option<String> {
    LAST_ERROR.lock().ok().and_then(|slot| slot.clone())
}

pub fn clear_error() {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        slot.take();
    }
}

fn env_proxy() -> Option<String> {
    std::env::var(ENV_PROXY).ok().filter(|v| !v.trim().is_empty())
}

fn env_pool() -> Option<String> {
    std::env::var(ENV_PROXY_POOL)
        .ok()
        .filter(|v| !v.trim().is_empty())
}

/// 拆分代理池文本：逗号、分号、换行都算分隔符。
fn split_list(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| c == ',' || c == ';' || c == '\n' || c == '\r')
        .map(str::trim)
}

/// 把用户输入规范成 ureq 可接受的形式。
///
/// 接受 `host:port`、`http://`、`https://`、`socks5://`，以及常见别名 `socks5h://`；
/// 拒绝 socks4 和未知协议，并要求带端口（否则几乎必然连错）。
pub fn normalize(spec: &str) -> Result<String, String> {
    let raw = spec.trim();
    if raw.is_empty() {
        return Err("代理地址为空".into());
    }
    if raw.chars().any(char::is_whitespace) {
        return Err("代理地址不能包含空白字符".into());
    }
    let lower = raw.to_ascii_lowercase();
    let normalized = if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("socks5://")
    {
        raw.to_string()
    } else if let Some(rest) = lower
        .starts_with("socks5h://")
        .then(|| &raw["socks5h://".len()..])
    {
        // socks5h 只是“远端解析 DNS”的约定写法，ureq 统一按 socks5 处理。
        format!("socks5://{rest}")
    } else if let Some((scheme, _)) = raw.split_once("://") {
        return Err(format!(
            "不支持的代理协议 {scheme}://，请用 http:// 或 socks5://"
        ));
    } else {
        format!("http://{raw}")
    };

    let authority = normalized
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(normalized.as_str());
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if host_port.is_empty() || !host_port.contains(':') {
        return Err(format!("代理地址需要 host:port，例如 127.0.0.1:7890（收到 {}）", mask(&normalized)));
    }
    Ok(normalized)
}

/// 隐藏代理里的账号密码，用于日志和界面展示。
pub fn mask(spec: &str) -> String {
    match spec.rsplit_once('@') {
        Some((before, host)) => {
            let scheme = before.split_once("://").map(|(s, _)| s).unwrap_or("");
            if scheme.is_empty() {
                format!("***@{host}")
            } else {
                format!("{scheme}://***@{host}")
            }
        }
        None => spec.to_string(),
    }
}

/// config.json 里配置的单条代理（环境变量优先）。无效时记录错误并视为未配置。
pub fn configured() -> Option<String> {
    if let Some(raw) = env_proxy() {
        return match normalize(&raw) {
            Ok(value) => Some(value),
            Err(e) => {
                let message = format!("环境变量 {ENV_PROXY} 无效：{e}");
                eprintln!("[proxy] {message}，已退回直连");
                set_error(message);
                None
            }
        };
    }
    let config = crate::api::model::load_config();
    if config.proxy.trim().is_empty() {
        return None;
    }
    match normalize(&config.proxy) {
        Ok(value) => Some(value),
        Err(e) => {
            let message = format!("代理配置无效：{e}");
            eprintln!("[proxy] {message}，已退回直连");
            set_error(message);
            None
        }
    }
}

/// 代理池（环境变量优先），已规范化并去重。
pub fn pool() -> Vec<String> {
    let raw = match env_pool() {
        Some(value) => value,
        None => {
            let config = crate::api::model::load_config();
            if config.proxy_pool.trim().is_empty() {
                return Vec::new();
            }
            config.proxy_pool
        }
    };
    let mut out: Vec<String> = Vec::new();
    for part in split_list(&raw) {
        if part.is_empty() {
            continue;
        }
        match normalize(part) {
            Ok(value) => {
                if !out.iter().any(|seen| seen == &value) {
                    out.push(value);
                }
            }
            Err(e) => set_error(format!("代理池条目「{part}」无效：{e}")),
        }
    }
    out
}

/// FNV-1a：跨版本稳定的账号 → 代理索引映射（不用 std 的随机化哈希）。
fn hash64(text: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// 为某个账号选出口：单条代理 > 代理池按账号哈希 > 直连。
pub fn for_account(account: Option<&str>) -> Option<String> {
    if let Some(explicit) = configured() {
        return Some(explicit);
    }
    let candidates = pool();
    if candidates.is_empty() {
        return None;
    }
    let key = account.unwrap_or_default().trim();
    let index = (hash64(key) % candidates.len() as u64) as usize;
    Some(candidates[index].clone())
}

/// 构建带代理的 Agent；`proxy` 为 None 表示直连。
pub fn agent_with(proxy: Option<&str>, timeout: Duration) -> Result<ureq::Agent, String> {
    let mut builder = ureq::AgentBuilder::new().timeout(timeout);
    if let Some(spec) = proxy.map(str::trim).filter(|spec| !spec.is_empty()) {
        let parsed = ureq::Proxy::new(spec)
            .map_err(|e| format!("代理地址无效（{}）：{e}", mask(spec)))?;
        builder = builder.proxy(parsed);
    }
    Ok(builder.build())
}

/// 按当前配置构建 Agent。代理无效时退回直连并记录错误，避免整个程序不可用。
pub fn agent(timeout: Duration) -> ureq::Agent {
    match agent_with(configured().as_deref(), timeout) {
        Ok(agent) => agent,
        Err(e) => {
            set_error(e.clone());
            eprintln!("[proxy] {e}，已退回直连");
            ureq::AgentBuilder::new().timeout(timeout).build()
        }
    }
}

/// 默认超时的 Agent（协议层/更新/上传共用）。
pub fn default_agent() -> ureq::Agent {
    agent(AGENT_TIMEOUT)
}

/// 一行描述当前出口，供界面展示。
pub fn describe(account: Option<&str>) -> String {
    match for_account(account) {
        Some(proxy) => format!("代理 {}", mask(&proxy)),
        None => {
            if pool().is_empty() {
                "直连（未配置代理）".to_string()
            } else {
                "直连（代理池未命中）".to_string()
            }
        }
    }
}

/// 校验并保存代理设置到 config.json；返回规范化后的 (proxy, pool)。
pub fn save(proxy: &str, pool_text: &str) -> Result<(String, String), String> {
    let normalized_proxy = if proxy.trim().is_empty() {
        String::new()
    } else {
        normalize(proxy)?
    };
    let mut entries: Vec<String> = Vec::new();
    for part in split_list(pool_text) {
        if part.is_empty() {
            continue;
        }
        let value = normalize(part)?;
        if !entries.iter().any(|seen| seen == &value) {
            entries.push(value);
        }
    }
    let normalized_pool = entries.join(", ");
    let mut config = crate::api::model::load_config();
    config.proxy = normalized_proxy.clone();
    config.proxy_pool = normalized_pool.clone();
    crate::api::model::save_config(&config)?;
    clear_error();
    Ok((normalized_proxy, normalized_pool))
}

/// 通过指定代理（None = 直连）探测出口，返回状态码和响应摘要。
pub fn probe(proxy: Option<&str>, url: &str, timeout: Duration) -> Result<String, String> {
    let agent = agent_with(proxy, timeout)?;
    let response = agent
        .get(url)
        .set("User-Agent", "NekoSportsWorldTool/probe")
        .call()
        .map_err(|e| format!("代理连接失败：{e}"))?;
    let status = response.status();
    let body = response.into_string().unwrap_or_default();
    Ok(format!("HTTP {status} · {}", crate::textlog::truncate(&body, 160)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_common_forms() {
        assert_eq!(normalize("127.0.0.1:7890").unwrap(), "http://127.0.0.1:7890");
        assert_eq!(
            normalize("socks5://127.0.0.1:1080").unwrap(),
            "socks5://127.0.0.1:1080"
        );
        assert_eq!(
            normalize("socks5h://127.0.0.1:1080").unwrap(),
            "socks5://127.0.0.1:1080"
        );
        assert_eq!(
            normalize("http://user:pass@10.0.0.2:8080").unwrap(),
            "http://user:pass@10.0.0.2:8080"
        );
    }

    #[test]
    fn normalize_rejects_bad_forms() {
        assert!(normalize("").is_err());
        assert!(normalize("127.0.0.1").is_err(), "缺端口必须拒绝");
        assert!(normalize("socks4://127.0.0.1:1080").is_err());
        assert!(normalize("ftp://127.0.0.1:21").is_err());
        assert!(normalize("http://127.0.0.1:7890 x").is_err());
    }

    #[test]
    fn mask_hides_credentials_only() {
        assert_eq!(mask("http://127.0.0.1:7890"), "http://127.0.0.1:7890");
        assert_eq!(
            mask("socks5://user:secret@127.0.0.1:1080"),
            "socks5://***@127.0.0.1:1080"
        );
        assert!(!mask("socks5://user:secret@127.0.0.1:1080").contains("secret"));
    }

    #[test]
    fn account_mapping_is_stable_and_spreads() {
        let pool: Vec<String> = (0..4)
            .map(|i| format!("http://127.0.0.1:{}", 7000 + i))
            .collect();
        let pick = |account: &str| {
            let index = (hash64(account) % pool.len() as u64) as usize;
            pool[index].clone()
        };
        // 同一账号多次映射结果一致
        for _ in 0..8 {
            assert_eq!(pick("13800000001"), pick("13800000001"));
        }
        // 不同账号应当尽量分散到不同出口
        let mut seen = std::collections::HashSet::new();
        for i in 0..20 {
            seen.insert(pick(&format!("1380000000{i}")));
        }
        assert!(seen.len() > 1, "账号哈希未把流量分散到不同出口");
    }

    #[test]
    fn save_normalizes_and_dedupes_pool_text() {
        // 只在内存里验证规范化逻辑，不写磁盘。
        let mut entries: Vec<String> = Vec::new();
        for part in split_list("127.0.0.1:7001, socks5://127.0.0.1:7002 ;127.0.0.1:7001") {
            if part.is_empty() {
                continue;
            }
            let value = normalize(part).unwrap();
            if !entries.iter().any(|seen| seen == &value) {
                entries.push(value);
            }
        }
        assert_eq!(
            entries,
            vec!["http://127.0.0.1:7001", "socks5://127.0.0.1:7002"]
        );
    }
}
