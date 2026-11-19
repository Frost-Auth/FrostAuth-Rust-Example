use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey, Verifier, PUBLIC_KEY_LENGTH};
use rand;
use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const SDK_VERSION: &str = "1.0.0";
pub const DEFAULT_BASE_URL: &str = "https://api.frostauth.cc";
const MAX_SIGNATURE_SKEW_MS: i128 = 60_000;
const MAX_RETRY_AFTER_SECONDS: u64 = 10;
const ASSERTION_PREFIX: &str = "frostauth:assertion:v1";

pub fn public_keys() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(
        "k2".to_string(),
        "MCowBQYDK2VwAyEA7xdiHZqo4DmS4O1C8FavYq9Yqk5QbBkJiicb1MTTFzo".to_string(),
    );
    m
}

pub mod codes {
    pub const CONFIG: &str = "CONFIG";
    pub const NETWORK: &str = "NETWORK";
    pub const TIMEOUT: &str = "TIMEOUT";
    pub const NOT_INITIALIZED: &str = "NOT_INITIALIZED";
    pub const NOT_ACTIVATED: &str = "NOT_ACTIVATED";
    pub const SERVER_ERROR: &str = "SERVER_ERROR";
    pub const SIGNATURE: &str = "SIGNATURE";
    pub const RATE_LIMITED: &str = "RATE_LIMITED";
}

#[derive(Debug, Clone)]
pub struct FrostAuthError {
    pub code: String,
    pub status: u16,
    pub retryable: bool,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl std::fmt::Display for FrostAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code={}, status={})", self.message, self.code, self.status)
    }
}
impl std::error::Error for FrostAuthError {}

impl FrostAuthError {
    pub fn needs_activation(&self) -> bool {
        self.status == 404 && !self.retryable
    }
    pub fn terminal(&self) -> bool {
        !self.retryable && !self.needs_activation() && (400..500).contains(&self.status)
    }
    fn new(code: &str, status: u16, message: impl Into<String>) -> Self {
        Self { code: code.into(), status, retryable: false, message: message.into(), retry_after: None }
    }
    fn retryable(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.into(), status: 0, retryable: true, message: message.into(), retry_after: None }
    }
}

type Result<T> = std::result::Result<T, FrostAuthError>;

fn b64u_decode(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim())
        .or_else(|_| STANDARD.decode(s.trim()))
        .map_err(|_| FrostAuthError::new(codes::CONFIG, 0, "not a usable base64url value"))
}

fn b64u_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn spki_to_raw(b64: &str) -> Result<[u8; PUBLIC_KEY_LENGTH]> {
    let der = b64u_decode(b64)?;
    if der.len() != 44 {
        return Err(FrostAuthError::new(codes::CONFIG, 0, "not a usable Ed25519 public key"));
    }
    let mut raw = [0u8; PUBLIC_KEY_LENGTH];
    raw.copy_from_slice(&der[12..]);
    Ok(raw)
}

fn verifying_keys(pins: &HashMap<String, String>) -> Result<Vec<(String, VerifyingKey)>> {
    let mut out = Vec::new();
    for (id, b64) in pins {
        if b64.trim().is_empty() {
            continue;
        }
        let raw = spki_to_raw(b64)?;
        let vk = VerifyingKey::from_bytes(&raw)
            .map_err(|_| FrostAuthError::new(codes::CONFIG, 0, "not a usable Ed25519 public key"))?;
        out.push((id.clone(), vk));
    }
    Ok(out)
}

fn claim_string(claims: &Value) -> Vec<u8> {
    let g = |k: &str| claims.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    [
        ASSERTION_PREFIX.to_string(),
        "1".to_string(),
        g("lic"), g("pid"), g("dev"), g("hwid"), g("status"), g("tier"),
        g("exp"), g("iat"), g("nbf"), g("naf"),
    ]
    .join("\n")
    .into_bytes()
}

fn parse_ms(v: &Value) -> Option<i128> {
    if let Some(n) = v.as_i64() {
        return Some(n as i128);
    }
    if let Some(n) = v.as_f64() {
        return Some(n as i128);
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
            return Some(dt.timestamp_millis() as i128);
        }
    }
    None
}

fn now_ms() -> i128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i128).unwrap_or(0)
}

pub fn verify_assertion(
    assertion: &str,
    pins: &HashMap<String, String>,
    hwid: Option<&str>,
    at: Option<i128>,
) -> (bool, String, Option<Value>) {
    if pins.is_empty() {
        return (false, "no pinned public key".into(), None);
    }
    let at = at.unwrap_or_else(now_ms);

    let parts: Vec<&str> = assertion.split('.').collect();
    if parts.len() != 3 {
        return (false, "malformed".into(), None);
    }
    let (payload, sig_b64, key_id) = (parts[0], parts[1], parts[2]);

    let keys = match verifying_keys(pins) {
        Ok(k) => k,
        Err(_) => return (false, "no pinned public key".into(), None),
    };
    let candidates: Vec<&VerifyingKey> = keys
        .iter()
        .filter(|(id, _)| key_id.is_empty() || id == key_id)
        .map(|(_, vk)| vk)
        .collect();
    if candidates.is_empty() {
        return (
            false,
            format!("signed with key \"{key_id}\", which this build does not trust"),
            None,
        );
    }

    let claims: Value = match b64u_decode(payload)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
    {
        Some(c) => c,
        None => return (false, "unreadable".into(), None),
    };
    let signature: Signature = match b64u_decode(sig_b64)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
    {
        Some(s) => s,
        None => return (false, "unreadable".into(), Some(claims.clone())),
    };

    let material = claim_string(&claims);
    let mut ok = false;
    for vk in &candidates {
        if vk.verify(&material, &signature).is_ok() {
            ok = true;
            break;
        }
    }
    if !ok {
        return (false, "signature does not verify".into(), Some(claims.clone()));
    }
    if let Some(h) = hwid {
        if claims.get("hwid").and_then(|v| v.as_str()) != Some(h) {
            return (false, "issued for a different machine".into(), Some(claims.clone()));
        }
    }
    let (Some(nbf), Some(naf)) = (parse_ms(&claims["nbf"]), parse_ms(&claims["naf"])) else {
        return (false, "offline window is missing or unreadable".into(), Some(claims.clone()));
    };
    if naf <= nbf {
        return (false, "offline window is missing or unreadable".into(), Some(claims.clone()));
    }
    if at < nbf {
        return (false, "not yet valid".into(), Some(claims.clone()));
    }
    if at > naf {
        return (false, "offline period has run out".into(), Some(claims.clone()));
    }
    let exp_raw = claims.get("exp").cloned().unwrap_or(Value::Null);
    let has_exp = exp_raw.as_str().map(|s| !s.trim().is_empty()).unwrap_or(false)
        || exp_raw.as_i64().map(|n| n != 0).unwrap_or(false);
    if has_exp {
        match parse_ms(&exp_raw) {
            Some(exp) if at <= exp => {}
            _ => return (false, "licence expired".into(), Some(claims.clone())),
        }
    }
    (true, String::new(), Some(claims))
}

fn run_cmd(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program).args(args).output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        None
    }
}

static MACHINE_CACHE: Mutex<Option<String>> = Mutex::new(None);

fn safe_user() -> String {
    std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "unknown".into())
}

fn raw_machine_id() -> String {
    if let Some(cached) = MACHINE_CACHE.lock().unwrap().clone() {
        return cached;
    }
    let found: Option<String> = match std::env::consts::OS {
        "windows" => run_cmd("reg", &[
            "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid",
        ])
        .and_then(|out| {
            out.lines().find_map(|l| {
                let i = l.find("REG_SZ")?;
                Some(l[i + 6..].trim().to_string())
            })
        }),
        "macos" => run_cmd("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]).and_then(|out| {
            out.lines().find_map(|l| {
                let i = l.find("\"IOPlatformUUID\" = \"")?;
                let rest = &l[i + "\"IOPlatformUUID\" = \"".len()..];
                Some(rest.trim_end_matches('"').to_string())
            })
        }),
        "linux" => std::fs::read_to_string("/etc/machine-id")
            .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        _ => None,
    };
    let id = found.unwrap_or_else(|| {
        let host = hostname();
        format!("fallback:{host}:{}:{}", safe_user(), std::env::consts::OS)
    });
    *MACHINE_CACHE.lock().unwrap() = Some(id.clone());
    id
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "unknown".into())
}

pub fn hardware_id(scope: &str) -> String {
    let scope = if scope.is_empty() { "frostauth" } else { scope };
    let mut h = Sha256::new();
    h.update(format!("{scope}|{}", raw_machine_id()));
    hex(&h.finalize())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn facet(v: &str) -> String {
    let mut h = Sha256::new();
    h.update(v.as_bytes());
    hex(&h.finalize())[..32].to_string()
}

const VM_MAC_PREFIXES: [&str; 10] = [
    "00:05:69", "00:0c:29", "00:1c:14", "00:50:56", "08:00:27", "0a:00:27",
    "00:15:5d", "00:1c:42", "52:54:00", "00:16:3e",
];

fn vm_name(cpu: &str) -> bool {
    let cpu = cpu.to_lowercase();
    ["vmware", "virtualbox", "vbox", "qemu", "kvm", "xen", "hyper-v", "hyperv", "parallels", "bhyve", "virtual machine", "innotek"]
        .iter().any(|p| cpu.contains(p))
}

fn mac_addresses() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match std::env::consts::OS {
        "windows" => {
            if let Some(csv) = run_cmd("getmac", &["/fo", "csv", "/nh"]) {
                for line in csv.lines() {
                    let inner = line.trim().trim_matches('"');
                    if let Some(first) = inner.split('"').next() {
                        let m = first.trim().to_lowercase().replace('-', ":");
                        if m.matches(':').count() == 5 && m != "00:00:00:00:00:00" && !m.is_empty() {
                            out.push(m);
                        }
                    }
                }
            }
        }
        "linux" => {
            if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
                for e in entries.flatten() {
                    if let Ok(addr) = std::fs::read_to_string(e.path().join("address")) {
                        let m = addr.trim().to_lowercase();
                        if m.matches(':').count() == 5 && m != "00:00:00:00:00:00" {
                            out.push(m);
                        }
                    }
                }
            }
        }
        "macos" => {
            if let Some(txt) = run_cmd("ifconfig", &[]) {
                let re = regex::Regex::new(r"ether\s+([0-9a-fA-F:]{17})").unwrap();
                for cap in re.captures_iter(&txt) {
                    out.push(cap[1].to_lowercase());
                }
            }
        }
        _ => {}
    }
    out.sort();
    out.dedup();
    out
}

pub fn hardware_profile() -> (Vec<(String, String)>, bool) {
    let cpu = match std::env::consts::OS {
        "windows" => run_cmd("reg", &[
            "query", r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "/v", "ProcessorNameString",
        ])
        .and_then(|out| {
            out.lines().find_map(|l| {
                let i = l.find("REG_SZ")?;
                Some(l[i + 6..].trim().to_string())
            })
        })
        .unwrap_or_else(|| "unknown".into()),
        "macos" => run_cmd("sysctl", &["-n", "machdep.cpu.brand_string"])
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".into()),
        "linux" => std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|txt| {
            txt.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        }).unwrap_or_else(|| "unknown".into()),
        _ => "unknown".into(),
    };

    let macs = mac_addresses();
    let n_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

    let mut components = vec![
        ("cpu".to_string(), facet(&format!("{cpu}|{n_cpus}"))),
        ("ram".to_string(), facet("unknown")),
        ("arch".to_string(), facet(std::env::consts::ARCH)),
        ("platform".to_string(), facet(std::env::consts::OS)),
        ("host".to_string(), facet(&hostname())),
    ];
    let all_vm = !macs.is_empty()
        && macs.iter().all(|m| VM_MAC_PREFIXES.iter().any(|p| m.starts_with(p)));
    if !macs.is_empty() {
        components.push(("mac".to_string(), facet(&macs.join(","))));
    }
    let virtualized = (all_vm && !macs.is_empty()) || vm_name(&cpu);
    (components, virtualized)
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local() || v6.is_unicast_link_local()
        }
    }
}

fn assert_real_host(base_url: &str) -> Result<()> {
    let host = host_of(base_url);
    let bare = host.trim_matches(|c| c == '[' || c == ']').to_string();
    if bare.is_empty()
        || bare == "localhost"
        || bare == "127.0.0.1"
        || bare == "::1"
        || bare.parse::<IpAddr>().is_ok()
    {
        return Ok(());
    }
    let addrs: Vec<IpAddr> = (bare.as_str(), 0u16)
        .to_socket_addrs()
        .map_err(|e| {
            FrostAuthError::new(
                codes::NETWORK,
                0,
                format!("cannot resolve the licence server host \"{bare}\" — refusing to continue ({e})"),
            )
        })?
        .map(|a| a.ip())
        .collect();
    let private: Vec<String> = addrs.iter().filter(|a| is_private_ip(**a)).map(|a| a.to_string()).collect();
    if !private.is_empty() {
        return Err(FrostAuthError::new(
            codes::NETWORK,
            0,
            format!(
                "\"{bare}\" resolves to loopback or private space ({}) — this is what a hosts-file hijack or licence emulator looks like. Refusing to continue.",
                private.join(", ")
            ),
        ));
    }
    Ok(())
}

fn host_of(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    rest.split(['/']).next().unwrap_or("").split(':').next().unwrap_or("").to_string()
}

struct Inner {
    pins_b64: HashMap<String, String>,
    keys: Vec<(String, VerifyingKey)>,
    app: Option<Value>,
    license: Option<Value>,
    product: Option<Value>,
    device: Option<Value>,
    user: Option<String>,
    account: Option<Value>,
    subscriptions: Vec<Value>,
    session: Option<Value>,
    key: Option<String>,
    assertion: Option<String>,
    offline_until: Option<String>,
    offline_since: Option<SystemTime>,
    machine_id: Option<String>,
    initialized: bool,
    activated: bool,
    closed: bool,
}

#[derive(Default, Clone)]
pub struct Hooks {
    pub on_activated: Option<Arc<dyn Fn(&Value) + Send + Sync>>,
    pub on_logged_in: Option<Arc<dyn Fn(&Value) + Send + Sync>>,
    pub on_validated: Option<Arc<dyn Fn(&Value) + Send + Sync>>,
    pub on_update_available: Option<Arc<dyn Fn(&str, &str) + Send + Sync>>,
    pub on_offline: Option<Arc<dyn Fn(&FrostAuthError, u64, bool) + Send + Sync>>,
    pub on_invalid: Option<Arc<dyn Fn(&FrostAuthError) + Send + Sync>>,
    pub on_needs_activation: Option<Arc<dyn Fn(&FrostAuthError) + Send + Sync>>,
}

pub struct Options {
    pub owner: String,
    pub product: String,
    pub version: String,
    pub base_url: String,
    pub timeout: Duration,
    pub retries: u32,
    pub offline_grace_seconds: u64,
    pub public_key: HashMap<String, String>,
    pub allow_insecure: bool,
    pub allow_private_dns: bool,
    pub hardware_id_override: Option<String>,
    pub collect_hardware: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            owner: String::new(),
            product: String::new(),
            version: String::new(),
            base_url: DEFAULT_BASE_URL.into(),
            timeout: Duration::from_secs(10),
            retries: 2,
            offline_grace_seconds: 900,
            public_key: HashMap::new(),
            allow_insecure: false,
            allow_private_dns: false,
            hardware_id_override: None,
            collect_hardware: true,
        }
    }
}

pub struct FrostAuthClient {
    base_url: String,
    owner: String,
    product: String,
    version: String,
    timeout: Duration,
    retries: u32,
    offline_grace: u64,
    allow_private_dns: bool,
    hw_override: Option<String>,
    collect_hardware: bool,
    http: Client,
    inner: Mutex<Inner>,
    pub hooks: Hooks,
}

impl FrostAuthClient {
    pub fn new(o: Options) -> Result<Arc<Self>> {
        for (name, v) in [("owner", &o.owner), ("product", &o.product), ("version", &o.version)] {
            if v.trim().is_empty() {
                return Err(FrostAuthError::new(codes::CONFIG, 0, format!("{name} is required")));
            }
        }
        let loopback = matches!(host_of(&o.base_url).as_str(), "localhost" | "127.0.0.1" | "::1");
        if !o.base_url.starts_with("https://") && !loopback && !o.allow_insecure {
            return Err(FrostAuthError::new(
                codes::CONFIG,
                0,
                "Refusing to send a licence key over plain http. Use https, or allow_insecure: true if you know what you are doing.",
            ));
        }
        let keys = verifying_keys(&o.public_key)?;
        let http = Client::builder()
            .timeout(o.timeout)
            .build()
            .map_err(|e| FrostAuthError::new(codes::CONFIG, 0, format!("http client: {e}")))?;
        Ok(Arc::new(Self {
            base_url: o.base_url,
            owner: o.owner,
            product: o.product,
            version: o.version,
            timeout: o.timeout,
            retries: o.retries,
            offline_grace: o.offline_grace_seconds,
            allow_private_dns: o.allow_private_dns,
            hw_override: o.hardware_id_override,
            collect_hardware: o.collect_hardware,
            http,
            inner: Mutex::new(Inner {
                pins_b64: o.public_key.clone(),
                keys,
                app: None,
                license: None,
                product: None,
                device: None,
                user: None,
                account: None,
                subscriptions: vec![],
                session: None,
                key: None,
                assertion: None,
                offline_until: None,
                offline_since: None,
                machine_id: None,
                initialized: false,
                activated: false,
                closed: false,
            }),
            hooks: Hooks::default(),
        }))
    }

    pub fn snapshot(&self) -> Value {
        let g = self.inner.lock().unwrap();
        json!({
            "app": g.app, "license": g.license, "product": g.product, "device": g.device,
            "user": g.user, "account": g.account, "subscriptions": g.subscriptions,
            "valid": g.activated && !g.closed,
        })
    }

    pub async fn init(self: &Arc<Self>) -> Result<Value> {
        if !self.allow_private_dns {
            assert_real_host(&self.base_url)?;
        }
        let path = format!(
            "/api/v1/settings/catalog/{}/{}",
            url_escape(&self.owner), url_escape(&self.product)
        );
        let (status, raw) = self.one_request(Method::GET, &path, None, None).await?;
        let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        if !body["success"].as_bool().unwrap_or(false) {
            let code = body["error"].as_str().unwrap_or("APP_NOT_FOUND").to_string();
            let msg = body["message"].as_str().unwrap_or("Application not found").to_string();
            return Err(FrostAuthError { code, status: status.as_u16(), retryable: false, message: msg, retry_after: None });
        }
        let key_id = body["key_id"].as_str().unwrap_or("").to_string();
        let served = body["public_key"].as_str().unwrap_or("").to_string();
        let pinned = public_keys().get(&key_id).cloned();
        match pinned {
            Some(p) if !key_id.is_empty() && served == p => {
                let raw = spki_to_raw(&p)?;
                let vk = VerifyingKey::from_bytes(&raw)
                    .map_err(|_| FrostAuthError::new(codes::CONFIG, 0, "built-in pinned key malformed"))?;
                let mut g = self.inner.lock().unwrap();
                g.pins_b64 = HashMap::from([(key_id.clone(), p)]);
                g.keys = vec![(key_id.clone(), vk)];
                g.app = Some(json!({
                    "name": body["app_name"], "ownerId": body["owner_id"], "messages": body["errors"],
                }));
                g.initialized = true;
                Ok(g.app.clone().unwrap())
            }
            _ => Err(FrostAuthError::new(
                codes::SIGNATURE,
                401,
                "Server identity check failed — refusing to continue",
            )),
        }
    }

    fn require_init(&self) -> Result<()> {
        if !self.inner.lock().unwrap().initialized {
            return Err(FrostAuthError::new(codes::NOT_INITIALIZED, 0, "Call init() before anything else"));
        }
        Ok(())
    }

    fn machine_id(&self) -> String {
        let mut g = self.inner.lock().unwrap();
        if let Some(id) = &g.machine_id {
            return id.clone();
        }
        let id = match &self.hw_override {
            Some(s) => s.clone(),
            None => {
                let scope = g
                    .app
                    .as_ref()
                    .and_then(|a| a["ownerId"].as_str())
                    .unwrap_or(&self.owner)
                    .to_string();
                hardware_id(&scope)
            }
        };
        g.machine_id = Some(id.clone());
        id
    }

    fn hardware_extra(&self) -> Value {
        if !self.collect_hardware {
            return json!({});
        }
        let (components, virtualized) = hardware_profile();
        json!({
            "components": components.iter().map(|(n, v)| json!({"n": n, "v": v})).collect::<Vec<_>>(),
            "virtual": virtualized,
        })
    }

    pub async fn activate(self: &Arc<Self>, key: &str, extra_hash: Option<&str>, label: Option<&str>) -> Result<Value> {
        self.require_init()?;
        if key.trim().is_empty() {
            return Err(FrostAuthError::new(codes::CONFIG, 0, "licence key is required"));
        }
        let mut body = json!({
            "key": key, "hwid": self.machine_id(), "os": std::env::consts::OS,
            "appVersion": self.version,
        });
        merge(&mut body, self.hardware_extra());
        if let Some(h) = extra_hash { body["hash"] = json!(h); }
        if let Some(l) = label { body["label"] = json!(&l.chars().take(64).collect::<String>()); }
        let data = self.request_envelope(Method::POST, "/api/v1/activate", Some(body), None).await?;
        {
            let mut g = self.inner.lock().unwrap();
            g.key = Some(key.to_string());
            Self::adopt_locked(&mut g, &data);
            g.activated = true;
            g.offline_since = None;
        }
        if let Some(cb) = &self.hooks.on_activated {
            cb(&self.snapshot());
        }
        Ok(self.snapshot())
    }

    pub async fn register(
        self: &Arc<Self>, key: &str, username: &str, password: &str,
        extra_hash: Option<&str>, label: Option<&str>,
    ) -> Result<Value> {
        self.require_init()?;
        if key.trim().is_empty() {
            return Err(FrostAuthError::new(codes::CONFIG, 0, "licence key is required"));
        }
        let mut body = json!({
            "key": key, "username": username, "password": password,
            "hwid": self.machine_id(), "os": std::env::consts::OS, "appVersion": self.version,
        });
        merge(&mut body, self.hardware_extra());
        if let Some(h) = extra_hash { body["hash"] = json!(h); }
        if let Some(l) = label { body["label"] = json!(&l.chars().take(64).collect::<String>()); }
        let data = self.request_envelope(Method::POST, "/api/v1/sdk/register", Some(body), None).await?;
        {
            let mut g = self.inner.lock().unwrap();
            g.key = Some(key.to_string());
            Self::adopt_locked(&mut g, &data);
            g.activated = true;
            g.offline_since = None;
        }
        if let Some(cb) = &self.hooks.on_activated {
            cb(&self.snapshot());
        }
        Ok(self.snapshot())
    }

    pub async fn login(
        self: &Arc<Self>, username: &str, password: &str,
        twofa: Option<&str>, extra_hash: Option<&str>, label: Option<&str>,
    ) -> Result<Value> {
        self.require_init()?;
        let mut body = json!({
            "owner": self.owner, "product": self.product, "username": username, "password": password,
            "hwid": self.machine_id(), "os": std::env::consts::OS, "appVersion": self.version,
        });
        merge(&mut body, self.hardware_extra());
        if let Some(t) = twofa { body["twofa"] = json!(t); }
        if let Some(h) = extra_hash { body["hash"] = json!(h); }
        if let Some(l) = label { body["label"] = json!(&l.chars().take(64).collect::<String>()); }
        let data = self.request_envelope(Method::POST, "/api/v1/sdk/login", Some(body), None).await?;
        {
            let mut g = self.inner.lock().unwrap();
            Self::adopt_locked(&mut g, &data);
            g.activated = true;
            g.offline_since = None;
        }
        if let Some(cb) = &self.hooks.on_logged_in {
            cb(&self.snapshot());
        }
        Ok(self.snapshot())
    }

    pub async fn upgrade(self: &Arc<Self>, username: &str, password: &str, key: &str) -> Result<Value> {
        self.require_init()?;
        self.request_envelope(Method::POST, "/api/v1/sdk/upgrade", Some(json!({
            "owner": self.owner, "product": self.product,
            "username": username, "password": password, "key": key,
        })), None).await
    }

    fn session_token(&self) -> Option<String> {
        self.inner.lock().unwrap().session.as_ref()
            .and_then(|s| s["token"].as_str()).map(|s| s.to_string())
    }

    async fn authed(self: &Arc<Self>, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        match self.session_token() {
            Some(t) => self.request_envelope(method, path, body, Some(t)).await,
            None => Err(FrostAuthError::new(
                codes::NOT_ACTIVATED, 0, "This call needs a session — activate or sign in first")),
        }
    }

    pub async fn logout(self: &Arc<Self>) -> Result<Value> {
        let had = self.session_token().is_some();
        let out = if had {
            self.authed(Method::POST, "/api/v1/sdk/logout", None).await
        } else {
            Ok(json!({"signedOut": true}))
        };
        self.close();
        out
    }

    pub async fn session(self: &Arc<Self>) -> Result<Value> {
        let data = self.authed(Method::GET, "/api/v1/sdk/session", None).await?;
        let mut g = self.inner.lock().unwrap();
        Self::adopt_locked(&mut g, &data);
        Ok(self.snapshot())
    }

    pub async fn variable(self: &Arc<Self>, key: &str) -> Result<String> {
        let d = self.authed(Method::GET, &format!("/api/v1/sdk/vars/app/{}", url_escape(key)), None).await?;
        Ok(d["value"].as_str().unwrap_or_default().to_string())
    }
    pub async fn list_vars(self: &Arc<Self>) -> Result<Vec<Value>> {
        let d = self.authed(Method::GET, "/api/v1/sdk/vars/user", None).await?;
        Ok(d["variables"].as_array().cloned().unwrap_or_default())
    }
    pub async fn get_var(self: &Arc<Self>, key: &str) -> Result<String> {
        let d = self.authed(Method::GET, &format!("/api/v1/sdk/vars/user/{}", url_escape(key)), None).await?;
        Ok(d["value"].as_str().unwrap_or_default().to_string())
    }
    pub async fn set_var(self: &Arc<Self>, key: &str, value: &str) -> Result<Value> {
        self.authed(Method::PUT, &format!("/api/v1/sdk/vars/user/{}", url_escape(key)), Some(json!({"value": value}))).await
    }
    pub async fn change_username(self: &Arc<Self>, username: &str, password: &str) -> Result<Value> {
        let d = self.authed(Method::PATCH, "/api/v1/sdk/username", Some(json!({"username": username, "password": password}))).await?;
        let mut g = self.inner.lock().unwrap();
        if let Some(acc) = g.account.as_mut().and_then(|v| v.as_object_mut()) {
            acc.insert("username".into(), d["username"].clone());
        }
        if let Some(u) = d["username"].as_str() {
            g.user = Some(u.to_string());
        }
        Ok(d)
    }
    pub async fn log(self: &Arc<Self>, message: &str) -> Result<Value> {
        let msg: String = message.chars().take(256).collect();
        self.authed(Method::POST, "/api/v1/sdk/log", Some(json!({"message": msg}))).await
    }
    pub async fn ban(self: &Arc<Self>, reason: &str) -> Result<Value> {
        let r: String = reason.chars().take(200).collect();
        let out = self.authed(Method::POST, "/api/v1/sdk/ban", Some(json!({"reason": r}))).await;
        let mut g = self.inner.lock().unwrap();
        g.activated = false;
        g.assertion = None;
        g.offline_until = None;
        out
    }
    pub async fn fetch_online(self: &Arc<Self>) -> Result<Value> {
        self.authed(Method::GET, "/api/v1/sdk/online", None).await
    }
    pub async fn check_blacklist(self: &Arc<Self>) -> Result<Value> {
        self.authed(Method::GET, "/api/v1/sdk/checkblacklist", None).await
    }
    pub async fn webhook(self: &Arc<Self>, web_id: &str, params: &str, body: &str, conttype: &str) -> Result<Value> {
        if web_id.trim().is_empty() {
            return Err(FrostAuthError::new(codes::CONFIG, 0, "webhook id is required"));
        }
        let mut payload = Map::new();
        if !params.is_empty() { payload.insert("params".into(), json!(&params.chars().take(2048).collect::<String>())); }
        if !body.is_empty() { payload.insert("body".into(), json!(&body.chars().take(8192).collect::<String>())); }
        if !conttype.is_empty() { payload.insert("conttype".into(), json!(&conttype.chars().take(128).collect::<String>())); }
        self.authed(Method::POST, &format!("/api/v1/sdk/webhook/{}", url_escape(web_id)), Some(Value::Object(payload))).await
    }
    pub async fn app_data(self: &Arc<Self>) -> Result<Value> {
        self.authed(Method::GET, "/api/v1/sdk/app", None).await
    }

    pub async fn file(self: &Arc<Self>, _id: &str) -> Result<Vec<u8>> {
        Err(FrostAuthError::new(codes::SERVER_ERROR, 0, "File downloads are disabled on this server"))
    }

    pub async fn validate(self: &Arc<Self>) -> Result<Value> {
        self.require_init()?;
        {
            let g = self.inner.lock().unwrap();
            if g.session.as_ref().and_then(|s| s["token"].as_str()).is_none() && g.key.is_none() {
                return Err(FrostAuthError::new(codes::NOT_ACTIVATED, 0, "Activate before validating"));
            }
        }
        match self.send_validate().await {
            Ok(data) => {
                {
                    let mut g = self.inner.lock().unwrap();
                    Self::adopt_locked(&mut g, &data);
                    g.activated = true;
                    g.offline_since = None;
                }
                if let Some(cb) = &self.hooks.on_validated {
                    cb(&self.snapshot());
                }
                Ok(self.snapshot())
            }
            Err(err) => {
                if matches!(err.code.as_str(), "INVALID_TOKEN" | "INVALID_SESSION") {
                    let has_key = self.inner.lock().unwrap().key.is_some();
                    if has_key {
                        self.inner.lock().unwrap().session = None;
                        let data = self.send_validate().await?;
                        {
                            let mut g = self.inner.lock().unwrap();
                            Self::adopt_locked(&mut g, &data);
                            g.activated = true;
                            g.offline_since = None;
                        }
                        if let Some(cb) = &self.hooks.on_validated {
                            cb(&self.snapshot());
                        }
                        return Ok(self.snapshot());
                    }
                }
                Err(err)
            }
        }
    }

    async fn send_validate(self: &Arc<Self>) -> Result<Value> {
        let hwid = self.machine_id();
        let (token, key) = {
            let g = self.inner.lock().unwrap();
            (g.session.as_ref().and_then(|s| s["token"].as_str()).map(String::from), g.key.clone())
        };
        let payload = if let Some(t) = token {
            json!({"token": t, "hwid": hwid, "appVersion": self.version, "os": std::env::consts::OS})
        } else if let Some(k) = key {
            json!({"key": k, "hwid": hwid, "appVersion": self.version, "os": std::env::consts::OS})
        } else {
            return Err(FrostAuthError::new(codes::NOT_ACTIVATED, 0, "activate before validating"));
        };
        self.request_envelope(Method::POST, "/api/v1/validate", Some(payload), None).await
    }

    pub fn start_heartbeat(self: &Arc<Self>, interval_seconds: Option<u64>) -> Result<tokio::task::JoinHandle<()>> {
        {
            let mut g = self.inner.lock().unwrap();
            let has_cred = g.session.as_ref().and_then(|s| s["token"].as_str()).is_some() || g.key.is_some();
            if !has_cred {
                return Err(FrostAuthError::new(
                    codes::NOT_ACTIVATED, 0,
                    "Nothing to heartbeat with: activate with a licence key, or sign in."));
            }
            g.closed = false;
        }
        let this = Arc::clone(self);
        Ok(tokio::spawn(async move {
            loop {
                let wait = match interval_seconds {
                    Some(s) => Duration::from_secs(s.max(1)),
                    None => {
                        let base = {
                            let g = this.inner.lock().unwrap();
                            g.session.as_ref().and_then(|s| s["heartbeatSeconds"].as_u64()).unwrap_or(180).max(15)
                        };
                        let jitter = rand::random::<u64>() % 5000;
                        Duration::from_secs(base) + Duration::from_millis(jitter)
                    }
                };
                tokio::time::sleep(wait).await;
                if this.inner.lock().unwrap().closed {
                    return;
                }
                match this.validate().await {
                    Ok(_) => {}
                    Err(err) => {
                        if err.needs_activation() {
                            this.inner.lock().unwrap().activated = false;
                            if let Some(cb) = &this.hooks.on_needs_activation { cb(&err); }
                            return;
                        }
                        if err.code == codes::SIGNATURE || err.terminal() {
                            this.inner.lock().unwrap().activated = false;
                            if let Some(cb) = &this.hooks.on_invalid { cb(&err); }
                            return;
                        }
                        let offline_for = {
                            let mut g = this.inner.lock().unwrap();
                            let since = *g.offline_since.get_or_insert_with(std::time::SystemTime::now);
                            since.elapsed().map(|d| d.as_secs()).unwrap_or(0)
                        };
                        let (verified, stop) = {
                            let mut g = this.inner.lock().unwrap();
                            let verified = g.assertion.as_ref().is_some_and(|assertion| {
                                verify_assertion(assertion, &g.pins_b64, g.machine_id.as_deref(), None).0
                            });
                            let stop = !verified && (g.assertion.is_some() || offline_for >= this.offline_grace);
                            if stop { g.activated = false; }
                            (verified, stop)
                        };
                        if let Some(cb) = &this.hooks.on_offline { cb(&err, offline_for, verified); }
                        if stop {
                            if let Some(cb) = &this.hooks.on_invalid {
                                cb(&FrostAuthError::new(codes::NETWORK, 0, format!("Could not reach the licence server for {offline_for}s")));
                            }
                            return;
                        }
                    }
                }
            }
        }))
    }

    pub fn stop_heartbeat(&self) {
        // The task exits itself when closed; closing is the stop signal.
    }

    pub fn close(&self) {
        let mut g = self.inner.lock().unwrap();
        g.closed = true;
        g.key = None;
        g.session = None;
        g.activated = false;
        g.account = None;
        g.subscriptions = vec![];
        g.assertion = None;
        g.offline_until = None;
        g.offline_since = None;
    }

    pub fn check_offline(&self) -> (bool, String) {
        let g = self.inner.lock().unwrap();
        match &g.assertion {
            None => (false, "no assertion issued yet".into()),
            Some(a) => {
                if g.pins_b64.is_empty() {
                    return (false, "no pinned publicKey to verify against".into());
                }
                let pins = g.pins_b64.clone();
                let mid = g.machine_id.clone();
                let (ok, reason, _) = verify_assertion(a, &pins, mid.as_deref(), None);
                (ok, reason)
            }
        }
    }

    fn adopt_locked(g: &mut Inner, data: &Value) {
        if data["session"]["token"].is_string() {
            g.session = Some(data["session"].clone());
        }
        for (src, dst) in [
            ("license", &mut g.license), ("product", &mut g.product), ("device", &mut g.device),
        ] {
            if !data[src].is_null() {
                *dst = Some(data[src].clone());
            }
        }
        if let Some(u) = data["user"].as_str() {
            g.user = Some(u.to_string());
        }
        if !data["account"].is_null() {
            g.account = Some(data["account"].clone());
        }
        if let Some(subs) = data["subscriptions"].as_array() {
            g.subscriptions = subs.clone();
        }
        if let Some(a) = data["offline"]["assertion"].as_str() {
            g.assertion = Some(a.to_string());
            g.offline_until = data["offline"]["notAfter"].as_str().map(String::from);
        }
        if data["product"]["updateAvailable"].as_bool().unwrap_or(false) {
            // handled by caller after releasing the lock (hooks are not borrowed here)
        }
    }

    fn adopt(&self, data: &Value) {
        let mut g = self.inner.lock().unwrap();
        let update = data["product"]["updateAvailable"].as_bool().unwrap_or(false);
        Self::adopt_locked(&mut g, data);
        drop(g);
        if update {
            let latest = data["product"]["latest"].as_str()
                .or_else(|| data["product"]["version"].as_str())
                .unwrap_or("").to_string();
            if let Some(cb) = &self.hooks.on_update_available {
                cb(&self.version, &latest);
            }
        }
    }

    async fn one_request(
        &self, method: Method, path: &str, body: Option<Value>, token: Option<&str>,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let mut nonce_b = [0u8; 16];
        use rand::RngCore as _;
        rand::rngs::OsRng.fill_bytes(&mut nonce_b);
        let nonce = b64u_encode(&nonce_b);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);

        let mut req = self.http
            .request(method.clone(), format!("{}{}", self.base_url, path))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("User-Agent", format!("frostauth-sdk-rust/{SDK_VERSION} ({})", std::env::consts::OS))
            .header("X-Frost-Nonce", &nonce)
            .header("X-Frost-Timestamp", now.to_string());
        if let Some(b) = &body {
            req = req.json(b);
        }
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.map_err(|e| {
            if e.is_timeout() {
                FrostAuthError::retryable(codes::TIMEOUT, format!("Request timed out after {:?}", self.timeout))
            } else {
                FrostAuthError::retryable(codes::NETWORK, "Could not reach the licence server")
            }
        })?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let raw = resp.bytes().await
            .map_err(|_| FrostAuthError::retryable(codes::NETWORK, "could not read the licence server answer"))?;

        let has_sig = headers.get("x-frost-signature").map(|v| !v.is_empty()).unwrap_or(false);
        if status != StatusCode::TOO_MANY_REQUESTS || has_sig {
            self.verify_response(&headers, &raw, &nonce, method.as_str(), path, status)?;
        }
        Ok((status, raw.to_vec()))
    }

    fn verify_response(
        &self, headers: &reqwest::header::HeaderMap, raw: &[u8],
        nonce: &str, method: &str, path: &str, status: StatusCode,
    ) -> Result<()> {
        let keys = self.inner.lock().unwrap().keys.clone();
        if keys.is_empty() {
            return Ok(());
        }
        let reject = |why: &str| FrostAuthError {
            code: codes::SIGNATURE.into(),
            status: status.as_u16(),
            retryable: false,
            message: format!("Refusing an unverified answer from the licence server: {why}"),
            retry_after: None,
        };
        let sig = String::from_utf8_lossy(headers.get("x-frost-signature").map(|v| v.as_bytes()).unwrap_or(b"")).to_string();
        let ts = String::from_utf8_lossy(headers.get("x-frost-timestamp").map(|v| v.as_bytes()).unwrap_or(b"")).to_string();
        if sig.is_empty() || ts.is_empty() {
            return Err(reject("it was not signed"));
        }
        let resp_nonce = String::from_utf8_lossy(headers.get("x-frost-nonce").map(|v| v.as_bytes()).unwrap_or(b""));
        if resp_nonce != nonce {
            return Err(reject("it answered a different request"));
        }
        let ts_n: i64 = ts.parse().map_err(|_| reject("bad timestamp"))?;
        let skew = ts_n as i128 - now_ms();
        if skew.abs() > MAX_SIGNATURE_SKEW_MS {
            return Err(reject("it was signed too long ago"));
        }
        let key_id = String::from_utf8_lossy(headers.get("x-frost-key-id").map(|v| v.as_bytes()).unwrap_or(b"")).to_string();
        let candidates: Vec<&VerifyingKey> = keys
            .iter()
            .filter(|(id, _)| key_id.is_empty() || id == &key_id)
            .map(|(_, vk)| vk)
            .collect();
        if candidates.is_empty() {
            return Err(reject(&format!("it was signed with key \"{key_id}\", which this build does not trust")));
        }
        let raw_str = String::from_utf8_lossy(raw);
        let material = format!("{ts}\n{nonce}\n{}\n{path}\n{}\n{raw_str}", method.to_uppercase(), status.as_u16());
        let signature: Signature = b64u_decode(&sig)
            .ok()
            .and_then(|b| Signature::from_slice(&b).ok())
            .ok_or_else(|| reject("bad signature encoding"))?;
        for vk in candidates {
            if vk.verify(material.as_bytes(), &signature).is_ok() {
                return Ok(());
            }
        }
        Err(reject("the signature did not match"))
    }

    async fn request_envelope(
        self: &Arc<Self>, method: Method, path: &str, body: Option<Value>, token: Option<String>,
    ) -> Result<Value> {
        let mut last_err: Option<FrostAuthError> = None;
        for attempt in 0..=self.retries {
            if attempt > 0 {
                let backoff = rand::random::<u64>() % ((300u64 * (1 << attempt)).min(15_000) + 1);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
            }
            let result = self.one_request(method.clone(), path, body.clone(), token.as_deref()).await;

            let (status, raw) = match result {
                Ok(pair) => pair,
                Err(err) => {
                    if err.code == codes::SIGNATURE {
                        return Err(err);
                    }
                    last_err = Some(err);
                    continue;
                }
            };

            if status == StatusCode::TOO_MANY_REQUESTS {
                let wait = last_err_wait(&raw);
                let err = FrostAuthError {
                    code: codes::RATE_LIMITED.into(),
                    status: 429,
                    retryable: true,
                    message: "Rate limited by the licence server".into(),
                    retry_after: Some(wait),
                };
                if attempt < self.retries && wait <= MAX_RETRY_AFTER_SECONDS {
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                    last_err = Some(err);
                    continue;
                }
                return Err(err);
            }

            let text = String::from_utf8_lossy(&raw).to_string();
            let payload: Value = serde_json::from_str(&text).unwrap_or(Value::Null);

            if status.as_u16() >= 500 {
                let typed = payload["response"]["errorCode"].as_str().map(String::from);
                if let Some(code) = typed {
                    let msg = payload["response"]["message"].as_str()
                        .unwrap_or(&format!("Request failed ({})", status.as_u16())).to_string();
                    return Err(FrostAuthError { code, status: status.as_u16(), retryable: false, message: msg, retry_after: None });
                }
                last_err = Some(FrostAuthError {
                    code: codes::SERVER_ERROR.into(),
                    status: status.as_u16(),
                    retryable: true,
                    message: payload["response"]["message"].as_str()
                        .unwrap_or("The licence server is having trouble").to_string(),
                    retry_after: None,
                });
                continue;
            }

            let has_error = !payload["error"].is_null();
            if has_error || !status.is_success() {
                let code = payload["response"]["errorCode"].as_str()
                    .map(String::from)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| match payload["error"].as_str() {
                        Some(s) if !s.is_empty() => s.to_string(),
                        _ => codes::SERVER_ERROR.to_string(),
                    });
                let msg = payload["response"]["message"].as_str()
                    .unwrap_or(&format!("Request failed ({})", status.as_u16())).to_string();
                return Err(FrostAuthError { code, status: status.as_u16(), retryable: false, message: msg, retry_after: None });
            }

            let data = payload["response"]["data"].clone();
            self.adopt(&data);
            return Ok(data);
        }
        Err(last_err.unwrap_or_else(|| FrostAuthError::retryable(codes::NETWORK, "Request failed")))
    }
}

fn last_err_wait(raw: &[u8]) -> u64 {
    let _ = raw;
    2
}

fn merge(dst: &mut Value, src: Value) {
    if let (Some(d), Some(s)) = (dst.as_object_mut(), src.as_object()) {
        for (k, v) in s {
            d.insert(k.clone(), v.clone());
        }
    }
}

fn url_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
