//! FrostAuth Rust SDK — console example. Mirrors sdk/example.mjs output.
//! Fill owner/product from your dashboard; set version to the build you ship.

use chrono::{DateTime, Local};
use frostauth::{FrostAuthClient, Options};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

/// Locale-style timestamp, e.g. 9/16/2026, 6:08:02 PM (local zone, like JS
/// `Date#toLocaleString()`).
fn loc(iso: &str) -> String {
    match DateTime::parse_from_rfc3339(iso) {
        Ok(dt) => dt.with_timezone(&Local).format("%-m/%-d/%Y, %-I:%M:%S %p").to_string(),
        Err(_) => "unknown".to_string(),
    }
}

#[tokio::main]
async fn main() {
    let client = match FrostAuthClient::new(Options {
        owner: "0809wkVP".into(),
        product: "33abf48a-8e33-4df5-a4bd-d79195704d52".into(),
        version: "1.0.2".into(),
        // base_url: "https://api.frostauth.cc".into(),
        ..Default::default()
    }) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("An error occurred: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = client.init().await {
        eprintln!("An error occurred: {e}");
        std::process::exit(1);
    }

    println!("[1] Login\n[2] Register\n[3] License\n[4] Upgrade");
    print!("Select an option: ");
    io::stdout().flush().unwrap();
    let mut option = String::new();
    io::stdin().read_line(&mut option).unwrap();
    let option = option.trim().to_string();

    let ask = |prompt: &str| -> String {
        print!("{prompt}");
        io::stdout().flush().unwrap();
        let mut s = String::new();
        io::stdin().read_line(&mut s).unwrap();
        s.trim().to_string()
    };

    let result = match option.as_str() {
        "1" => client.login(&ask("Username: "), &ask("Password: "), None, None, None).await,
        "2" => {
            client
                .register(&ask("License: "), &ask("Username: "), &ask("Password: "), None, None)
                .await
        }
        "3" => client.activate(&ask("License: "), None, None).await,
        "4" => {
            let username = ask("Username: ");
            let password = ask("Password: ");
            let license = ask("License: ");
            match client.upgrade(&username, &password, &license).await {
                Ok(_) => {
                    println!("Upgraded. Sign in to use the new licence.");
                    client.login(&username, &password, None, None, None).await
                }
                Err(e) => Err(e),
            }
        }
        _ => {
            println!("Invalid option selected.");
            return;
        }
    };
    if let Err(e) = result {
        eprintln!("An error occurred: {e}");
        std::process::exit(1);
    }

    dashboard(&client).await;
}

/// Snapshot-backed profile readout. Everything here comes from the local
/// snapshot (populated by activate/register/login on every plan), so it works
/// with or without a session token — unlike app_data/online, which are
/// session-backed and fail on plans without tokenSystem.
/// Only prints fields the backend actually returns (licenseView + accountView
/// + device + product) — no invented email/key/plan lookups.
fn show_user(snap: &serde_json::Value) {
    let str_of = |v: &serde_json::Value, key: &str| -> String {
        v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
    };
    let num_of = |v: &serde_json::Value, key: &str| -> Option<String> {
        match v.get(key) {
            Some(x) if x.is_number() => Some(x.to_string()),
            Some(x) => x.as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()),
            None => None,
        }
    };
    let when = |iso: &str| -> String {
        if iso.is_empty() {
            return "—".to_string();
        }
        let s = loc(iso);
        if s == "unknown" { "—".to_string() } else { s }
    };

    let null = serde_json::Value::Null;
    let license = snap.get("license").unwrap_or(&null);
    let account = snap.get("account").unwrap_or(&null);
    let device = snap.get("device").unwrap_or(&null);
    let product = snap.get("product").unwrap_or(&null);

    let mut who = snap.get("user").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if who.is_empty() {
        who = str_of(account, "username");
    }
    if who.is_empty() {
        who = "unknown".to_string();
    }

    let mut tier = str_of(license, "tier");
    if tier.is_empty() {
        tier = "starter".to_string();
    }
    let mut state = str_of(license, "status");
    if state.is_empty() {
        state = "unknown".to_string();
    }

    let mut expiry = str_of(license, "expiresAt");
    if expiry.is_empty() {
        if let Some(subs) = snap.get("subscriptions").and_then(|s| s.as_array()) {
            for s in subs {
                let e = s.get("expiresAt").and_then(|x| x.as_str()).unwrap_or("");
                if !e.is_empty() {
                    expiry = e.to_string();
                    break;
                }
            }
        }
    }
    let valid_line = if expiry.is_empty() {
        "never".to_string()
    } else {
        let base = when(&expiry);
        match DateTime::parse_from_rfc3339(&expiry) {
            Ok(dt) => {
                let diff = dt.with_timezone(&Local).signed_duration_since(Local::now());
                let days = if diff.num_seconds() <= 0 {
                    0
                } else {
                    (diff.num_seconds() + 86399) / 86400
                };
                format!("{base} ({days}d left)")
            }
            Err(_) => base,
        }
    };

    let mut prod_line = str_of(product, "name");
    if prod_line.is_empty() {
        prod_line = "—".to_string();
    }
    let prod_ver = str_of(product, "version");
    if !prod_ver.is_empty() {
        prod_line.push_str(&format!(" v{prod_ver}"));
    }

    let used = num_of(license, "devicesUsed").unwrap_or("—".to_string());
    let devices_line = if license.get("unlimitedDevices").and_then(|x| x.as_bool()).unwrap_or(false) {
        format!("{used} (unlimited)")
    } else if let Some(lim) = num_of(license, "deviceLimit") {
        format!("{used} / {lim}")
    } else {
        used
    };

    let mut dev_line = str_of(device, "id");
    if dev_line.is_empty() {
        dev_line = "—".to_string();
    }
    let mut ip_line = str_of(account, "lastIp");
    if ip_line.is_empty() {
        ip_line = "—".to_string();
    }

    println!();
    println!("Signed in as {who}");
    println!("----------------------------------------------");
    println!("  Licence ..... {state} ({tier})");
    println!("  IP Address .. {ip_line}");
    println!("  Product ..... {prod_line}");
    println!("  Devices ..... {devices_line}");
    println!("  Valid Until . {valid_line}");
    println!("  Device Id ... {dev_line}");
    println!("  First Seen .. {}", when(&str_of(account, "createdAt")));
    println!("  Last Seen ... {}", when(&str_of(account, "lastLoginAt")));
    println!("----------------------------------------------");
}

async fn dashboard(client: &std::sync::Arc<FrostAuthClient>) {
    // Snapshot-backed only. Session-backed reads (app_data/online) are
    // plan-gated (tokenSystem: Developer/Pro) and print "unknown" on other
    // plans, so they are not shown here at all.
    let snap = client.snapshot();

    show_user(&snap);
    println!();

    let subs = snap["subscriptions"].as_array().cloned().unwrap_or_default();
    for (i, sub) in subs.iter().enumerate() {
        let name = sub
            .get("tier")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| sub.get("status").and_then(|x| x.as_str()))
            .unwrap_or("");
        let expiry = match sub.get("expiresAt").and_then(|x| x.as_str()) {
            Some(iso) if !iso.is_empty() => loc(iso),
            _ => "never".to_string(),
        };
        println!("[{}/{}] | Subscription: {} - Expiry: {}", i + 1, subs.len(), name, expiry);
    }

    let created = snap
        .get("account")
        .and_then(|a| a.get("createdAt"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    println!("Created at: {}", if created.is_empty() { "unknown".into() } else { loc(created) });
    let last_login = snap
        .get("account")
        .and_then(|a| a.get("lastLoginAt"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    println!("Last Login: {}", if last_login.is_empty() { "unknown".into() } else { loc(last_login) });
    let first_expiry = subs
        .iter()
        .find_map(|s| s.get("expiresAt").and_then(|x| x.as_str()))
        .unwrap_or("");
    println!("Expires: {}", if first_expiry.is_empty() { "never".into() } else { loc(first_expiry) });

    let payload = serde_json::json!({ "content": "Hello from FrostAuth" }).to_string();
    match client.webhook("discord", "", &payload, "").await {
        Ok(res) => {
            let status = res.get("status").cloned().unwrap_or(serde_json::Value::Null);
            let ok = res.get("ok").cloned().unwrap_or(serde_json::Value::Null);
            println!("\nWebhook test: upstream {status} (ok: {ok})");
        }
        Err(e) => println!("\nWebhook test failed: {} {e}", e.code),
    }

    // Build-hash extra: hash THIS binary's contents when the product has
    // CHECK HASH enabled; pass Some(hash) to activate/register/login.
    let self_hash = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .map(|bytes| {
            let digest = Sha256::digest(&bytes);
            digest.iter().map(|b| format!("{b:02x}")).collect::<String>()
        })
        .unwrap_or_else(|| "unavailable".into());
    println!("\nBuild hash (this file):");
    println!("  {self_hash}");
    println!("  Pass it as Some(self_hash) to activate/register/login when the product requires it.");

    println!("\nClosing app in 10 seconds...");
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    let _ = client.logout().await;
}
