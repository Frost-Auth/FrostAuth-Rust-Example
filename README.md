# FrostAuth-Rust-Example 🌟

FrostAuth Rust example SDK for https://www.frostauth.cc license key API auth.

This example ships the SDK source directly — `src/lib.rs` as the `frostauth`
crate. Add the path to your `Cargo.toml`, mirror `src/main.rs`, and you're
integrated. Deps from crates.io (tokio, reqwest, ed25519-dalek, …).

## Bugs

If you're running this example with no significant changes and something's broken,
open an issue with your FrostAuth version, Rust toolchain (`rustc -V`), and the
exact error text.

We do **NOT** provide support for wiring FrostAuth into your project. If the
build steps below don't make sense yet, learn some Rust first (the Book/YouTube),
then come back.

## Security practices

* Ship releases through a protector (VMProtect on the binary) and put license
checks behind their markers, not just `main()`.
* Run frequent integrity checks so patched memory kills the session instead of
granting access.
* Never write a downloaded file to disk if you don't want the user to have it.
Execute in memory and wipe the buffer the moment you're done.
* Treat every client answer as advisory. The server re-checks the license on
each call — don't add a local `valid` boolean that bypasses it.

FrostAuth signs every response and pins the server key, but no API survives a
client that trusts itself. Obfuscation + integrity checks stop tampering; the
API stops key sharing.

## Copyright License

Copyright (c) 2026 FrostAuth. All rights reserved.

This SDK is distributed under Elastic License 2.0. See [LICENSE](LICENSE).

## What is FrostAuth?

FrostAuth is a cloud licensing platform that protects your software from piracy
and unauthorized access. Hardware-locked licenses, secure auth, real-time
analytics, and a dashboard your customers never see. Client SDKs for Rust (this
repo), C++, C#, Python, Go, Java, and JavaScript. Come ask questions on
Discord: https://www.frostauth.cc/discord

## Requirements

* Rust 1.75+ (edition 2021). Windows MSVC needs the C++ redistributable +
Windows SDK — if linking dies with `ucrt.lib not found`, use the GNU toolchain:
`rustup toolchain install stable-x86_64-pc-windows-gnu`, then prefix every
cargo command with `rustup run stable-x86_64-pc-windows-gnu`.

## Build

```bash
cd FrostAuth-Rust-Example
cargo build --release          # binary: target/release/frostauth-example(.exe)
cargo run --release            # run the console example
```

First build downloads ~40 crates — allow a few minutes. Integrate by adding
the crate path to your `Cargo.toml`:

```toml
[dependencies]
frostauth = { path = "../frostauth" }
```

## ` frostAuth` instance definition — `Options`

Open your FrostAuth dashboard, pick your product, and copy the three values
into [`src/main.rs`](src/main.rs):

```rust
let app = FrostAuth::new(Options {
    owner: "YOUR-OWNER-ID".into(),     // dashboard → product → owner id
    product: "YOUR-PRODUCT-ID".into(), // dashboard → product → product id
    version: "1.0.0".into(),           // must match the version you ship
    ..Default::default()
})?;
```

## Initialize application

You must call this before anything else. It fetches the public catalog and
pins the server's signing key (TOFU) — every later response is Ed25519-checked
against it, so a MITM serving a fake key aborts here instead of later.

```rust
app.init().await?;
```

## Display application information

```rust
let app_data = app.app_data().await.unwrap_or(serde_json::json!({}));
let version = app_data.get("product").and_then(|p| p.get("version"));
println!("App Version: {}", version.unwrap_or(&serde_json::json!("?")));
```

## Check session validation

Re-checks the license/session with the server. Falls back from a stale session
token to the stored license key once.

```rust
app.validate().await?; // Err → session dead, exit, don't continue into paid code
```

## Check blacklist status

Whether this device/IP/key is blacklisted. Optional: the server already
refuses blacklisted callers on login/register, so this is just an early exit
for clients that want to close before showing UI.

```rust
app.check_blacklist().await?; // Err → blocked, exit
```

## Login with username/password

```rust
let snap = app.login(&username, &password, None, None, None).await?;
```

(`twofa`, build hash, and label ride the last three `Option`s.)

## Register with username/password/key

```rust
let snap = app.register(&key, &username, &password, None, None).await?;
```

## Upgrade user with key

Attaches a license key to an existing app user (adds time). Unlike login and
register this opens **no session** — sign the user in after a successful
upgrade.

```rust
app.upgrade(&username, &password, &key).await?;
println!("Upgraded. Sign in to use the new licence.");
let snap = app.login(&username, &password, None, None, None).await?;
```

## Login with just license key

For key-only products. Binds the key to this machine and opens a session —
no username needed.

```rust
let snap = app.activate(&key, None, None).await?;
```

Extra build evidence: `app.activate(&key, Some(self_hash), Some(label))`
when the product has hash checks on.

## User Data

Everything about the current session lives in the snapshot:

```rust
let snap = app.snapshot();
println!("Username: {}", snap.get("user").unwrap_or(&serde_json::json!("")));
println!("IP: {}", snap.pointer("/account/lastIp").unwrap_or(&serde_json::json!("?")));
println!("Device Id: {}", snap.pointer("/device/id").unwrap_or(&serde_json::json!("?")));
```

## Check subscription of user

Gate features by tier. Compare against the tier name you configured on the
dashboard — exact match, case-insensitive on the server side.

```rust
let pro = snap.get("subscriptions").and_then(|s| s.as_array()).map(|subs| {
    subs.iter().any(|s| s.get("tier").and_then(|t| t.as_str()).unwrap_or("").eq_ignore_ascii_case("pro"))
}).unwrap_or(false);
if !pro { println!("This feature needs a Pro subscription."); return; }
```

## Application variables

Server-side strings, global for all users (feature flags, MOTD, config).
Read-only from the client; edit them on the dashboard. Tier- and
version-gated server-side.

```rust
println!("MOTD: {}", app.variable("maintenance_message").await?);
```

## User Variables

Per-user key/value pairs. Read and write them unless the operator marked one
read-only (balances, ranks — server-writable only).

```rust
let vars = app.list_vars().await?;          // every variable on this user
let theme = app.get_var("theme").await?;    // one variable's value
app.set_var("theme", "dark").await?;        // write it back
println!("theme: {theme}");
```

## Application Logs

Ship an event to the operator log. Good for anti-debug alerts and crash
breadcrumbs. If the operator set a Discord webhook, it lands there instead of
the dashboard (dashboard logs rotate after 30 days).

```rust
app.log("client started, integrity check passed").await?;
```

## Ban the user

Blacklists the HWID + IP. Call it when your integrity checks catch tampering.
Only works after login. Ends the local session either way.

```rust
app.ban("debugger detected").await?; // reason shows on next login + dashboard
```

## Server-sided webhooks

Fire an operator-configured webhook by id. The destination URL lives on the
server — the client only supplies params/body, so secrets never ship in your
binary. Tier-gated like files/variables.

```rust
let res = app.webhook("discord", "", r#"{"content":"Hello from FrostAuth"}"#, "").await?;
println!("upstream: {} ok: {}", res["status"], res["ok"]);
```

## Download file

> Currently disabled server-side (route unmounted). `file()` returns
> `SERVER_ERROR` until file storage ships. The snippet below is the
> integration pattern for when it lands.

```rust
let bytes = app.file("loader").await?;
std::fs::write("loader.bin", &bytes)?;
```

## Changing username

Lets a signed-in user rename themselves (password re-checked server-side).

```rust
let res = app.change_username(&new_name, &password).await?;
println!("Renamed to {}", res["username"]);
```

## Heartbeat & offline

`validate()` on a timer keeps the session fresh. The SDK caches a signed
offline assertion — when the network drops, `check_offline()` verifies it
locally so the app keeps working inside the grace window.

```rust
let _hb = app.start_heartbeat(None)?; // server cadence until stop/close
// ...
let (ok, reason) = app.check_offline();
if !ok { println!("offline: {reason}"); }
// ...
app.stop_heartbeat();
app.close();
```

## SDK layout

* `src/lib.rs` — the whole SDK as the `frostauth` crate.
* `src/main.rs` — the interactive demo this README walks through.
