# FrostAuth-Rust-Example 🌟

Rust example for the [FrostAuth license key API](https://www.frostauth.cc/).

Add `frostauth-sdk` to your Cargo project and import it as `frostauth`. See `src/main.rs` for the console example.

## Bugs

Open an issue if you can reproduce the failure with the example. Include your FrostAuth SDK version, `rustc --version`, and the exact error. Remove license keys and tokens before posting.

## Security practices

- If you use VMProtect or Themida, put the protector's markers around the license checks.
- Run integrity checks during the session. End the session if a check detects tampering.
- Keep files you need to protect on the server. Clear temporary buffers when the app is done with them.
- Use the API to recheck licenses and enforce access to server resources there. A local `isValid` flag alone can't enforce access.

## Copyright License

Copyright (c) 2026 FrostAuth. All rights reserved.

This SDK is distributed under Elastic License 2.0. See [LICENSE](LICENSE).

## What is FrostAuth?

FrostAuth is a cloud licensing API with device-bound keys, app accounts, and a dashboard for managing licenses and tracking activations. SDKs are available for C++, C#, Go, Java, JavaScript, Python, and Rust. For product questions, join the [FrostAuth Discord](https://www.frostauth.cc/discord).

## Requirements

Use a current stable Rust toolchain with Cargo. The Windows MSVC toolchain also needs the Visual Studio C++ build tools and Windows SDK. Dependencies are listed in `Cargo.toml`.

## Build

Run these commands from the SDK directory after setting your product details in the example.

```bash
cargo build --locked --release
cargo run --locked --release
```

Cargo puts the example binary in `target/release/`. To use the SDK from another crate, add a path dependency.

```toml
[dependencies]
frostauth = { package = "frostauth-sdk", path = "../path/to/sdk/langs/rust" }
```

## `FrostAuthClient` instance definition

Copy the owner ID and product ID from the FrostAuth dashboard into `src/main.rs`. Set the version you plan to ship.

```rust
use frostauth::{FrostAuthClient, Options};

let app = FrostAuthClient::new(Options {
    owner: "0809y7MP".into(),                                  // dashboard → product → owner id
    product: "33abf48a-8e33-4df5-a4bd-d79195704d52".into(),    // dashboard → product → product id
    version: "1.0.0".into(),                                   // must match the version you ship
    ..Default::default()
})?;
```

## Initialize application

Call `init()` first. It fetches the public product catalog and checks the returned key ID and Ed25519 public key against the SDK's pin. The SDK uses the pinned key to verify signed responses.

```rust
app.init().await?;
```

## Display application information

Fetch application information after activation or sign-in returns a session token.

```rust
let app_data = app.app_data().await?;
println!("App version: {}", app_data["product"]["version"]);
```

## Check session validation

After activation or sign-in, call `validate()` to check the license again. If the API rejects a stale session token, the SDK retries once with the stored license key when it has one.

```rust
app.validate().await?;
```

## Check blacklist status

Check the blacklist with an active session. The API also checks it during activation and sign-in.

```rust
app.check_blacklist().await?;
```

## Login with username/password

Supply the account credentials. If the account uses two-factor authentication, include its code.

```rust
let snap = app.login(&username, &password, None, None, None).await?;
```

## Register with username/password/key

```rust
let snap = app.register(&key, &username, &password, None, None).await?;
```

## Upgrade user with key

Apply the key to the existing account. Sign in after the upgrade to open a session.

```rust
app.upgrade(&username, &password, &key).await?;
println!("Upgraded. Sign in to use the new licence.");
let snap = app.login(&username, &password, None, None, None).await?;
```

## Login with just license key

For a key-only product, activate with the license key. The API applies the product's device rules and issues a session token where supported.

```rust
let snap = app.activate(&key, None, None).await?;
```

Pass the build hash and device label as `Some(value)` when you supply them.

## User Data

Read the current user, account, device, and subscriptions from the snapshot.

```rust
let snap = app.snapshot();
println!("Username: {}", snap.get("user").unwrap_or(&serde_json::json!("")));
println!("IP: {}", snap.pointer("/account/lastIp").unwrap_or(&serde_json::json!("?")));
println!("Device Id: {}", snap.pointer("/device/id").unwrap_or(&serde_json::json!("?")));
```

## Check subscription of user

Use the tier name you set in the dashboard. The example checks for `pro`.

```rust
let pro = snap.get("subscriptions").and_then(|s| s.as_array()).map(|subs| {
    subs.iter().any(|s| s.get("tier").and_then(|t| t.as_str()).unwrap_or("").eq_ignore_ascii_case("pro"))
}).unwrap_or(false);
if !pro {
    println!("This feature needs a Pro subscription.");
}
```

## Application variables

Edit shared variables in the dashboard. The API applies each variable's tier and version rules on read.

```rust
println!("MOTD: {}", app.variable("maintenance_message").await?);
```

## User Variables

Read or update values for the signed-in user. The API rejects writes to variables the operator marked read-only.

```rust
println!("{:?}", app.list_vars().await?);
let theme = app.get_var("theme").await?;    // one variable's value
app.set_var("theme", "dark").await?;        // write it back
println!("theme: {theme}");
```

## Application Logs

Send an event to the operator's log. The product's logging settings determine where it appears.

```rust
app.log("client started, integrity check passed").await?;
```

## Ban the user

Use an active session to ban the current device and IP address. The call also ends the local session.

```rust
app.ban("debugger detected").await?; // reason shows on next login + dashboard
```

## Server-side webhooks

Call a webhook by its configured ID. The API stores the destination and the client supplies the parameters and body.

```rust
let res = app.webhook("discord", "", r#"{"content":"Hello from FrostAuth"}"#, "").await?;
println!("upstream: {} ok: {}", res["status"], res["ok"]);
```

## Heartbeat & offline

After activation or sign-in, start the heartbeat. `check_offline()` verifies the cached signed assertion, including its expiry. If the assertion has expired or fails verification during an outage, the next failed heartbeat clears the active state. An invalid API response signature also stops the heartbeat and clears the active state.

Set `Options::offline_grace_seconds` to change the 15-minute fallback for sessions that received no assertion.

```rust
let _hb = app.start_heartbeat(None)?; // server cadence until stop/close
// ...
let (ok, reason) = app.check_offline();
if !ok { println!("offline: {reason}"); }
// ...
app.stop_heartbeat();
app.close();
```

## Compatibility checks

On Linux, run `bash sdk/compatibility/run.sh rust` from the Cerberus root. The suite tests activation, validation, signed errors, and offline heartbeat behavior against a local API fixture.

This SDK initialized successfully against the live FrostAuth API on November 18, 2026. A live activation and heartbeat require a disposable license.

## SDK layout

- `src/lib.rs` contains the SDK.
- `src/main.rs` runs the interactive example.
