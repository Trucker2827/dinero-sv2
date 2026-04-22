//! Minimal JSON-RPC client for dinerod.
//!
//! Only the RPCs the template provider needs — `getbestblockhash` for
//! tip detection and `getblocktemplate` for the actual template fetch.
//! Authentication: supports either a cookie file (default on a fresh
//! datadir) or explicit `user:password`.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

/// Dinerod JSON-RPC client.
pub struct RpcClient {
    http: Client,
    url: String,
    auth_header: String,
}

/// How to authenticate against dinerod.
#[derive(Clone, Debug)]
pub enum Auth {
    /// Path to `.cookie` file (format: `__cookie__:RANDOM`).
    Cookie(String),
    /// Explicit user + password (rpcuser / rpcpassword in dinero.conf).
    UserPass(String, String),
}

impl Auth {
    fn to_header(&self) -> Result<String> {
        let user_pass = match self {
            Auth::Cookie(p) => std::fs::read_to_string(Path::new(p))
                .with_context(|| format!("reading cookie {p}"))?
                .trim()
                .to_string(),
            Auth::UserPass(u, p) => format!("{u}:{p}"),
        };
        Ok(format!("Basic {}", B64.encode(user_pass)))
    }
}

#[derive(Serialize)]
struct Request<'a, T: Serialize> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: T,
}

impl RpcClient {
    /// Create a new RPC client.
    ///
    /// `url` example: `http://127.0.0.1:20998`
    pub fn new(url: String, auth: Auth) -> Result<Self> {
        Ok(Self {
            http: Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .context("building reqwest client")?,
            url,
            auth_header: auth.to_header()?,
        })
    }

    async fn call<P: Serialize>(&self, method: &str, params: P) -> Result<Value> {
        let req = Request {
            jsonrpc: "1.0",
            id: 0,
            method,
            params,
        };
        let resp = self
            .http
            .post(&self.url)
            .header("Authorization", &self.auth_header)
            .json(&req)
            .send()
            .await
            .with_context(|| format!("posting {method}"))?;
        let body: Value = resp.json().await.context("decoding RPC JSON")?;
        if let Some(err) =
            body.get("error")
                .and_then(|e| if e.is_null() { None } else { Some(e.clone()) })
        {
            return Err(anyhow!("rpc {method} error: {err}"));
        }
        Ok(body.get("result").cloned().unwrap_or_else(|| body.clone()))
    }

    /// Current tip hash (display-order hex, as dinerod serves it).
    pub async fn get_best_block_hash(&self) -> Result<String> {
        let v = self.call("getbestblockhash", serde_json::json!([])).await?;
        Ok(v.as_str().map(str::to_owned).unwrap_or_default())
    }

    /// Fetch a block template for the given payout address.
    pub async fn get_block_template(&self, address: &str) -> Result<Value> {
        self.call(
            "getblocktemplate",
            serde_json::json!([{ "address": address }]),
        )
        .await
    }
}
