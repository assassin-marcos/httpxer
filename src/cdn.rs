//! Live CDN-range fetch per run (user-chosen behaviour). Pulls the
//! published prefix lists from Cloudflare, AWS (CloudFront), Fastly, and
//! Google Cloud in parallel with a 10-second per-provider budget. Saves
//! the merged result to `~/.httpxer/cdn-cache.txt` so a subsequent run
//! with no network still has the previous-known table.
//!
//! Akamai/Imperva/Stackpath are intentionally NOT covered here — they
//! don't publish prefix lists; the right move is ASN→prefix expansion
//! via RIPEstat, which adds startup latency without a clear win for v0.1.

use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Default)]
pub struct CdnTable {
    entries: Vec<(IpNetwork, String)>,
}

impl CdnTable {
    pub fn lookup(&self, ip: IpAddr) -> Option<&str> {
        for (net, tag) in &self.entries {
            if net.contains(ip) {
                return Some(tag.as_str());
            }
        }
        None
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

fn cache_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        let mut p = PathBuf::from(home);
        p.push(".httpxer");
        p.push("cdn-cache.txt");
        return p;
    }
    PathBuf::from("/tmp/.httpxer-cdn-cache.txt")
}

fn parse_cache(s: &str) -> Vec<(IpNetwork, String)> {
    s.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (cidr, tag) = line.split_once('|')?;
            let n = cidr.parse::<IpNetwork>().ok()?;
            Some((n, tag.to_string()))
        })
        .collect()
}

fn write_cache(entries: &[(IpNetwork, String)]) {
    let path = cache_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut buf = String::with_capacity(entries.len() * 30);
    buf.push_str("# httpxer CDN cache — written on last successful fetch\n");
    for (net, tag) in entries {
        buf.push_str(&format!("{}|{}\n", net, tag));
    }
    let _ = std::fs::write(&path, buf);
}

async fn fetch_text(url: &str) -> Option<String> {
    // Plain wreq client — no emulation needed for CDN provider APIs (they're
    // unprotected JSON / text endpoints, not WAF-fronted). Cert verification
    // off so this still works on systems with stale CA bundles.
    let client = wreq::Client::builder()
        .timeout(Duration::from_secs(10))
        .cert_verification(false)
        .build()
        .ok()?;
    let resp = client.get(url).send().await.ok()?;
    resp.text().await.ok()
}

async fn fetch_cloudflare() -> Vec<(IpNetwork, String)> {
    let mut out = Vec::new();
    for url in &[
        "https://www.cloudflare.com/ips-v4",
        "https://www.cloudflare.com/ips-v6",
    ] {
        if let Some(body) = fetch_text(url).await {
            for line in body.lines() {
                if let Ok(n) = line.trim().parse::<IpNetwork>() {
                    out.push((n, "cloudflare".to_string()));
                }
            }
        }
    }
    out
}

/// Fetch the AWS IP-ranges feed ONCE and split it into:
///   - `cloudfront` prefixes (httpx categorizes these as `cdn`)
///   - all other AWS prefixes (httpx categorizes these as `cloud`/`aws`)
///
/// The split lets `load_cdn_table` push CLOUDFRONT entries FIRST in the
/// linear-scan vector so a CLOUDFRONT-specific lookup beats the
/// generic-AWS catch-all when prefixes overlap. Matches httpx's
/// behaviour against e.g. `3.78.154.254` (EC2 EU-Central — non-CloudFront
/// AWS IP that previously showed `cdn:""` in httpxer output but
/// `cdn_name:aws cdn_type:cloud` in httpx).
async fn fetch_aws_all() -> (Vec<(IpNetwork, String)>, Vec<(IpNetwork, String)>) {
    let Some(body) = fetch_text("https://ip-ranges.amazonaws.com/ip-ranges.json").await else {
        return (vec![], vec![]);
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        return (vec![], vec![]);
    };
    let mut cloudfront = Vec::new();
    let mut aws = Vec::new();
    for (arr_key, cidr_key) in &[("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")] {
        if let Some(arr) = v.get(*arr_key).and_then(|p| p.as_array()) {
            for p in arr {
                let is_cf =
                    p.get("service").and_then(|s| s.as_str()) == Some("CLOUDFRONT");
                if let Some(c) = p.get(*cidr_key).and_then(|s| s.as_str()) {
                    if let Ok(n) = c.parse::<IpNetwork>() {
                        if is_cf {
                            cloudfront.push((n, "cloudfront".to_string()));
                        } else {
                            aws.push((n, "aws".to_string()));
                        }
                    }
                }
            }
        }
    }
    (cloudfront, aws)
}

async fn fetch_fastly() -> Vec<(IpNetwork, String)> {
    let Some(body) = fetch_text("https://api.fastly.com/public-ip-list").await else {
        return vec![];
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        return vec![];
    };
    let mut out = Vec::new();
    for key in &["addresses", "ipv6_addresses"] {
        if let Some(arr) = v.get(*key).and_then(|a| a.as_array()) {
            for p in arr {
                if let Some(c) = p.as_str() {
                    if let Ok(n) = c.parse::<IpNetwork>() {
                        out.push((n, "fastly".to_string()));
                    }
                }
            }
        }
    }
    out
}

async fn fetch_google_cloud() -> Vec<(IpNetwork, String)> {
    let Some(body) = fetch_text("https://www.gstatic.com/ipranges/cloud.json").await else {
        return vec![];
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        return vec![];
    };
    let mut out = Vec::new();
    if let Some(arr) = v.get("prefixes").and_then(|p| p.as_array()) {
        for p in arr {
            for key in &["ipv4Prefix", "ipv6Prefix"] {
                if let Some(c) = p.get(*key).and_then(|s| s.as_str()) {
                    if let Ok(n) = c.parse::<IpNetwork>() {
                        out.push((n, "google".to_string()));
                    }
                }
            }
        }
    }
    out
}

/// Live-fetch the four major published CDN prefix lists in parallel.
/// On total failure (no provider responded), falls back to the on-disk
/// cache. Returns an empty table if both fail — `cdn` field will just be
/// empty in the output, which is what httpx does without -td anyway.
pub async fn load_cdn_table(skip_fetch: bool) -> CdnTable {
    if skip_fetch {
        return CdnTable::default();
    }
    let (cf, (cfr, aws), fa, gc) = tokio::join!(
        fetch_cloudflare(),
        fetch_aws_all(),
        fetch_fastly(),
        fetch_google_cloud(),
    );
    let mut entries =
        Vec::with_capacity(cf.len() + cfr.len() + aws.len() + fa.len() + gc.len());
    // Order matters — `lookup()` returns the FIRST matching prefix. Push
    // narrower / higher-priority providers (CDNs) before broader ones
    // (generic AWS) so an IP that's both CLOUDFRONT and generic-AWS tags
    // as `cloudfront`, not `aws`.
    entries.extend(cf);
    entries.extend(cfr);
    entries.extend(fa);
    entries.extend(gc);
    entries.extend(aws);
    if entries.is_empty() {
        // All providers failed → fall back to disk cache.
        if let Ok(s) = std::fs::read_to_string(cache_path()) {
            let cached = parse_cache(&s);
            if !cached.is_empty() {
                eprintln!(
                    "[!] CDN providers unreachable, using cached table ({} ranges)",
                    cached.len()
                );
                return CdnTable { entries: cached };
            }
        }
        eprintln!("[!] CDN providers unreachable and no cache — cdn field will be empty");
        return CdnTable::default();
    }
    write_cache(&entries);
    CdnTable { entries }
}
