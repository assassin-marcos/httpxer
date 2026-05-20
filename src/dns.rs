//! DNS resolution — A/AAAA + CNAME for each hostname, in parallel.
//!
//! Uses hickory-resolver with Cloudflare upstreams, bypassing the system
//! resolver entirely. Same pattern portwave uses: predictable per-query
//! timeouts and immune to /etc/hosts / glibc-NSS interference.

use futures::stream::{FuturesUnordered, StreamExt};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioAsyncResolver;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub host: String,
    pub ips: Vec<IpAddr>,      // A + AAAA flattened
    pub cname: Option<String>, // first CNAME directly under `host`, if any
    pub error: Option<String>, // resolve error reason, if no records
}

pub fn build_resolver(timeout_secs: u64) -> Arc<TokioAsyncResolver> {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(timeout_secs);
    opts.attempts = 2;
    opts.cache_size = 0; // per-run results — don't carry stale entries
    Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::cloudflare(),
        opts,
    ))
}

async fn resolve_one(resolver: Arc<TokioAsyncResolver>, host: String) -> DnsRecord {
    // Race the CNAME and A/AAAA lookups in parallel. The CNAME lookup
    // returns an error (NoRecordsFound) for hosts that are directly A —
    // that's fine, we just record None for cname.
    let cname_fut = resolver.lookup(host.clone(), RecordType::CNAME);
    let ip_fut = resolver.lookup_ip(host.clone());
    let (cname_res, ip_res) = tokio::join!(cname_fut, ip_fut);

    let cname = cname_res.ok().and_then(|lookup| {
        lookup.iter().find_map(|rdata| match rdata {
            RData::CNAME(name) => Some(name.to_string().trim_end_matches('.').to_string()),
            _ => None,
        })
    });

    match ip_res {
        Ok(lookup) => {
            let ips: Vec<IpAddr> = lookup.iter().collect();
            DnsRecord {
                host,
                error: if ips.is_empty() {
                    Some("no A/AAAA records".to_string())
                } else {
                    None
                },
                ips,
                cname,
            }
        }
        Err(e) => DnsRecord {
            host,
            ips: vec![],
            cname,
            error: Some(format!("{}", e)),
        },
    }
}

pub async fn resolve_many(
    resolver: Arc<TokioAsyncResolver>,
    hosts: Vec<String>,
    concurrency: usize,
) -> Vec<DnsRecord> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set: FuturesUnordered<tokio::task::JoinHandle<DnsRecord>> = FuturesUnordered::new();
    for h in hosts {
        let sem = sem.clone();
        let resolver = resolver.clone();
        set.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            resolve_one(resolver, h).await
        }));
    }
    let mut out = Vec::new();
    while let Some(joined) = set.next().await {
        if let Ok(r) = joined {
            out.push(r);
        }
    }
    out
}
