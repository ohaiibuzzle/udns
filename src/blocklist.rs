// Blocklist: parses a domain list and answers "is this name blocked?".
//
// Every entry blocks the domain itself and all of its subdomains
// ("*.example.com" and "example.com" mean the same thing).
// Allowed domains (and their subdomains) are never blocked, even if a more
// specific name is on the blocklist.
// To save RAM, only a 64-bit hash of each domain is kept, in a sorted Vec.
// That's 8 bytes per entry instead of 40+ for a HashSet<String>.

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::time::Duration;

pub struct Blocklist {
    hashes: Vec<u64>,
    allowed: Vec<u64>,
}

// ponytail: comparing hashes instead of strings can give a false positive with
// odds of about 1e-14 per query. Store full strings if that ever matters.
fn hash_domain(domain: &str) -> u64 {
    // DefaultHasher::new() uses fixed keys, so equal strings always hash equally.
    let mut hasher = DefaultHasher::new();
    hasher.write(domain.as_bytes());
    hasher.finish()
}

impl Blocklist {
    pub fn empty() -> Blocklist {
        Blocklist {
            hashes: Vec::new(),
            allowed: Vec::new(),
        }
    }

    /// `allowed` entries use the same formats as the list text.
    pub fn parse(text: &str, allowed: &[String]) -> Blocklist {
        Blocklist {
            hashes: parse_hashes(text),
            allowed: parse_hashes(&allowed.join("\n")),
        }
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// `name` must be lowercase, without the trailing dot.
    pub fn is_blocked(&self, name: &str) -> bool {
        has_suffix_in(&self.hashes, name) && !has_suffix_in(&self.allowed, name)
    }
}

/// Accepts wildcard lists ("*.x.com"), plain domain lists ("x.com") and
/// hosts files ("0.0.0.0 x.com"). Lines starting with # or ! are comments.
fn parse_hashes(text: &str) -> Vec<u64> {
    let mut hashes: Vec<u64> = Vec::new();
    for line in text.lines() {
        let line: &str = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        // In hosts-file lines the domain is the last word.
        let word: &str = match line.split_whitespace().last() {
            Some(word) => word,
            None => continue,
        };
        let without_star: &str = word.strip_prefix("*.").unwrap_or(word);
        let domain: String = without_star.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() || domain == "localhost" {
            continue;
        }
        hashes.push(hash_domain(&domain));
    }
    hashes.sort_unstable();
    hashes.dedup();
    hashes.shrink_to_fit();
    hashes
}

/// Checks "a.b.c", then "b.c", then "c" against the sorted hashes.
fn has_suffix_in(hashes: &[u64], name: &str) -> bool {
    let mut suffix: &str = name;
    loop {
        if hashes.binary_search(&hash_domain(suffix)).is_ok() {
            return true;
        }
        match suffix.find('.') {
            Some(dot) => suffix = &suffix[dot + 1..],
            None => return false,
        }
    }
}

/// Downloads (or reads) the list text. Blocking: call from spawn_blocking.
pub fn fetch(source: &str) -> Result<String, String> {
    if !source.starts_with("http://") && !source.starts_with("https://") {
        return std::fs::read_to_string(source).map_err(|e| format!("read {source}: {e}"));
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .into();
    let mut response = match agent.get(source).call() {
        Ok(response) => response,
        Err(e) => return Err(format!("download {source}: {e}")),
    };
    // ureq's default body limit is 10 MB; the biggest hagezi lists are larger.
    let text: Result<String, ureq::Error> = response
        .body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_string();
    text.map_err(|e| format!("download {source}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches() {
        let list = Blocklist::parse(
            "# comment\n! adblock comment\n\n*.ads.example.com\ntracker.net.\n0.0.0.0 Hosts.Example.org\n127.0.0.1 localhost\n",
            &[],
        );
        assert_eq!(list.len(), 3);
        assert!(list.is_blocked("ads.example.com"));
        assert!(list.is_blocked("x.y.ads.example.com"));
        assert!(!list.is_blocked("example.com"));
        assert!(!list.is_blocked("notads.example.com"));
        assert!(list.is_blocked("tracker.net"));
        assert!(list.is_blocked("cdn.tracker.net"));
        assert!(!list.is_blocked("nottracker.net"));
        assert!(list.is_blocked("hosts.example.org"));
        assert!(!list.is_blocked("localhost"));
        assert!(!list.is_blocked(""));
    }

    #[test]
    fn allowed_beats_blocked() {
        let allowed: Vec<String> =
            vec!["telemetry.example.com".to_string(), "*.ok.net".to_string()];
        let list = Blocklist::parse("example.com\nads.ok.net\n", &allowed);
        assert!(list.is_blocked("example.com"));
        assert!(list.is_blocked("ads.example.com"));
        assert!(!list.is_blocked("telemetry.example.com"));
        assert!(!list.is_blocked("eu.telemetry.example.com"));
        assert!(!list.is_blocked("ads.ok.net"));
        assert!(!list.is_blocked("ok.net"));
    }
}
