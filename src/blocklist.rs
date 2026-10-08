// Blocklist: parses a domain list and answers "is this name blocked?".
//
// Every entry blocks the domain itself and all of its subdomains
// ("*.example.com" and "example.com" mean the same thing).
// To save RAM, only a 64-bit hash of each domain is kept, in a sorted Vec.
// That's 8 bytes per entry instead of 40+ for a HashSet<String>.

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::time::Duration;

pub struct Blocklist {
    hashes: Vec<u64>,
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
        Blocklist { hashes: Vec::new() }
    }

    /// Accepts wildcard lists ("*.x.com"), plain domain lists ("x.com") and
    /// hosts files ("0.0.0.0 x.com"). Lines starting with # or ! are comments.
    pub fn parse(text: &str) -> Blocklist {
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
        Blocklist { hashes }
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// `name` must be lowercase, without the trailing dot.
    /// Checks "a.b.c", then "b.c", then "c".
    pub fn is_blocked(&self, name: &str) -> bool {
        let mut suffix: &str = name;
        loop {
            if self.hashes.binary_search(&hash_domain(suffix)).is_ok() {
                return true;
            }
            match suffix.find('.') {
                Some(dot) => suffix = &suffix[dot + 1..],
                None => return false,
            }
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
}
