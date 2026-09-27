//! Redaction of untrusted/sensitive text before it is logged or rendered.
//!
//! Three concerns:
//! 1. Cluster output may carry control/ANSI sequences (terminal injection) →
//!    strip control characters ([`redact_text`]).
//! 2. A command string may contain secrets after flags like `--token` → mask
//!    those values ([`redact_command`]).
//! 3. Free-text error output (stderr) may echo a supplied secret back → mask
//!    flag values *and* high-entropy token-shaped substrings ([`redact_message`]).

const SENSITIVE_FLAGS: &[&str] = &[
    "--token",
    "--password",
    "--pass",
    "--secret",
    "--otp",
    "--bearer-token",
];
const MASK: &str = "***";

/// Remove ASCII/Unicode control characters (keeps normal printable text).
#[must_use]
pub fn redact_text(input: &str) -> String {
    input.chars().filter(|c| !c.is_control()).collect()
}

/// Strip control characters and mask values following sensitive flags.
/// Handles both `--token X` and `--token=X` forms.
#[must_use]
pub fn redact_command(input: &str) -> String {
    mask_tokens(&redact_text(input), false)
}

/// Strip control characters and mask secrets in free-text output.
///
/// Meant for e.g. an error message or `tsh` stderr that might echo a supplied
/// secret. In addition to the flag-based masking of [`redact_command`], this
/// masks any standalone high-entropy token-shaped word. Over-redaction is
/// acceptable here - this text only ever goes to the NDJSON log, never back to
/// the CLI.
#[must_use]
pub fn redact_message(input: &str) -> String {
    mask_tokens(&redact_text(input), true)
}

/// Returns true for a word that looks like a secret token: long, alphanumeric
/// (optionally with `_-+/=`), and mixing letters and digits - i.e. high entropy.
/// Deliberately conservative so it does not mask hostnames (dots), file paths
/// (slashes plus extensions), or short identifiers. Callers strip surrounding
/// punctuation and split URLs first (see [`mask_secret_parts`]).
fn looks_like_secret(word: &str) -> bool {
    const MIN_LEN: usize = 24;
    if word.len() < MIN_LEN {
        return false;
    }
    let mut has_alpha = false;
    let mut has_digit = false;
    for c in word.chars() {
        match c {
            'a'..='z' | 'A'..='Z' => has_alpha = true,
            '0'..='9' => has_digit = true,
            '_' | '-' | '+' | '/' | '=' => {}
            _ => return false, // any other char (e.g. '.') → not a bare token
        }
    }
    has_alpha && has_digit
}

/// Characters a bare token can be made of (base64 and hex alphabets).
const fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '=')
}

/// Characters of one URL path segment / query value / dotted label: the token
/// alphabet minus the `/` and `=` separators.
const fn is_segment_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+')
}

/// Mask the secret parts of one whitespace-separated word, keeping the rest.
/// First the word minus surrounding punctuation/quotes (`"abc…",` → `"***",`);
/// failing that, each `[A-Za-z0-9_+-]` run on its own, so a secret embedded in
/// a URL path (`/web/invite/<secret>`) or query (`?token=<secret>`) is masked
/// while the scheme, host and ordinary path segments stay readable. Runs are
/// judged by [`looks_like_secret`] alone, so hostnames and normal paths (short,
/// dotted labels) are untouched.
fn mask_secret_parts(word: &str) -> String {
    let start = word.len() - word.trim_start_matches(|c| !is_token_char(c)).len();
    let end = word.trim_end_matches(|c| !is_token_char(c)).len();
    if let (Some(pre), Some(core), Some(post)) =
        (word.get(..start), word.get(start..end), word.get(end..))
        && looks_like_secret(core)
    {
        return format!("{pre}{MASK}{post}");
    }
    let mut out = String::with_capacity(word.len());
    let mut run_start = None;
    for (i, c) in word.char_indices() {
        match (is_segment_char(c), run_start) {
            (true, None) => run_start = Some(i),
            (true, Some(_)) => {}
            (false, from) => {
                if let Some(from) = from {
                    push_masked(&mut out, word.get(from..i).unwrap_or_default());
                    run_start = None;
                }
                out.push(c);
            }
        }
    }
    if let Some(from) = run_start {
        push_masked(&mut out, word.get(from..).unwrap_or_default());
    }
    out
}

fn push_masked(out: &mut String, run: &str) {
    out.push_str(if looks_like_secret(run) { MASK } else { run });
}

/// Shared masking pass over whitespace-separated tokens. `entropy` also masks
/// bare high-entropy words (used for free-text messages, not command lines).
fn mask_tokens(cleaned: &str, entropy: bool) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut mask_next = false;

    for tok in cleaned.split_whitespace() {
        if mask_next {
            out.push(MASK.to_owned());
            mask_next = false;
            continue;
        }
        if let Some((flag, _val)) = tok.split_once('=')
            && SENSITIVE_FLAGS.contains(&flag)
        {
            out.push(format!("{flag}={MASK}"));
            continue;
        }
        if SENSITIVE_FLAGS.contains(&tok) {
            mask_next = true;
            out.push(tok.to_owned());
            continue;
        }
        if entropy {
            out.push(mask_secret_parts(tok));
            continue;
        }
        out.push(tok.to_owned());
    }

    out.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_control_and_ansi() {
        let dirty = "host\x1b[31mname\x07\n";
        assert_eq!(redact_text(dirty), "host[31mname");
    }

    #[test]
    fn masks_secret_flag_values() {
        assert_eq!(
            redact_command("tsh login --token abcd123 --proxy x"),
            "tsh login --token *** --proxy x"
        );
        assert_eq!(
            redact_command("tsh login --token=abcd123"),
            "tsh login --token=***"
        );
        assert!(!redact_command("tsh login --token abcd123").contains("abcd123"));
    }

    #[test]
    fn message_masks_echoed_secret_and_high_entropy_tokens() {
        // Flag form echoed back in an error.
        assert_eq!(
            redact_message("error: invalid --token abcd1234 supplied"),
            "error: invalid --token *** supplied"
        );
        // Bare high-entropy token-shaped word (e.g. a leaked join token).
        let masked = redact_message("login failed for token a1b2c3d4e5f6a7b8c9d0e1f2g3h4");
        assert!(!masked.contains("a1b2c3d4e5f6a7b8c9d0e1f2g3h4"));
        assert!(masked.contains("***"));
    }

    #[test]
    fn message_does_not_over_redact_normal_text() {
        // Hostnames (dots), short ids, and prose must survive.
        let msg = "could not reach node-01.root.example.com: connection refused";
        assert_eq!(redact_message(msg), msg);
        // A long alpha-only word (no digits) is not treated as a secret.
        let plain = "authenticationrequiredforthisoperationplease";
        assert_eq!(redact_message(plain), plain);
    }

    const SECRET: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";

    #[test]
    fn message_masks_quoted_secret() {
        let masked = redact_message(&format!("token \"{SECRET}\" not found"));
        assert_eq!(masked, "token \"***\" not found");
        let masked = redact_message(&format!("token '{SECRET}' not found"));
        assert_eq!(masked, "token '***' not found");
    }

    #[test]
    fn message_masks_secret_before_trailing_punctuation() {
        assert_eq!(
            redact_message(&format!("removed {SECRET}, done")),
            "removed ***, done"
        );
        assert_eq!(
            redact_message(&format!("bad token {SECRET}.")),
            "bad token ***."
        );
        assert_eq!(
            redact_message(&format!("(token: {SECRET})")),
            "(token: ***)"
        );
    }

    #[test]
    fn message_masks_secret_in_url_path() {
        assert_eq!(
            redact_message(&format!(
                "open https://proxy.example.com:443/web/invite/{SECRET}"
            )),
            "open https://proxy.example.com:443/web/invite/***"
        );
    }

    #[test]
    fn message_masks_secret_in_url_query() {
        assert_eq!(
            redact_message(&format!(
                "GET https://proxy/v1/join?token={SECRET}&x=1 failed"
            )),
            "GET https://proxy/v1/join?token=***&x=1 failed"
        );
    }

    #[test]
    fn message_keeps_ordinary_sentences_hosts_and_paths() {
        for msg in [
            "Error: \"node-01.root.example.com\" not found.",
            "dial tcp: lookup ec2-54-123-45-67.eu-west-1.compute.amazonaws.com: no such host",
            "see https://goteleport.com/docs/admin-guides/management/admin/troubleshooting/",
            "open /home/user/.tsh/keys/proxy.example.com/alice-x509.pem: permission denied",
            "access denied to perform action \"list\" on \"token\", retry later.",
        ] {
            assert_eq!(redact_message(msg), msg);
        }
    }
}
