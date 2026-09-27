//! A dependency-free secret string. Domain stays dependency-free, so it can't
//! use the `zeroize` crate the outer layers rely on; [`SecretString`] is the
//! minimal equivalent for secrets that live inside domain entities.

/// A secret string: masked `Debug`, no `Display`, and its buffer is wiped
/// (best effort, in safe code) when dropped. Read it with
/// [`SecretString::expose`] only where the raw value is really needed (an argv
/// element, a one-time display), never to log it.
///
/// The wipe overwrites the whole allocation with zeros and passes it through
/// [`core::hint::black_box`] so the stores aren't elided as dead writes. That
/// is the same idea as `zeroize` minus its volatile writes (which need
/// `unsafe`, forbidden here).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretString(String);

impl SecretString {
    #[must_use]
    pub const fn new(value: String) -> Self {
        Self(value)
    }

    /// The raw secret. Keep the borrow short; don't copy it into a plain
    /// `String` that outlives the call.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Move the value out (no copy: the allocation moves with it), to hand it
    /// straight to other wiping storage such as `zeroize::Zeroizing`.
    #[must_use]
    pub fn into_inner(mut self) -> String {
        core::mem::take(&mut self.0)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A display form safe to render: a short prefix (enough to tell tokens
    /// apart) plus `…` for long values, `****` for short ones, where even a
    /// prefix would give away too much of the secret.
    #[must_use]
    pub fn masked(&self) -> String {
        const MIN_LEN_FOR_PREFIX: usize = 12;
        const PREFIX: usize = 4;
        if self.0.chars().count() < MIN_LEN_FOR_PREFIX {
            return "****".to_owned();
        }
        let mut out: String = self.0.chars().take(PREFIX).collect();
        out.push('…');
        out
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl core::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        // `into_bytes` reuses the allocation; `clear` + `resize` up to the
        // capacity rewrites every byte of it (spare capacity included) without
        // reallocating.
        let mut bytes = core::mem::take(&mut self.0).into_bytes();
        let cap = bytes.capacity();
        bytes.clear();
        bytes.resize(cap, 0);
        core::hint::black_box(&mut bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_value() {
        let s = SecretString::new("a1b2c3d4e5f6a7b8".to_owned());
        assert_eq!(format!("{s:?}"), "<redacted>");
    }

    #[test]
    fn masked_shows_a_short_prefix_only_for_long_values() {
        let long = SecretString::new("a1b2c3d4e5f6a7b8".to_owned());
        assert_eq!(long.masked(), "a1b2…");
        let short = SecretString::new("tbot-ci".to_owned());
        assert_eq!(short.masked(), "****");
        assert_eq!(short.expose(), "tbot-ci");
    }
}
