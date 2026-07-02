//! User MFA devices (`tsh mfa ls`).
//!
//! Note: the security-key fields in the CLI output (`publicKeyCbor`,
//! `credentialId`, `aaguid`, …) are **public-key credential metadata, not
//! secrets** — the private key never leaves the authenticator. We keep only
//! display fields regardless.

/// One registered second-factor device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MfaDevice {
    pub name: String,
    /// Device kind: `totp`, `webauthn`, `sso`, … (derived from the CLI output).
    pub kind: String,
    pub added: String,
    pub last_used: String,
}
