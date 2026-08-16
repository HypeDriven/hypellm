//! What the operating system is actually enforcing about this process.
//!
//! Specification 20.1 requires a dedicated unprivileged user, a system-call
//! sandbox, disabled core dumps, and memory locking for secret pages. The
//! router implements none of them, and cannot: `setuid`, `seccomp`, `setrlimit`
//! and `mlock` are all `unsafe` FFI, which specification 18.2 forbids
//! workspace-wide. They have to come from the systemd unit or the container
//! runtime (`DI-003`).
//!
//! That leaves a gap this module fills. A deployment can *believe* it applied
//! those directives and be wrong — a typo in a unit file, a container runtime
//! that drops `SystemCallFilter`, a `LimitCORE` that never took — and nothing
//! would say so. The router cannot apply the hardening, but it can **read what
//! was applied** and report what is missing, because Linux publishes all of it
//! as text in `/proc/self`.
//!
//! # What this is not
//!
//! Not enforcement. Every finding is a warning, never a refusal: a container
//! that runs as uid 0 with everything else locked down is a real deployment,
//! and a router that refused to start would be substituting its own opinion for
//! the operator's on a question it cannot see the whole of.
//!
//! Not portable. `/proc` is Linux. On any other platform, or with `/proc`
//! unmounted, every reading is `Unknown` and the router says nothing rather
//! than warning about a file it could not read.
//!
//! Not a substitute for reading the unit file. It sees the *result*, so it can
//! say "no seccomp filter is active" but not "your `SystemCallFilter` line is
//! misspelled".

/// What could be determined about one hardening property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finding {
    /// The property is in the state specification 20.1 asks for.
    Applied,
    /// The property is readable and is not in that state.
    Missing,
    /// The property could not be read: not Linux, `/proc` unmounted, or a
    /// kernel that does not publish this field.
    ///
    /// Deliberately distinct from `Missing`. Reporting "no sandbox" on a
    /// platform where the check does not work would train an operator to
    /// ignore the warning, which costs more than the warning is worth.
    Unknown,
}

impl Finding {
    /// Whether this warrants telling the operator about.
    #[must_use]
    pub const fn is_missing(self) -> bool {
        matches!(self, Self::Missing)
    }
}

/// What the operating system is enforcing about this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// Whether the process runs as a user other than root.
    ///
    /// Specification 20.1's "dedicated unprivileged user". The router cannot
    /// drop privilege, so this only reports how it was started.
    pub unprivileged: Finding,
    /// Whether core dumps are disabled.
    ///
    /// Specification 20.1's "core dumps disabled or restricted". This matters
    /// more here than in an ordinary service: the release profile uses
    /// `panic = "abort"`, so a dump is *likely* on a panic, and the process
    /// holds provider credentials, the store MAC key, and session material in
    /// memory. A dump is a copy of all of it on disk, readable by whoever can
    /// read the dump directory.
    pub core_dumps_disabled: Finding,
    /// Whether a seccomp filter is active.
    ///
    /// Specification 20.1's "system-call sandbox". Read from `Seccomp:` in
    /// `/proc/self/status`: 0 is disabled, 1 is strict mode, 2 is filter mode.
    pub seccomp: Finding,
    /// Whether `no_new_privs` is set.
    ///
    /// Not named by specification 20.1 directly, but it is what stops a setuid
    /// binary reachable from this process from regaining privilege, and it is
    /// set by the same systemd directive block. A deployment that has it is
    /// almost certainly the one that applied the rest.
    pub no_new_privs: Finding,
    /// Whether the process holds no effective capabilities.
    ///
    /// A non-root process with `CAP_SYS_ADMIN` is not meaningfully
    /// unprivileged, so this is the check that stops `unprivileged` from being
    /// read as more than it says.
    pub no_capabilities: Finding,
}

impl Hardening {
    /// Read the current process's hardening state.
    #[must_use]
    pub fn detect() -> Self {
        let status = std::fs::read_to_string("/proc/self/status").ok();
        let limits = std::fs::read_to_string("/proc/self/limits").ok();
        Self::from_proc(status.as_deref(), limits.as_deref())
    }

    /// Parse from the text of `/proc/self/status` and `/proc/self/limits`.
    ///
    /// Split from [`Self::detect`] because the interesting cases are states
    /// this process is not in: a hardened deployment, a setuid binary, a kernel
    /// without seccomp. A test that can only look at itself cannot reach any of
    /// them, and would pass whether or not the parsing was right.
    #[must_use]
    pub fn from_proc(status: Option<&str>, limits: Option<&str>) -> Self {
        Self {
            unprivileged: match effective_uid_of(status) {
                Some(0) => Finding::Missing,
                Some(_) => Finding::Applied,
                None => Finding::Unknown,
            },
            core_dumps_disabled: match core_limit_of(limits) {
                Some(0) => Finding::Applied,
                Some(_) => Finding::Missing,
                None => Finding::Unknown,
            },
            seccomp: match status_field(status, "Seccomp:") {
                Some("0") => Finding::Missing,
                Some(_) => Finding::Applied,
                None => Finding::Unknown,
            },
            no_new_privs: match status_field(status, "NoNewPrivs:") {
                Some("0") => Finding::Missing,
                Some(_) => Finding::Applied,
                None => Finding::Unknown,
            },
            no_capabilities: match status_field(status, "CapEff:") {
                // A hex mask; all zeroes means none held. Compared by parsing
                // rather than by string equality because the field width has
                // changed across kernel versions.
                Some(mask) => match u64::from_str_radix(mask, 16) {
                    Ok(0) => Finding::Applied,
                    Ok(_) => Finding::Missing,
                    Err(_) => Finding::Unknown,
                },
                None => Finding::Unknown,
            },
        }
    }

    /// Every missing property, as a stable identifier and an explanation.
    ///
    /// The explanation names the systemd directive that supplies it, because
    /// the useful form of this warning is one an operator can act on without
    /// first working out which of specification 20.1's items it refers to.
    #[must_use]
    pub fn missing(&self) -> Vec<(&'static str, &'static str)> {
        let mut out = Vec::new();
        if self.unprivileged.is_missing() {
            out.push((
                "unprivileged_user",
                "running as uid 0 and unable to drop privilege — `setuid` needs unsafe FFI, \
                 which the workspace forbids. Run as a dedicated unprivileged user \
                 (systemd `User=`).",
            ));
        }
        if self.no_capabilities.is_missing() {
            out.push((
                "no_capabilities",
                "holding effective capabilities, so it is not meaningfully unprivileged \
                 even if its uid is not 0 (systemd `CapabilityBoundingSet=` and \
                 `AmbientCapabilities=`).",
            ));
        }
        if self.core_dumps_disabled.is_missing() {
            out.push((
                "core_dumps_disabled",
                "core dumps are enabled. The release profile aborts on panic and this \
                 process holds credentials, the store MAC key, and session material in \
                 memory, so a dump writes all of it to disk (systemd `LimitCORE=0`).",
            ));
        }
        if self.seccomp.is_missing() {
            out.push((
                "syscall_sandbox",
                "no seccomp filter is active, so specification 20.1's system-call sandbox \
                 is absent (systemd `SystemCallFilter=`).",
            ));
        }
        if self.no_new_privs.is_missing() {
            out.push((
                "no_new_privs",
                "`no_new_privs` is not set, so a setuid binary reachable from this process \
                 could regain privilege (systemd `NoNewPrivileges=yes`).",
            ));
        }
        out
    }
}

/// The effective uid from the text of `/proc/self/status`.
///
/// `Uid: real effective saved filesystem` — the *effective* one is what
/// privilege actually follows, and the one that differs on a setuid binary.
fn effective_uid_of(status: Option<&str>) -> Option<u32> {
    status_field_raw(status, "Uid:")?
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
}

/// The soft core-dump limit from the text of `/proc/self/limits`.
///
/// The columns are `Limit`, `Soft Limit`, `Hard Limit`, `Units`, and the *soft*
/// limit is the one that governs. Located by name rather than by row index
/// because the row order is not a kernel guarantee.
fn core_limit_of(limits: Option<&str>) -> Option<u64> {
    for line in limits?.lines() {
        let Some(rest) = line.strip_prefix("Max core file size") else {
            continue;
        };
        let soft = rest.split_whitespace().next()?;
        // "unlimited" is the widest possible value, not an unreadable one.
        return if soft == "unlimited" {
            Some(u64::MAX)
        } else {
            soft.parse().ok()
        };
    }
    None
}

/// A whitespace-delimited field from `/proc/self/status`, first value only.
fn status_field<'a>(status: Option<&'a str>, name: &str) -> Option<&'a str> {
    status_field_raw(status, name)?.split_whitespace().next()
}

/// The raw remainder of a `/proc/self/status` line, after its label.
fn status_field_raw<'a>(status: Option<&'a str>, name: &str) -> Option<&'a str> {
    status?.lines().find_map(|line| line.strip_prefix(name))
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::expect_used,
    reason = "test module: fixtures are indexed directly and failure is a panic"
)]
mod tests {
    use super::*;

    /// A `/proc/self/status` body for a hardened deployment.
    const HARDENED: &str = "Name:\thypellm-router\nUid:\t1000\t1000\t1000\t1000\n\
                            CapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n\
                            Seccomp_filters:\t1\n";
    /// The same fields for a deployment that applied none of it.
    const BARE: &str = "Name:\thypellm-router\nUid:\t0\t0\t0\t0\n\
                        CapEff:\t000001ffffffffff\nNoNewPrivs:\t0\nSeccomp:\t0\n";

    const CORE_OFF: &str = "Limit  Soft Limit  Hard Limit  Units\n\
                            Max core file size        0         unlimited  bytes\n";
    const CORE_ON: &str = "Limit  Soft Limit  Hard Limit  Units\n\
                           Max core file size        unlimited  unlimited  bytes\n";

    #[test]
    fn a_hardened_process_reports_nothing_missing() {
        let hardening = Hardening::from_proc(Some(HARDENED), Some(CORE_OFF));
        assert_eq!(hardening.unprivileged, Finding::Applied);
        assert_eq!(hardening.core_dumps_disabled, Finding::Applied);
        assert_eq!(hardening.seccomp, Finding::Applied);
        assert_eq!(hardening.no_new_privs, Finding::Applied);
        assert_eq!(hardening.no_capabilities, Finding::Applied);
        assert!(
            hardening.missing().is_empty(),
            "a fully hardened process warned anyway: {:?}",
            hardening.missing()
        );
    }

    #[test]
    fn an_unhardened_process_reports_every_item_specification_20_1_names() {
        let hardening = Hardening::from_proc(Some(BARE), Some(CORE_ON));
        let missing: Vec<&str> = hardening.missing().into_iter().map(|(id, _)| id).collect();
        assert_eq!(
            missing,
            vec![
                "unprivileged_user",
                "no_capabilities",
                "core_dumps_disabled",
                "syscall_sandbox",
                "no_new_privs",
            ]
        );

        // Every warning has to be actionable, so each names the directive that
        // supplies it. A warning an operator cannot act on is noise, and noise
        // is how the actionable ones stop being read.
        for (id, explanation) in hardening.missing() {
            assert!(
                explanation.contains("systemd"),
                "{id} does not say how to fix it: {explanation}"
            );
        }
    }

    #[test]
    fn an_unreadable_proc_reports_unknown_and_warns_about_nothing() {
        // `/proc` is Linux. On any other platform every reading must be
        // `Unknown` and the router must say nothing: warning about a file it
        // could not read would train an operator to ignore the warning, which
        // costs more than the warning is worth.
        let hardening = Hardening::from_proc(None, None);
        assert_eq!(hardening.unprivileged, Finding::Unknown);
        assert_eq!(hardening.core_dumps_disabled, Finding::Unknown);
        assert_eq!(hardening.seccomp, Finding::Unknown);
        assert_eq!(hardening.no_new_privs, Finding::Unknown);
        assert_eq!(hardening.no_capabilities, Finding::Unknown);
        assert!(hardening.missing().is_empty());

        // A body present but missing the fields is the same case: a kernel that
        // does not publish `Seccomp:` must not read as "no sandbox".
        let partial = Hardening::from_proc(Some("Name:\tx\nUid:\t1000\t1000\t1000\t1000\n"), None);
        assert_eq!(partial.unprivileged, Finding::Applied);
        assert_eq!(partial.seccomp, Finding::Unknown);
        assert!(partial.missing().is_empty());
    }

    #[test]
    fn the_uid_read_is_the_effective_one_not_the_real_one() {
        // A setuid-root binary reports `Uid: 1000 0 0 0` — real 1000, effective
        // 0. Reading the first field would call that unprivileged, which is
        // exactly the case worth warning about. The two are equal in any
        // ordinary run, so this is the only way to catch the wrong field.
        let setuid = "Uid:\t1000\t0\t0\t0\n";
        assert_eq!(effective_uid_of(Some(setuid)), Some(0));
        assert_eq!(
            Hardening::from_proc(Some(setuid), None).unprivileged,
            Finding::Missing
        );

        assert_eq!(effective_uid_of(Some("Uid:\t0\t1000\t1000\t1000\n")), Some(1000));
        assert_eq!(effective_uid_of(Some("Name:\tx\n")), None);
        assert_eq!(effective_uid_of(Some("Uid:\t1000\n")), None);
        assert_eq!(effective_uid_of(Some("Uid:\tabc\tdef\n")), None);
        assert_eq!(effective_uid_of(None), None);
    }

    #[test]
    fn the_core_limit_read_is_the_soft_one_and_unlimited_is_not_unreadable() {
        // The soft limit governs. Reading the hard limit would report a process
        // with `LimitCORE=0` and an unlimited hard ceiling as dumping cores.
        assert_eq!(core_limit_of(Some(CORE_OFF)), Some(0));
        // And "unlimited" is the widest value, not a parse failure — treating
        // it as unreadable would silence the warning in the one case that most
        // needs it.
        assert_eq!(core_limit_of(Some(CORE_ON)), Some(u64::MAX));
        assert_eq!(
            Hardening::from_proc(None, Some(CORE_ON)).core_dumps_disabled,
            Finding::Missing
        );

        // A restricted-but-non-zero limit still dumps, so it is still missing.
        let restricted = "Max core file size        4096      unlimited  bytes\n";
        assert_eq!(core_limit_of(Some(restricted)), Some(4096));
        assert_eq!(
            Hardening::from_proc(None, Some(restricted)).core_dumps_disabled,
            Finding::Missing
        );

        assert_eq!(core_limit_of(Some("Max open files  1024  4096  files\n")), None);
        assert_eq!(core_limit_of(None), None);
    }

    #[test]
    fn capabilities_are_parsed_as_a_mask_not_compared_as_a_string() {
        // The field width has changed across kernel versions, so matching
        // "0000000000000000" literally would report a capability-free process
        // on a kernel with a different width as holding capabilities.
        for zero in ["0000000000000000", "00000000", "0"] {
            let status = format!("CapEff:\t{zero}\n");
            assert_eq!(
                Hardening::from_proc(Some(&status), None).no_capabilities,
                Finding::Applied,
                "width {zero} misread"
            );
        }
        let held = "CapEff:\t0000000000200000\n";
        assert_eq!(
            Hardening::from_proc(Some(held), None).no_capabilities,
            Finding::Missing
        );
    }

    #[test]
    fn this_process_is_readable_and_is_not_root() {
        // The detection path itself, against the real `/proc`. Weak by
        // construction — the test suite is one ordinary process — so it asserts
        // only what is true of any ordinary process and leaves the
        // discriminating work to the fixtures above.
        let hardening = Hardening::detect();
        assert_ne!(
            hardening.unprivileged,
            Finding::Missing,
            "the test suite should not be running as root"
        );
    }
}
