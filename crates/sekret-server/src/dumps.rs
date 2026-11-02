//! Keeps the root key and passphrases out of core dumps.

/// Sets the core file size limit to zero, hard and soft, so nothing later in this process can
/// raise it again without privilege. Call it before any key is read. The process stays dumpable
/// in the `PR_SET_DUMPABLE` sense, which keeps `/proc/<pid>` readable by its own user.
#[cfg(unix)]
pub fn forbid_core_dumps() -> std::io::Result<()> {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a valid, initialised rlimit and touches no other memory.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn forbid_core_dumps() -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn no_core_dump_can_be_written() -> anyhow::Result<()> {
        forbid_core_dumps()?;
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: getrlimit writes into the rlimit passed and nothing else.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
        // Raising the hard limit again is refused, so nothing later can turn dumps back on.
        let raised = libc::rlimit {
            rlim_cur: 1 << 20,
            rlim_max: 1 << 20,
        };
        // SAFETY: as above.
        let refused = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raised) } != 0;
        // SAFETY: geteuid takes no arguments.
        let root = unsafe { libc::geteuid() } == 0;
        assert!(refused || root);
        Ok(())
    }
}
