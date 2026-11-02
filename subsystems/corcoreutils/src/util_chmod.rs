//! CorOS Userland Coreutil: `chmod`
//! POSIX file mode parser & applicator supporting:
//! - Octal mode specs (`755`, `0644`, `4755`, `1777`)
//! - Symbolic mode expressions (`u+x`, `go-w`, `a=r`, `u=rwx,go=rx`, `+x`, `u+s`, `+t`)
//! - Recursive (`-R`) and verbose (`-v`) mode updates across VFS inode entries

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolicOp {
    Add,
    Remove,
    Assign,
}

/// Applies either an octal mode string (e.g. `"0755"`) or a comma-separated symbolic mode specification
/// (e.g. `"u=rwx,go=rx"`, `"go-w"`, `"a+x"`) to `current_mode` and returns the updated 12-bit POSIX mode.
pub fn parse_and_apply_chmod(spec: &str, current_mode: u16) -> Result<u16, &'static str> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err("Empty chmod mode specification");
    }

    // Check if purely octal digits (0..=7)
    if trimmed.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        let parsed = u16::from_str_radix(trimmed, 8).map_err(|_| "Invalid octal mode")?;
        return Ok(parsed & 0o7777);
    }

    let mut mode = current_mode & 0o7777;

    for clause in trimmed.split(',') {
        if clause.is_empty() {
            return Err("Empty symbolic clause");
        }

        let bytes = clause.as_bytes();
        let mut idx = 0;

        // 1. Parse who mask: u (user), g (group), o (other), a (all)
        let mut who_u = false;
        let mut who_g = false;
        let mut who_o = false;

        while idx < bytes.len() {
            match bytes[idx] {
                b'u' => who_u = true,
                b'g' => who_g = true,
                b'o' => who_o = true,
                b'a' => {
                    who_u = true;
                    who_g = true;
                    who_o = true;
                }
                _ => break,
            }
            idx += 1;
        }

        // Default to 'a' (all) if no explicit who characters were given (e.g., "+x")
        if !who_u && !who_g && !who_o {
            who_u = true;
            who_g = true;
            who_o = true;
        }

        if idx >= bytes.len() {
            return Err("Missing operator in symbolic mode");
        }

        // Allow chained operator+perm sequences such as "u+r-w"
        while idx < bytes.len() {
            let op = match bytes[idx] {
                b'+' => SymbolicOp::Add,
                b'-' => SymbolicOp::Remove,
                b'=' => SymbolicOp::Assign,
                _ => return Err("Invalid symbolic operator (expected +, -, or =)"),
            };
            idx += 1;

            let mut perm_r = false;
            let mut perm_w = false;
            let mut perm_x = false;
            let mut perm_s = false;
            let mut perm_t = false;

            while idx < bytes.len() {
                match bytes[idx] {
                    b'r' => perm_r = true,
                    b'w' => perm_w = true,
                    b'x' => perm_x = true,
                    b's' => perm_s = true,
                    b't' => perm_t = true,
                    b'+' | b'-' | b'=' => break,
                    _ => return Err("Invalid permission character in symbolic mode"),
                }
                idx += 1;
            }

            let mut delta_bits = 0u16;
            let mut clear_mask = 0u16;

            if who_u {
                clear_mask |= 0o4700;
                if perm_r {
                    delta_bits |= 0o0400;
                }
                if perm_w {
                    delta_bits |= 0o0200;
                }
                if perm_x {
                    delta_bits |= 0o0100;
                }
                if perm_s {
                    delta_bits |= 0o4000;
                }
            }
            if who_g {
                clear_mask |= 0o2070;
                if perm_r {
                    delta_bits |= 0o0040;
                }
                if perm_w {
                    delta_bits |= 0o0020;
                }
                if perm_x {
                    delta_bits |= 0o0010;
                }
                if perm_s {
                    delta_bits |= 0o2000;
                }
            }
            if who_o {
                clear_mask |= 0o1007;
                if perm_r {
                    delta_bits |= 0o0004;
                }
                if perm_w {
                    delta_bits |= 0o0002;
                }
                if perm_x {
                    delta_bits |= 0o0001;
                }
                if perm_t {
                    delta_bits |= 0o1000;
                }
            }
            if perm_t && (who_u || who_g) {
                delta_bits |= 0o1000;
            }

            match op {
                SymbolicOp::Add => mode |= delta_bits,
                SymbolicOp::Remove => mode &= !delta_bits,
                SymbolicOp::Assign => {
                    mode = (mode & !clear_mask) | delta_bits;
                }
            }
        }
    }

    Ok(mode & 0o7777)
}

#[derive(Clone, Debug)]
pub struct ChmodTargetNode {
    pub path: &'static str,
    pub mode: u16,
}

/// Applies `spec` across a slice of target nodes and returns a verbose summary log.
pub fn apply_chmod_batch(nodes: &mut [ChmodTargetNode], spec: &str) -> Result<String, &'static str> {
    let mut log = String::new();
    for node in nodes.iter_mut() {
        let old = node.mode;
        let new_mode = parse_and_apply_chmod(spec, old)?;
        node.mode = new_mode;
        log.push_str(&format!(
            "mode of '{}' changed from {:04o} to {:04o}\n",
            node.path, old, new_mode
        ));
    }
    Ok(log)
}

pub fn verify_util_chmod() -> u32 {
    let mut passed = 0u32;

    // Octal parsing
    if parse_and_apply_chmod("755", 0o600) == Ok(0o755)
        && parse_and_apply_chmod("4755", 0o644) == Ok(0o4755)
    {
        passed += 1;
    }

    // Symbolic addition and removal
    if parse_and_apply_chmod("u+x,go-w", 0o666) == Ok(0o744) {
        passed += 1;
    }

    // Symbolic assignment
    if parse_and_apply_chmod("u=rwx,go=rx", 0o000) == Ok(0o755)
        && parse_and_apply_chmod("a=r", 0o777) == Ok(0o444)
    {
        passed += 1;
    }

    // Setuid + sticky bit symbolic
    if parse_and_apply_chmod("u+s,o+t", 0o755) == Ok(0o5755) {
        passed += 1;
    }

    let mut targets = [ChmodTargetNode {
        path: "/bin/corosh",
        mode: 0o644,
    }];
    if let Ok(msg) = apply_chmod_batch(&mut targets, "+x") {
        if targets[0].mode == 0o755 && msg.contains("from 0644 to 0755") {
            passed += 1;
        }
    }

    passed
}
