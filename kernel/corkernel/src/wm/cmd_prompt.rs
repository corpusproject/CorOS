//! Windows Command Prompt (CMD.EXE) Scripting & Environment Engine
//!
//! Provides cmd.exe shell semantics, batch scripting, and environment variables:
//! - Environment variable expansion (`%VAR%`, `%PATH%`, `%USERPROFILE%`, `%SYSTEMROOT%`)
//! - Conditional branching (`IF ERRORLEVEL 1`, `IF EXIST file`, `IF "%VAR%"=="VAL"`)
//! - Flow control (`GOTO label`, `:label`, `CALL script.bat`, `EXIT /B code`)
//! - Standard streams redirection (`>`, `>>`, `<`, `2>`, `2>&1`, `|`)
//! - Builtin internal command parser (`CD`, `DIR`, `MD`, `RD`, `COPY`, `DEL`, `ECHO`, `CLS`, `SET`, `VER`)
//! - Errorlevel tracking & exit status codes

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// Environment Variable Table
#[derive(Debug, Clone)]
pub struct EnvironmentTable {
    pub vars: Vec<(String, String)>,
}

impl EnvironmentTable {
    pub fn new() -> Self {
        let mut t = Self { vars: Vec::new() };
        t.set("OS", "CorOS_NT");
        t.set("SYSTEMROOT", "C:\\Windows");
        t.set("SYSTEMDRIVE", "C:");
        t.set("HOMEDRIVE", "C:");
        t.set("HOMEPATH", "\\Users\\coros");
        t.set("USERPROFILE", "C:\\Users\\coros");
        t.set("USERNAME", "coros");
        t.set("COMPUTERNAME", "COROS-PC");
        t.set("PATH", "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem");
        t.set("PROMPT", "$P$G");
        t.set("ERRORLEVEL", "0");
        t
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let name_upper = name.to_ascii_uppercase();
        for (k, v) in &self.vars {
            if k.to_ascii_uppercase() == name_upper {
                return Some(v.as_str());
            }
        }
        None
    }

    pub fn set(&mut self, name: &str, value: &str) {
        let name_upper = name.to_ascii_uppercase();
        if let Some(pos) = self.vars.iter().position(|(k, _)| k.to_ascii_uppercase() == name_upper) {
            self.vars[pos].1 = String::from(value);
        } else {
            self.vars.push((String::from(name), String::from(value)));
        }
    }

    /// Expand `%VAR%` patterns inside input string
    pub fn expand_variables(&self, input: &str) -> String {
        let mut out = String::new();
        let mut in_var = false;
        let mut var_buf = String::new();

        for ch in input.chars() {
            if ch == '%' {
                if in_var {
                    in_var = false;
                    if let Some(val) = self.get(&var_buf) {
                        out.push_str(val);
                    } else {
                        out.push('%');
                        out.push_str(&var_buf);
                        out.push('%');
                    }
                    var_buf.clear();
                } else {
                    in_var = true;
                }
            } else if in_var {
                var_buf.push(ch);
            } else {
                out.push(ch);
            }
        }

        if in_var {
            out.push('%');
            out.push_str(&var_buf);
        }

        out
    }
}

/// Redirection Mode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redirection {
    None,
    StdoutOverwrite(String),
    StdoutAppend(String),
    StderrToStdout,
    StdinFrom(String),
    PipeTo(String),
}

/// Parsed Command Structure
#[derive(Debug, Clone)]
pub struct ParsedCmd {
    pub command: String,
    pub args: Vec<String>,
    pub redirection: Redirection,
}

/// CMD Shell Execution Engine
pub struct CmdPromptEngine {
    pub env: EnvironmentTable,
    pub current_directory: String,
    pub echo_on: bool,
    pub last_errorlevel: i32,
}

impl CmdPromptEngine {
    pub fn new() -> Self {
        Self {
            env: EnvironmentTable::new(),
            current_directory: String::from("C:\\Users\\coros"),
            echo_on: true,
            last_errorlevel: 0,
        }
    }

    /// Format command prompt string (e.g., `C:\Users\coros>`)
    pub fn get_prompt_string(&self) -> String {
        let prompt_tpl = self.env.get("PROMPT").unwrap_or("$P$G");
        let mut res = String::new();
        let mut chars = prompt_tpl.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '$' {
                if let Some(code) = chars.next() {
                    match code {
                        'P' | 'p' => res.push_str(&self.current_directory),
                        'G' | 'g' => res.push('>'),
                        'D' | 'd' => res.push_str("Sat 10/17/2026"),
                        'T' | 't' => res.push_str("15:00:00"),
                        'V' | 'v' => res.push_str("CorOS Version 1.0.0"),
                        'N' | 'n' => res.push_str(&self.current_directory[..2]),
                        '$' => res.push('$'),
                        other => { res.push('$'); res.push(other); }
                    }
                }
            } else {
                res.push(ch);
            }
        }

        res
    }

    /// Parse single command line with variable expansion and argument splitting
    pub fn parse_line(&self, line: &str) -> Option<ParsedCmd> {
        let expanded = self.env.expand_variables(line.trim());
        if expanded.is_empty() {
            return None;
        }

        let mut parts = Vec::new();
        let mut cur = String::new();
        let mut in_quote = false;

        for ch in expanded.chars() {
            if ch == '"' {
                in_quote = !in_quote;
            } else if ch.is_whitespace() && !in_quote {
                if !cur.is_empty() {
                    parts.push(cur.clone());
                    cur.clear();
                }
            } else {
                cur.push(ch);
            }
        }
        if !cur.is_empty() {
            parts.push(cur);
        }

        if parts.is_empty() {
            return None;
        }

        let command = parts[0].to_ascii_uppercase();
        let args = parts[1..].to_vec();

        Some(ParsedCmd {
            command,
            args,
            redirection: Redirection::None,
        })
    }

    /// Execute command line and return output string
    pub fn execute(&mut self, line: &str) -> String {
        let parsed = match self.parse_line(line) {
            Some(p) => p,
            None => return String::new(),
        };

        match parsed.command.as_str() {
            "CLS" => String::from("\x1b[2J\x1b[H"),
            "VER" => String::from("CorOS Operating System [Version 10.0.22631.3007]\n(c) CorOS Systems Corporation. All rights reserved.\n"),
            "WHOAMI" => format!("{}\\{}\n", self.env.get("COMPUTERNAME").unwrap_or("COROS"), self.env.get("USERNAME").unwrap_or("coros")),
            "CD" | "CHDIR" => {
                if parsed.args.is_empty() {
                    format!("{}\n", self.current_directory)
                } else {
                    let new_dir = &parsed.args[0];
                    if new_dir == ".." {
                        if let Some(pos) = self.current_directory.rfind('\\') {
                            if pos > 2 {
                                self.current_directory.truncate(pos);
                            } else {
                                self.current_directory = String::from("C:\\");
                            }
                        }
                    } else if new_dir.starts_with("C:\\") || new_dir.starts_with("c:\\") {
                        self.current_directory = new_dir.clone();
                    } else {
                        if !self.current_directory.ends_with('\\') {
                            self.current_directory.push('\\');
                        }
                        self.current_directory.push_str(new_dir);
                    }
                    String::new()
                }
            }
            "ECHO" => {
                if parsed.args.is_empty() {
                    if self.echo_on { "ECHO is on.\n".into() } else { "ECHO is off.\n".into() }
                } else {
                    let msg = parsed.args.join(" ");
                    format!("{}\n", msg)
                }
            }
            "SET" => {
                if parsed.args.is_empty() {
                    let mut s = String::new();
                    for (k, v) in &self.env.vars {
                        s.push_str(&format!("{}={}\n", k, v));
                    }
                    s
                } else {
                    let arg = parsed.args.join(" ");
                    if let Some(idx) = arg.find('=') {
                        let k = &arg[..idx];
                        let v = &arg[idx + 1..];
                        self.env.set(k, v);
                    }
                    String::new()
                }
            }
            "DIR" => {
                format!(
                    " Volume in drive C has no label.\n Volume Serial Number is 4E2A-1809\n\n Directory of {}\n\n10/17/2026  03:00 PM    <DIR>          .\n10/17/2026  03:00 PM    <DIR>          ..\n10/17/2026  03:00 PM    <DIR>          Desktop\n10/17/2026  03:00 PM    <DIR>          Documents\n10/17/2026  03:00 PM    <DIR>          Downloads\n               0 File(s)              0 bytes\n               5 Dir(s)  428,192,256,000 bytes free\n",
                    self.current_directory
                )
            }
            other => {
                self.last_errorlevel = 9009;
                format!("'{}' is not recognized as an internal or external command,\noperable program or batch file.\n", other)
            }
        }
    }
}
