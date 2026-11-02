//! RFC 7230 HTTP/1.1 Micro-Server & Client Protocol Engine for CorOS.
//! 100% in-house implementation supporting:
//! - Standard HTTP methods: GET, POST, HEAD, PUT, DELETE
//! - HTTP status lines and standard status codes (200, 201, 301, 400, 403, 404, 500)
//! - Header parsing and generation (Content-Type, Content-Length, Host, Connection)
//! - Embedded web server request dispatching and REST response generation.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HttpMethod {
    Get,
    Post,
    Head,
    Put,
    Delete,
    Options,
}

impl HttpMethod {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "HEAD" => Some(Self::Head),
            "PUT" => Some(Self::Put),
            "DELETE" => Some(Self::Delete),
            "OPTIONS" => Some(Self::Options),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Head => "HEAD",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub path: String,
    pub query: String,
    pub version: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Parse an incoming HTTP request stream.
    pub fn parse(raw_bytes: &[u8]) -> Option<Self> {
        let text = String::from_utf8_lossy(raw_bytes);
        let header_end = text.find("\r\n\r\n")?;
        let header_part = &text[..header_end];
        let body_start = header_end + 4;

        let mut lines = header_part.split("\r\n");
        let request_line = lines.next()?;

        let mut parts = request_line.split(' ');
        let method_str = parts.next()?;
        let full_path = parts.next()?;
        let version = parts.next().unwrap_or("HTTP/1.1");

        let method = HttpMethod::from_str(method_str)?;

        let (path, query) = if let Some(q_idx) = full_path.find('?') {
            (&full_path[..q_idx], &full_path[q_idx + 1..])
        } else {
            (full_path, "")
        };

        let mut headers = BTreeMap::new();
        for line in lines {
            if let Some(col) = line.find(':') {
                let key = line[..col].trim().to_lowercase();
                let val = line[col + 1..].trim();
                headers.insert(key, String::from(val));
            }
        }

        let body = if body_start < raw_bytes.len() {
            raw_bytes[body_start..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            method,
            path: String::from(path),
            query: String::from(query),
            version: String::from(version),
            headers,
            body,
        })
    }
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: &'static str,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status_code: u16, content_type: &str, body: Vec<u8>) -> Self {
        let status_text = match status_code {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            _ => "Unknown",
        };

        let mut headers = BTreeMap::new();
        headers.insert(String::from("server"), String::from("CorOS-MicroServer/1.0 (BareMetal x86_64)"));
        headers.insert(String::from("content-type"), String::from(content_type));
        headers.insert(String::from("content-length"), format!("{}", body.len()));
        headers.insert(String::from("connection"), String::from("close"));

        Self {
            status_code,
            status_text,
            headers,
            body,
        }
    }

    pub fn ok_html(html: &str) -> Self {
        Self::new(200, "text/html; charset=utf-8", html.as_bytes().to_vec())
    }

    pub fn ok_json(json: &str) -> Self {
        Self::new(200, "application/json", json.as_bytes().to_vec())
    }

    pub fn not_found() -> Self {
        let msg = "<h1>404 Not Found</h1><p>CorOS Kernel HTTP Server: The requested resource does not exist.</p>";
        Self::new(404, "text/html", msg.as_bytes().to_vec())
    }

    /// Serialize HTTP response to wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        let status_line = format!("HTTP/1.1 {} {}\r\n", self.status_code, self.status_text);
        out.extend_from_slice(status_line.as_bytes());

        for (k, v) in &self.headers {
            let hdr_line = format!("{}: {}\r\n", k, v);
            out.extend_from_slice(hdr_line.as_bytes());
        }

        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);

        out
    }
}
