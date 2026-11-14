# Path Traversal (CWE-22) & SSRF (CWE-918) Patterns

## 1. Path Traversal (`path_traversal`, CWE-22)

**What to look for:**
- File-system read/write/download/include sinks (`open`, `fs.readFile`, `res.sendFile`, `new File`, `Files.readAllBytes`, `file_get_contents`, `File.ReadAllText`, `os.Open`) receiving a filename or subpath from request input (`req.query`, `$_GET`, `@RequestParam`, etc.).

**False-positive checks (do NOT report when present):**
- The path is canonicalized (`realpath`, `getCanonicalPath`, `Path.GetFullPath`, `filepath.Clean`) **and** verified to start with the intended base directory (`resolved.startsWith(baseDir)`).
- Only an allow-listed fixed filename or basename without directory traversal (`..`) is accepted, or a lookup maps an opaque ID to a server-side path.

## 2. Server-Side Request Forgery (`ssrf`, CWE-918)

**What to look for:**
- Outbound HTTP/network clients (`requests.get`, `urllib.request.urlopen`, `fetch`, `axios`, `HttpURLConnection`, `RestTemplate`, `curl_init`, `HttpClient`, `http.Get`) using a URL, host, or webhook target controlled by the caller.

**False-positive checks (do NOT report when present):**
- The scheme and hostname are validated against an explicit server-side allow-list before the request is sent.
- DNS resolution is checked to reject loopback (`127.0.0.0/8`, `::1`), link-local/cloud metadata (`169.254.169.254`), and RFC1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) with redirects disabled or re-validated.
