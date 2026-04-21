# curl2nuclei

Convert a captured curl command into a runnable [nuclei](https://github.com/projectdiscovery/nuclei) detection template.

You found a parameter that smells off. You curl-ed it once, eyeballed the response, moved on. `curl2nuclei` takes that one-off curl, picks a vulnerability class, and hands you back a YAML template you scan with immediately. The output is the artifact, not a report about the artifact.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: active](https://img.shields.io/badge/status-active-brightgreen.svg)](#)

## Overview

The gap this fills: a manual curl is throwaway, a nuclei template is reusable across a whole engagement and the rest of your scope. Re-typing the request body, headers, cookies, and matchers into a YAML by hand is the friction that keeps people from doing it. This script eats the curl, drops the request into a `raw:` block exactly as captured, and bolts on payloads + matchers tuned per vulnerability class.

Six classes ship: `sqli`, `ssrf`, `xss`, `redirect`, `rce`, `time-based`. OOB classes (`ssrf`, `rce`) wire `{{interactsh-url}}` into the payloads and add an `interactsh_protocol` matcher; inline classes use word/regex matchers tuned to the class. The output ends with a boxed next-step panel containing the literal `nuclei -t ... -u ...` command — copy, paste, run.

## Features

The parser handles real-world curl as it comes off Burp's *Copy as cURL* and Chrome DevTools — multi-line escapes, `-H`, `-X`, `-d/--data-raw/--data-urlencode`, `--json`, `-b/--cookie`, `-u`, `-A`, `-e`, and `-G`. The captured request lands in `raw:` byte-for-byte, so cookies and custom headers carry through.

- Six profiles: `sqli`, `ssrf`, `xss`, `redirect`, `rce`, `time-based`
- `--param name` to fuzz one parameter; default fuzzes every key in the query and body
- Templates emit `tags: curl2nuclei,<class>` so they are filterable in bulk scans
- `--stdout` for piping into Burp's BCheck or another generator
- Pure Python 3.9+ standard library, no install step

## Installation

```bash
git clone https://github.com/daniyalnasir-root/curl2nuclei.git
cd curl2nuclei
python3 cli.py -h
```

## Usage

```bash
# SQLi probe on one query parameter
python3 cli.py \
    --curl "curl 'https://httpbin.org/anything?id=1&user=guest'" \
    --class sqli --param id --out sqli-id.yaml

nuclei -t sqli-id.yaml -u https://httpbin.org/anything

# SSRF on a body parameter, request copied from Burp (cookie carried through)
python3 cli.py \
    --curl @./captured.curl \
    --class ssrf --param fetch_url --out ssrf-fetch.yaml

# Pipe to stdout for downstream chaining
python3 cli.py --curl "curl https://x.example/?q=1" --class xss --param q --stdout
```

## Command Line Options

| Flag | Required | Description |
|------|----------|-------------|
| `--curl` | yes | Curl command string, or `@path/to/file` |
| `--class` | yes | One of `sqli`, `ssrf`, `xss`, `redirect`, `rce`, `time-based` |
| `--param` | no | Single query/body parameter name to fuzz (default: every parameter) |
| `--out` | no | Path to write the YAML (default `./<id>.yaml`) |
| `--stdout` | no | Print YAML only; do not write a file or render the next-step panel |

## Output Example

```
$ python3 cli.py --curl "curl 'https://httpbin.org/anything?id=1&user=guest'" \
                 --class sqli --param id --out sqli-httpbin.yaml

id: sqli-httpbin-org-anything

info:
  name: SQLI probe on httpbin.org/anything
  author: curl2nuclei
  severity: high
  ...

http:
  - raw:
      - |
        GET /anything?id={{payload}}&user=guest HTTP/1.1
        Host: httpbin.org

    payloads:
      payload:
        - "'"
        - "' OR '1'='1"
        - "1 AND SLEEP(7)--"
    ...

┌─ next step ────────────────────────────────────────────────────┐
│ nuclei -t sqli-httpbin.yaml -u https://httpbin.org/anything    │
│                                                                │
│ written: sqli-httpbin.yaml                                     │
└────────────────────────────────────────────────────────────────┘
```

Templates validate cleanly under `nuclei -validate`. Full unabridged outputs are in [`examples/`](examples/).

## Legal Disclaimer

This tool is for authorized security testing and educational use only.
Run it only against systems you own or have explicit written permission to test.
The author accepts no liability for misuse. Unauthorized use may violate
local, state, or federal law.

## Author

Built by **Daniyal Nasir**, a **Penetration Tester** and **VAPT Consultant** specialising in **web application penetration testing**, **API security assessments**, **cloud penetration testing**, and **red team engagements** for Fortune 500 clients and high-traffic SaaS platforms. Ten years of **offensive security** practice with an active **bug bounty hunting** portfolio and a strong **responsible vulnerability disclosure** record. Certifications: **OSCP**, **LPT**, **CPENT**, **CEH**, **CISA**, **CISM**, **CASP+**. Connect on [LinkedIn](https://www.linkedin.com/in/daniyalnasir) or visit [daniyalnasir.com](https://www.daniyalnasir.com) for **penetration testing services** and **cybersecurity consulting** engagements.

## License

MIT, see [LICENSE](LICENSE).
