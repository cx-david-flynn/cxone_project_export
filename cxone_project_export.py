#!/usr/bin/env python3
"""Export a Checkmarx One project inventory to CSV.

Authentication (environment variables):
  CX_API_KEY    API key (refresh token). The base URL, IAM URL and tenant are
                derived from the claims inside the key.            -- or --
  CX_CLIENT_ID / CX_CLIENT_SECRET  OAuth client credentials (these require the
                three values below, since there is no key to read them from)
Optional overrides (also needed with client credentials):
  CX_BASE_URL   AST API base URL, e.g. https://us.ast.checkmarx.net
  CX_IAM_URL    IAM base URL,     e.g. https://us.iam.checkmarx.net
  CX_TENANT     Tenant name
Each can also be passed as a command line flag.

The output file must be a .csv located in (or below) the current directory.
"""
import argparse
import base64
import csv
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from urllib.parse import urlparse

import requests

COLUMNS = [
    "Project ID", "Project Name", "Scan Origin", "Source", "Tags", "Groups",
    "Applications", "Last Scan", "Risk Level", "Total Vulnerabilities",
    "Critical Vulnerabilities", "High Vulnerabilities", "Medium Vulnerabilities",
    "Low Vulnerabilities", "Internet Facing", "languageOverview",
]
SEVERITIES = ("critical", "high", "medium", "low")
PAGE = 100


def derive_from_api_key(api_key):
    """Return (base_url, iam_url, tenant) read from the claims of a Checkmarx One API key.

    The key is a JWT. Its `iss` claim looks like
    https://<region>.iam.checkmarx.net/auth/realms/<tenant>, and the
    `ast-base-url` claim (when present) holds the API base URL. The claims are
    only read here, not verified; the server validates the key at login.
    """
    try:
        payload = api_key.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        iss = urlparse(claims["iss"])
        parts = [p for p in iss.path.split("/") if p]
        tenant = parts[parts.index("realms") + 1]
        iam = f"{iss.scheme}://{iss.netloc}"
    except (IndexError, KeyError, ValueError, TypeError):
        sys.exit("Could not read tenant/IAM URL from CX_API_KEY. Is it a valid Checkmarx One API key? "
                 "You can still pass --base-url, --iam-url and --tenant explicitly.")
    base = claims.get("ast-base-url")
    if not base:
        # iam.checkmarx.net -> ast.checkmarx.net, eu.iam.checkmarx.net -> eu.ast.checkmarx.net
        host = iss.netloc
        if host.startswith("iam."):
            host = "ast." + host[len("iam."):]
        elif ".iam." in host:
            host = host.replace(".iam.", ".ast.", 1)
        else:
            sys.exit(f"Cannot derive the AST base URL from IAM host '{iss.netloc}'. Pass --base-url explicitly.")
        base = f"{iss.scheme}://{host}"
    return base, iam, tenant


class Client:
    def __init__(self, base, iam, tenant, api_key=None, client_id=None, client_secret=None, verbose=False):
        self.base, self.iam, self.tenant = base.rstrip("/"), iam.rstrip("/"), tenant
        self.verbose = verbose
        self.session = requests.Session()
        self._login(api_key, client_id, client_secret)

    def _login(self, api_key, client_id, client_secret):
        url = f"{self.iam}/auth/realms/{self.tenant}/protocol/openid-connect/token"
        if api_key:
            data = {"grant_type": "refresh_token", "client_id": "ast-app", "refresh_token": api_key}
        elif client_id and client_secret:
            data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
        else:
            sys.exit("Provide CX_API_KEY or CX_CLIENT_ID/CX_CLIENT_SECRET.")
        resp = self.session.post(url, data=data, timeout=30)
        if resp.status_code != 200:
            sys.exit(f"Authentication failed (HTTP {resp.status_code})")
        self.session.headers["Authorization"] = "Bearer " + resp.json()["access_token"]

    def fetch_json(self, path, params=None, base=None, optional=False):
        """GET a JSON document. HTTP errors raise, or return None if optional."""
        resp = self.session.get((base or self.base) + path, params=params, timeout=60)
        if not resp.ok:
            if optional:
                if self.verbose:
                    print(f"[warn] GET {path} -> {resp.status_code}", file=sys.stderr)
                return None
            resp.raise_for_status()
        return resp.json()

    def paged(self, path, key, params=None):
        offset = 0
        while True:
            p = dict(params or {}, limit=PAGE, offset=offset)
            data = self.fetch_json(path, p) or {}
            items = data.get(key) or []
            yield from items
            offset += PAGE
            if len(items) < PAGE:
                return


def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def sev_counts(summary):
    """Sum severity counters across all engines in a scan-summary entry."""
    out = dict.fromkeys(SEVERITIES, 0)
    for v in (summary or {}).values():
        if isinstance(v, dict) and isinstance(v.get("severityCounters"), list):
            for c in v["severityCounters"]:
                sev = str(c.get("severity", "")).lower()
                if sev in out:
                    out[sev] += int(c.get("counter", 0) or 0)
    return out


def risk_level(c):
    for s in SEVERITIES:
        if c[s]:
            return s.capitalize()
    return "None"


# Sections of the SAST scan metrics document that are keyed by language name.
LANGUAGE_SECTIONS = ("successfullLocPerLanguage", "domObjectsPerLanguage", "scannedFilesPerLanguage")


def languages_from_metrics(metrics):
    """Return the sorted language names present in a SAST metrics document."""
    found = set()
    for section in LANGUAGE_SECTIONS:
        for language, value in (metrics.get(section) or {}).items():
            if isinstance(value, dict):  # scannedFilesPerLanguage -> {goodFiles, ...}
                value = sum(v for v in value.values() if isinstance(v, (int, float)))
            if isinstance(value, (int, float)) and value > 0:
                found.add(str(language))
    return sorted(found)


def languages_for(client, scan_id):
    """Languages scanned by a completed SAST scan (/api/sast-metadata/{scan}/metrics)."""
    data = client.fetch_json(f"/api/sast-metadata/{scan_id}/metrics", optional=True)
    return languages_from_metrics(data) if isinstance(data, dict) else []


def collect(client, project_filter=None):
    projects = list(client.paged("/api/projects", "projects"))
    if project_filter:
        f = project_filter.lower()
        projects = [p for p in projects if f in p.get("name", "").lower()]
    print(f"Found {len(projects)} projects", file=sys.stderr)

    # Group id -> name (best effort)
    groups = {}
    g = client.fetch_json(f"/auth/realms/{client.tenant}/pip/groups", base=client.iam, optional=True)
    for item in g if isinstance(g, list) else []:
        groups[item.get("id")] = item.get("name") or item.get("path") or item.get("id")

    # Project id -> application names
    apps = {}
    for a in client.paged("/api/applications", "applications"):
        for pid in a.get("projectIds") or []:
            apps.setdefault(pid, []).append(a.get("name", a.get("id")))

    # Last scan per project (batched)
    ids = [p["id"] for p in projects]
    last = {}
    for batch in chunks(ids, 50):
        data = client.fetch_json("/api/projects/last-scan",
                                 {"project-ids": ",".join(batch), "limit": len(batch)}, optional=True)
        last.update(data or {})

    # Severity counts per last scan (batched)
    summaries = {}
    scan_ids = [s["id"] for s in last.values() if s and s.get("id")]
    for batch in chunks(scan_ids, 20):
        data = client.fetch_json("/api/scan-summary", {"scan-ids": ",".join(batch)}, optional=True) or {}
        for s in data.get("scansSummaries") or []:
            summaries[s.get("scanId")] = s

    # Languages come from the last scan (any branch) when it has SAST metrics.
    with ThreadPoolExecutor(max_workers=4) as ex:
        langs = dict(zip(scan_ids, ex.map(lambda sid: languages_for(client, sid), scan_ids)))
    project_langs = {pid: langs.get((last.get(pid) or {}).get("id"), []) for pid in ids}

    # Fallback: for projects still without languages, use the last completed SAST scan instead.
    missing = [pid for pid in ids if not project_langs[pid]]
    fallback_scan = {}
    for batch in chunks(missing, 50):
        data = client.fetch_json("/api/projects/last-scan",
                                 {"project-ids": ",".join(batch), "limit": len(batch),
                                  "engine": "sast", "sast-status": "Completed"}, optional=True)
        for pid, s in (data or {}).items():
            if s and s.get("id"):
                fallback_scan[pid] = s["id"]
    todo = sorted(set(fallback_scan.values()) - set(langs))  # skip scans already tried above
    with ThreadPoolExecutor(max_workers=4) as ex:
        langs.update(zip(todo, ex.map(lambda sid: languages_for(client, sid), todo)))
    for pid, sid_ in fallback_scan.items():
        project_langs[pid] = langs.get(sid_, [])

    rows = []
    for p in projects:
        scan = last.get(p["id"]) or {}
        sid = scan.get("id")
        c = sev_counts(summaries.get(sid))
        tags = p.get("tags") or {}
        inet = p.get("internetFacing", p.get("isInternetFacing"))
        rows.append({
            "Project ID": p["id"],
            "Project Name": p.get("name", ""),
            "Scan Origin": p.get("origin", "") or scan.get("sourceOrigin", ""),
            "Source": p.get("repoUrl", "") or scan.get("sourceType", ""),
            "Tags": ";".join(f"{k}={v}" if v else k for k, v in tags.items()),
            "Groups": ";".join(groups.get(g_, g_) for g_ in p.get("groups") or []),
            "Applications": ";".join(apps.get(p["id"], [])),
            "Last Scan": scan.get("createdAt", ""),
            "Risk Level": risk_level(c),
            "Total Vulnerabilities": sum(c.values()),
            "Critical Vulnerabilities": c["critical"],
            "High Vulnerabilities": c["high"],
            "Medium Vulnerabilities": c["medium"],
            "Low Vulnerabilities": c["low"],
            "Internet Facing": "" if inet is None else str(bool(inet)).lower(),
            "languageOverview": ";".join(project_langs[p["id"]]),
        })
    return rows


def safe_output_path(name):
    """Normalize the user-supplied file name and confine it to the working directory tree."""
    root = os.path.realpath(os.getcwd())
    path = os.path.realpath(os.path.normpath(os.path.abspath(name)))
    if os.path.commonpath([root, path]) != root:
        sys.exit(f"Output file must be inside the current directory ({root}): {path}")
    if os.path.splitext(path)[1].lower() != ".csv":
        sys.exit(f"Output file must have a .csv extension: {path}")
    if os.path.isdir(path):
        sys.exit(f"Output path is a directory: {path}")
    if not os.path.isdir(os.path.dirname(path)):
        sys.exit(f"Output directory does not exist: {os.path.dirname(path)}")
    return path


def write_csv(file_name, rows):
    """Validate the destination (normalize + confine) and write the CSV."""
    root = os.path.realpath(os.getcwd())
    out_path = os.path.realpath(os.path.normpath(os.path.abspath(file_name)))
    if os.path.commonpath([root, out_path]) != root or os.path.isdir(out_path):
        sys.exit(f"Refusing to write outside the current directory: {out_path}")
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    return out_path


def main():
    env = os.environ.get
    ap = argparse.ArgumentParser(description="Export Checkmarx One projects to CSV.")
    ap.add_argument("--file-name", "-f", default=f"project-list-{date.today():%Y-%m-%d}.csv",
                    help="Output CSV name (default: project-list-yyyy-mm-dd.csv)")
    ap.add_argument("--dry-run", "-n", action="store_true",
                    help="Fetch data and show a preview, but do not write a file")
    ap.add_argument("--project-filter", help="Only include projects whose name contains this text")
    ap.add_argument("--verbose", "-v", action="store_true", help="Show warnings for failed optional lookups")
    ap.add_argument("--base-url", default=env("CX_BASE_URL"), help="Override; derived from the API key by default")
    ap.add_argument("--iam-url", default=env("CX_IAM_URL"), help="Override; derived from the API key by default")
    ap.add_argument("--tenant", default=env("CX_TENANT"), help="Override; derived from the API key by default")
    ap.add_argument("--api-key", default=env("CX_API_KEY"))
    ap.add_argument("--client-id", default=env("CX_CLIENT_ID"))
    ap.add_argument("--client-secret", default=env("CX_CLIENT_SECRET"))
    a = ap.parse_args()

    base_url, iam_url, tenant = a.base_url, a.iam_url, a.tenant
    if a.api_key:
        # Explicit values win; anything missing is derived from the API key.
        d_base, d_iam, d_tenant = derive_from_api_key(a.api_key)
        base_url, iam_url, tenant = base_url or d_base, iam_url or d_iam, tenant or d_tenant
    if not (base_url and iam_url and tenant):
        ap.error("Set CX_API_KEY (URLs and tenant are derived from it), or provide "
                 "--base-url, --iam-url and --tenant with client credentials")

    out_path = safe_output_path(a.file_name)  # fail fast before any API calls
    client = Client(base_url, iam_url, tenant, a.api_key, a.client_id, a.client_secret, a.verbose)
    rows = collect(client, a.project_filter)

    if a.dry_run:
        print(f"[dry-run] {len(rows)} rows would be written to {out_path}")
        for r in rows[:5]:
            print(r)
        return
    print(f"Wrote {len(rows)} rows to {write_csv(out_path, rows)}")


if __name__ == "__main__":
    main()
