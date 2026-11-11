# Checkmarx One Project Export

`cxone_project_export.py` exports an inventory of every project in a Checkmarx One tenant to a CSV file.

## Output columns

| Column | Source |
|---|---|
| Project ID, Project Name | Project record |
| Scan Origin | Project `origin` (falls back to the last scan's source origin) |
| Source | Project repository URL (falls back to the last scan's source type) |
| Tags | Project tags, `key=value` pairs joined with `;` |
| Groups | Group names assigned to the project, joined with `;` (IDs if names can't be resolved) |
| Applications | Applications the project belongs to, joined with `;` |
| Last Scan | Creation time of the project's most recent scan (any branch) |
| Risk Level | Highest severity found in the last scan: Critical, High, Medium, Low, or None |
| Total / Critical / High / Medium / Low Vulnerabilities | Severity counts from the last scan, summed across all engines |
| Internet Facing | `true` or `false` if the project record has an `internetFacing` field, otherwise blank |
| languageOverview | Languages scanned by SAST, joined with `;` (see below) |

### How `languageOverview` is filled

1. Languages come from the SAST metrics of the project's last scan.
2. If that scan has no SAST metrics (for example it was SCA-only, failed, or partial), the project's last
   **completed SAST scan** is used instead.
3. If neither scan has language metrics, the value is blank.

## Requirements

- Python 3.10 or newer
- The `requests` package
- A Checkmarx One API key

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Authentication

Set your API key in the environment:

```bash
export CX_API_KEY='<your API key>'
```

The AST base URL, IAM URL and tenant name are **derived from the API key** (it is a JWT whose claims contain
them), so no other settings are needed. The key is only decoded locally to read those claims. Checkmarx
validates it when the script logs in.

Keep the key out of source control and shell history where you can. Only projects the key's owner is allowed to see are exported.

### Optional overrides

Use these if the derived values are wrong, or to log in with an OAuth client instead of an API key.

| Setting | Environment variable | Flag |
|---|---|---|
| AST base URL | `CX_BASE_URL` | `--base-url` |
| IAM URL | `CX_IAM_URL` | `--iam-url` |
| Tenant | `CX_TENANT` | `--tenant` |
| API key | `CX_API_KEY` | `--api-key` |
| OAuth client ID / secret | `CX_CLIENT_ID` / `CX_CLIENT_SECRET` | `--client-id` / `--client-secret` |

OAuth client credentials have no key to read from, so the base URL, IAM URL and tenant must also be provided.

## Usage

```bash
python cxone_project_export.py                      # writes project-list-yyyy-mm-dd.csv
python cxone_project_export.py --dry-run            # fetch and preview 5 rows, write nothing
python cxone_project_export.py --file-name out.csv  # choose the file name
python cxone_project_export.py --project-filter web # only projects whose name contains "web"
python cxone_project_export.py --verbose            # show warnings for failed lookups
```

| Flag | Short | Description |
|---|---|---|
| `--file-name` | `-f` | Output file. Default `project-list-yyyy-mm-dd.csv` using today's date |
| `--dry-run` | `-n` | Fetch the data and print a preview, but do not create a file |
| `--project-filter` | | Only include projects whose name contains this text (case-insensitive) |
| `--verbose` | `-v` | Print a warning when an optional lookup fails (for example a 404 for scan metrics) |

### Output file rules

The output file must end in `.csv` and be inside the directory you run the script from (subdirectories are fine).
Paths that point elsewhere are refused.

## Notes and limitations

- Rows are in the order the API returns projects, which can vary between runs.
- Severity counts and risk level reflect each project's most recent scan, regardless of branch.
- A project with no scans has zero counts, no last-scan date and a blank `languageOverview`.
- Language data only exists for scans where SAST produced metrics. Some SAST scans have none, so their projects stay blank.
- The script makes one request per project scan for languages (4 at a time). Large tenants take longer to export.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Authentication failed (HTTP 400/401)` | The API key is invalid, expired or revoked |
| `Could not read tenant/IAM URL from CX_API_KEY` | The value isn't a Checkmarx One API key. Use the override flags |
| `404` on `/api/projects` | The derived base URL is wrong. Pass `--base-url` |
| Blank `languageOverview` for scanned projects | The scan has no SAST language metrics. Run with `--verbose` to see which scans |
| `Output file must be inside the current directory` | Run the script from the folder where you want the file |
