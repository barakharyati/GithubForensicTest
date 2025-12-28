# GithubForensicTest

A forensic security tool to scan GitHub Pull Request diffs for suspicious patterns. Download and analyze PR diffs at scale to detect potential security issues, secrets, and malicious code injections.

## Features

- 🔍 **Regex Pattern Search** - Search PR diffs using powerful regex patterns
- ⚡ **Parallel Downloads** - Download multiple PRs simultaneously (10x faster)
- 🚀 **Ripgrep Integration** - Uses ripgrep for 10-100x faster searching (with Python fallback)
- 🔑 **Multi-Token Support** - Rotate through multiple GitHub tokens to handle rate limits
- 📊 **Live Progress** - Real-time progress bar with ETA
- 📁 **Organized Output** - Each scan creates a timestamped folder with all results
- 📝 **Detailed Logging** - Full logs for debugging and audit trails
- 💾 **Multiple Export Formats** - Results in JSON and CSV

## Setup

### 1. Clone the repository

```bash
git clone <repo-url>
cd GithubForensicTest
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure GitHub tokens

Create a `.env` file with your GitHub Personal Access Tokens:

```bash
cp example.env .env
```

Edit `.env` and add your tokens (comma-separated for multiple tokens):

```
GITHUB_TOKENS=ghp_token1,ghp_token2,ghp_token3
```

**Generate tokens at:** https://github.com/settings/tokens

Required scopes:
- `public_repo` - for public repositories
- `repo` - for private repositories

### 5. Configure target repository and patterns

Edit `config.json`:

```json
{
    "repo": "owner/repo-name",
    "search_patterns": [
        "password",
        "api[_-]?key",
        "secret"
    ],
    "pr_state": "all",
    "per_page": 100
}
```

| Field | Description |
|-------|-------------|
| `repo` | GitHub repository in `owner/repo` format |
| `search_patterns` | Array of regex patterns to search for |
| `pr_state` | `"all"`, `"open"`, or `"closed"` |
| `per_page` | PRs per API request (max 100) |
| `max_workers` | Parallel download threads (default: 10) |

## Optional: Install ripgrep for faster searching

```bash
# macOS
brew install ripgrep

# Ubuntu/Debian
apt install ripgrep

# Windows
choco install ripgrep
```

If ripgrep is not installed, the tool falls back to Python regex (slower but works).

## Usage

```bash
python github_forensic_test.py
```

## Output Structure

Each scan creates a timestamped folder:

```
scans/
└── PR/
    └── owner-repo_20251228_143052/
        ├── diffs/              # Downloaded PR diff files
        │   ├── PR_1234.diff
        │   ├── PR_5678.diff
        │   └── ...
        ├── scan.log            # Detailed log file
        ├── results.json        # Full results with metadata
        ├── results.csv         # CSV for spreadsheet viewing
        └── config_used.json    # Config snapshot for this run
```

## Example Patterns

### Security scanning
```json
{
    "search_patterns": [
        "password\\s*=",
        "api[_-]?key\\s*=",
        "secret\\s*=",
        "token\\s*=",
        "credential",
        "BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY"
    ]
}
```

### Finding specific code patterns
```json
{
    "search_patterns": [
        "eval\\(",
        "exec\\(",
        "subprocess\\.call",
        "os\\.system"
    ]
}
```

## Rate Limits

GitHub API rate limits:
- **Authenticated:** 5,000 requests/hour per token
- **Unauthenticated:** 60 requests/hour

The tool automatically rotates through multiple tokens when rate limits are reached. For large repositories, use multiple tokens.

## License

MIT

