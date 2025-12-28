#!/usr/bin/env python3
"""
GitHub PR Diff Downloader and Pattern Scanner

Downloads all PR diffs from a GitHub repository and searches for patterns.
Uses multiple GitHub tokens for rate limit handling.
Features: Parallel downloads, ripgrep for fast searching.

Usage:
    python github_forensic_test.py                    # Full scan (download + search)
    python github_forensic_test.py --search-only DIR  # Search existing diffs folder
"""

import os
import re
import json
import time
import logging
import sys
import subprocess
import shutil
import threading
import argparse
import requests
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from typing import Iterator
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class Match:
    """Represents a pattern match in a PR diff."""
    pr_number: int
    pr_title: str
    pattern: str
    line_number: int
    line_content: str
    file_path: str


class ProgressBar:
    """Thread-safe progress bar for console output."""
    
    def __init__(self, total: int, prefix: str = "", width: int = 40):
        self.total = total
        self.prefix = prefix
        self.width = width
        self.current = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
    
    def update(self, current: int = None, suffix: str = ""):
        with self.lock:
            if current is not None:
                self.current = current
            else:
                self.current += 1
            
            if self.total == 0:
                percent = 100
            else:
                percent = (self.current / self.total) * 100
            
            filled = int(self.width * self.current / max(self.total, 1))
            bar = "█" * filled + "░" * (self.width - filled)
            
            elapsed = time.time() - self.start_time
            if self.current > 0:
                eta = (elapsed / self.current) * (self.total - self.current)
                eta_str = f"ETA: {eta:.0f}s"
            else:
                eta_str = "ETA: --"
            
            sys.stdout.write(f"\r{self.prefix} |{bar}| {percent:5.1f}% ({self.current}/{self.total}) {eta_str} {suffix[:30]:30}    ")
            sys.stdout.flush()
    
    def increment(self, suffix: str = ""):
        """Thread-safe increment."""
        with self.lock:
            self.current += 1
            current = self.current
            
            if self.total == 0:
                percent = 100
            else:
                percent = (current / self.total) * 100
            
            filled = int(self.width * current / max(self.total, 1))
            bar = "█" * filled + "░" * (self.width - filled)
            
            elapsed = time.time() - self.start_time
            if current > 0:
                eta = (elapsed / current) * (self.total - current)
                eta_str = f"ETA: {eta:.0f}s"
            else:
                eta_str = "ETA: --"
            
            sys.stdout.write(f"\r{self.prefix} |{bar}| {percent:5.1f}% ({current}/{self.total}) {eta_str} {suffix[:30]:30}    ")
            sys.stdout.flush()
    
    def finish(self):
        elapsed = time.time() - self.start_time
        sys.stdout.write(f"\r{self.prefix} |{'█' * self.width}| 100.0% ({self.total}/{self.total}) Done in {elapsed:.1f}s\n")
        sys.stdout.flush()


class TokenRotator:
    """Thread-safe token rotator for rate limit handling."""
    
    def __init__(self, tokens: list[str], logger: logging.Logger):
        self.tokens = tokens
        self.current_index = 0
        self.rate_limits = {token: {'remaining': 5000, 'reset': 0} for token in tokens}
        self.logger = logger
        self.lock = threading.Lock()
    
    def get_token(self) -> str:
        """Get the next available token with remaining rate limit."""
        with self.lock:
            for _ in range(len(self.tokens)):
                token = self.tokens[self.current_index]
                limit_info = self.rate_limits[token]
                
                # Check if rate limit is exhausted and not yet reset
                if limit_info['remaining'] <= 1:
                    reset_time = limit_info['reset']
                    if time.time() < reset_time:
                        # Try next token
                        self.current_index = (self.current_index + 1) % len(self.tokens)
                        continue
                
                return token
            
        # All tokens exhausted, wait for the earliest reset
        earliest_reset = min(self.rate_limits[t]['reset'] for t in self.tokens)
        wait_time = max(0, earliest_reset - time.time()) + 1
        self.logger.warning(f"All tokens rate limited. Waiting {wait_time:.0f} seconds...")
        # Print on same line to not break progress bar
        sys.stdout.write(f"\r⏳ RATE LIMITED - Waiting {wait_time:.0f}s for reset...".ljust(80))
        sys.stdout.flush()
        
        time.sleep(wait_time)
        return self.tokens[0]
    
    def update_rate_limit(self, token: str, remaining: int, reset: int):
        """Update rate limit info for a token."""
        with self.lock:
            self.rate_limits[token] = {'remaining': remaining, 'reset': reset}
            self.logger.debug(f"Token rate limit updated: remaining={remaining}, reset={reset}")
            
            # Rotate to next token if current is low
            if remaining <= 10:
                self.current_index = (self.current_index + 1) % len(self.tokens)


class GitHubPRScanner:
    """Downloads and scans GitHub PR diffs for patterns."""
    
    GITHUB_API = "https://api.github.com"
    
    def __init__(self, config_path: str = "config.json"):
        load_dotenv()
        
        # Load config
        with open(config_path) as f:
            self.config = json.load(f)
        
        self.repo = self.config["repo"]
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.config["search_patterns"]]
        self.pattern_strings = self.config["search_patterns"]
        
        # Parallel download settings
        self.max_workers = self.config.get("max_workers", 10)
        
        # Check for ripgrep
        self.use_ripgrep = self._check_ripgrep()
        
        # Create run folder with timestamp
        self.run_folder = self._create_run_folder()
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Setup tokens
        tokens_str = os.getenv("GITHUB_TOKENS", "")
        if not tokens_str:
            raise ValueError("GITHUB_TOKENS not found in .env file")
        
        tokens = [t.strip() for t in tokens_str.split(",") if t.strip()]
        if not tokens:
            raise ValueError("No valid tokens found in GITHUB_TOKENS")
        
        self.logger.info(f"Loaded {len(tokens)} GitHub token(s)")
        print(f"🔑 Loaded {len(tokens)} GitHub token(s)")
        self.token_rotator = TokenRotator(tokens, self.logger)
        
        # Setup diffs folder inside run folder (stores PR diff files)
        self.diffs_folder = self.run_folder / "diffs"
        self.diffs_folder.mkdir(exist_ok=True)
        
        # Track stats (thread-safe)
        self.stats = {
            'prs_fetched': 0,
            'prs_downloaded': 0,
            'prs_cached': 0,
            'matches_found': 0,
            'errors': 0
        }
        self.stats_lock = threading.Lock()
        
        # Store PR metadata for ripgrep results mapping
        self.pr_metadata = {}
    
    def _check_ripgrep(self) -> bool:
        """Check if ripgrep (rg) is available."""
        if shutil.which("rg"):
            return True
        print("⚠️  ripgrep (rg) not found. Install it for 10-100x faster searching:")
        print("   brew install ripgrep  # macOS")
        print("   apt install ripgrep   # Ubuntu/Debian")
        print("   Using Python regex fallback...\n")
        return False
    
    def _create_run_folder(self) -> Path:
        """Create a run folder with org-repo_dateTime format inside scans/PR/."""
        # Parse org and repo from "org/repo" format
        repo_parts = self.repo.replace("/", "-")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder_name = f"{repo_parts}_{timestamp}"
        
        # Create scans/PR folder structure
        scans_folder = Path("scans")
        scans_folder.mkdir(exist_ok=True)
        
        pr_folder = scans_folder / "PR"
        pr_folder.mkdir(exist_ok=True)
        
        # Create run folder inside scans/PR/
        run_folder = pr_folder / folder_name
        run_folder.mkdir(exist_ok=True)
        
        return run_folder
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging to file and configure logger."""
        logger = logging.getLogger("PRScanner")
        logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers
        logger.handlers = []
        
        # File handler - detailed logs
        log_file = self.run_folder / "scan.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
        
        # Log initial info
        logger.info("=" * 60)
        logger.info("GithubForensicTest Started")
        logger.info("=" * 60)
        logger.info(f"Repository: {self.repo}")
        logger.info(f"Run folder: {self.run_folder}")
        logger.info(f"Search patterns: {self.pattern_strings}")
        logger.info(f"PR state filter: {self.config.get('pr_state', 'all')}")
        logger.info(f"Parallel workers: {self.max_workers}")
        logger.info(f"Using ripgrep: {self.use_ripgrep}")
        
        return logger
    
    def _make_request(self, url: str, headers: dict = None) -> requests.Response:
        """Make an authenticated request with token rotation."""
        token = self.token_rotator.get_token()
        
        req_headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        if headers:
            req_headers.update(headers)
        
        response = requests.get(url, headers=req_headers)
        
        # Update rate limit info
        remaining = int(response.headers.get("X-RateLimit-Remaining", 5000))
        reset = int(response.headers.get("X-RateLimit-Reset", 0))
        self.token_rotator.update_rate_limit(token, remaining, reset)
        
        if response.status_code == 403 and remaining == 0:
            # Rate limited, retry with different token
            self.logger.warning("Token rate limited, rotating...")
            return self._make_request(url, headers)
        
        return response
    
    def get_pr_count(self) -> int:
        """Get approximate count of PRs."""
        state = self.config.get("pr_state", "all")
        url = f"{self.GITHUB_API}/repos/{self.repo}/pulls?state={state}&per_page=1"
        response = self._make_request(url)
        
        if response.status_code != 200:
            return 0
        
        # Check Link header for last page
        link_header = response.headers.get("Link", "")
        if 'rel="last"' in link_header:
            # Parse the last page number
            match = re.search(r'page=(\d+)>; rel="last"', link_header)
            if match:
                return int(match.group(1))
        
        return len(response.json())
    
    def get_all_prs(self) -> Iterator[dict]:
        """Fetch all PRs from the repository."""
        page = 1
        per_page = self.config.get("per_page", 100)
        state = self.config.get("pr_state", "all")
        limit = self.config.get("limit", None)  # None means no limit
        
        limit_str = f", limit={limit}" if limit else ""
        self.logger.info(f"Fetching PRs from {self.repo} (state={state}{limit_str})")
        print(f"\n📥 Fetching PRs from {self.repo} (state={state}{limit_str})...")
        
        fetched_count = 0
        
        while True:
            url = f"{self.GITHUB_API}/repos/{self.repo}/pulls"
            url += f"?state={state}&per_page={per_page}&page={page}"
            
            response = self._make_request(url)
            
            if response.status_code != 200:
                self.logger.error(f"Error fetching PRs: {response.status_code} - {response.text}")
                print(f"\n❌ Error fetching PRs: {response.status_code}")
                with self.stats_lock:
                    self.stats['errors'] += 1
                break
            
            prs = response.json()
            if not prs:
                break
            
            for pr in prs:
                with self.stats_lock:
                    self.stats['prs_fetched'] += 1
                yield pr
                fetched_count += 1
                
                # Check if we've reached the limit
                if limit and fetched_count >= limit:
                    self.logger.info(f"Reached PR limit of {limit}")
                    return
            
            self.logger.info(f"Page {page}: fetched {len(prs)} PRs")
            page += 1
    
    def download_pr_diff(self, pr: dict) -> tuple[dict, str | None]:
        """Download the diff for a PR and save it to the diffs folder."""
        pr_number = pr["number"]
        pr_title = pr["title"]
        diff_file = self.diffs_folder / f"PR_{pr_number}.diff"
        
        # Store metadata for ripgrep results mapping
        self.pr_metadata[pr_number] = {'title': pr_title, 'number': pr_number}
        
        # Check if already downloaded
        if diff_file.exists():
            with self.stats_lock:
                self.stats['prs_cached'] += 1
            self.logger.debug(f"PR #{pr_number} already cached")
            return pr, "cached"
        
        # Fetch diff
        url = f"{self.GITHUB_API}/repos/{self.repo}/pulls/{pr_number}"
        response = self._make_request(url, headers={"Accept": "application/vnd.github.v3.diff"})
        
        if response.status_code != 200:
            self.logger.error(f"Error fetching diff for PR #{pr_number}: {response.status_code}")
            with self.stats_lock:
                self.stats['errors'] += 1
            return pr, None
        
        diff_content = response.text
        
        # Save diff
        with open(diff_file, "w", encoding="utf-8") as f:
            f.write(diff_content)
        
        with self.stats_lock:
            self.stats['prs_downloaded'] += 1
        self.logger.info(f"Downloaded PR #{pr_number}: {pr_title[:50]}")
        
        return pr, diff_content
    
    def download_all_parallel(self, prs_list: list[dict], progress_bar: ProgressBar) -> None:
        """Download all PR diffs in parallel."""
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.download_pr_diff, pr): pr for pr in prs_list}
            
            for future in as_completed(futures):
                pr = futures[future]
                try:
                    _, result = future.result()
                    status = "✓" if result else "⚠️"
                    progress_bar.increment(f"PR #{pr['number']} [{status}]")
                except Exception as e:
                    self.logger.error(f"Error downloading PR #{pr['number']}: {e}")
                    progress_bar.increment(f"PR #{pr['number']} [❌]")
    
    def search_with_ripgrep(self) -> list[Match]:
        """Search diffs using ripgrep for much faster performance."""
        all_matches = []
        
        print(f"\n🚀 Searching with ripgrep ({len(self.pattern_strings)} patterns)...")
        
        for i, pattern in enumerate(self.pattern_strings, 1):
            print(f"   [{i}/{len(self.pattern_strings)}] Searching: {pattern[:50]}...", end=" ", flush=True)
            pattern_matches = 0
            try:
                # Run ripgrep: -n for line numbers, -i for case insensitive, -H for filename
                cmd = [
                    "rg", "-n", "-i", "-H", "--no-heading",
                    pattern,
                    str(self.diffs_folder)
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0 and result.stdout:
                    # Parse ripgrep output: filename:line_number:content
                    for line in result.stdout.strip().split("\n"):
                        if not line:
                            continue
                        
                        # Parse: /path/to/PR_123.diff:456:+content
                        parts = line.split(":", 2)
                        if len(parts) >= 3:
                            filepath = parts[0]
                            line_num = int(parts[1])
                            content = parts[2]
                            
                            # Only match added lines (starting with +)
                            if content.startswith("+") and not content.startswith("+++"):
                                # Extract PR number from filename
                                filename = Path(filepath).name
                                pr_match = re.search(r'PR_(\d+)\.diff', filename)
                                if pr_match:
                                    pr_number = int(pr_match.group(1))
                                    pr_info = self.pr_metadata.get(pr_number, {})
                                    
                                    # Get file path from diff context
                                    file_path = self._get_file_from_diff(filepath, line_num)
                                    
                                    match = Match(
                                        pr_number=pr_number,
                                        pr_title=pr_info.get('title', 'Unknown'),
                                        pattern=pattern,
                                        line_number=line_num,
                                        line_content=content[1:].strip()[:200],
                                        file_path=file_path
                                    )
                                    all_matches.append(match)
                                    pattern_matches += 1
                                    self.logger.info(f"Match found in PR #{pr_number}: pattern='{pattern}'")
                
                # Always print result (moved outside the if block)
                print(f"✓ {pattern_matches} match(es)")
                
            except subprocess.TimeoutExpired:
                self.logger.error(f"Ripgrep timeout for pattern: {pattern}")
                print("timeout!")
            except Exception as e:
                self.logger.error(f"Ripgrep error for pattern '{pattern}': {e}")
                print(f"error: {e}")
        
        print(f"   ✓ Total matches: {len(all_matches)}")
        return all_matches
    
    def _get_file_from_diff(self, diff_path: str, target_line: int) -> str:
        """Extract the file path from a diff file for a given line number."""
        try:
            with open(diff_path, 'r', encoding='utf-8', errors='replace') as f:
                current_file = "unknown"
                for i, line in enumerate(f, 1):
                    if line.startswith("diff --git"):
                        parts = line.split(" b/")
                        if len(parts) > 1:
                            current_file = parts[1].strip()
                    if i >= target_line:
                        return current_file
        except Exception:
            pass
        return "unknown"
    
    def search_diff_python(self, pr: dict, diff_content: str) -> list[Match]:
        """Search for patterns in a PR diff using Python regex (fallback)."""
        matches = []
        pr_number = pr["number"]
        pr_title = pr["title"]
        
        current_file = "unknown"
        
        for line_num, line in enumerate(diff_content.split("\n"), 1):
            # Track current file
            if line.startswith("diff --git"):
                parts = line.split(" b/")
                if len(parts) > 1:
                    current_file = parts[1]
            
            # Only search in added lines (starting with +)
            if line.startswith("+") and not line.startswith("+++"):
                for pattern, pattern_str in zip(self.patterns, self.pattern_strings):
                    if pattern.search(line):
                        matches.append(Match(
                            pr_number=pr_number,
                            pr_title=pr_title,
                            pattern=pattern_str,
                            line_number=line_num,
                            line_content=line[1:].strip()[:200],
                            file_path=current_file
                        ))
                        self.logger.info(f"Match found in PR #{pr_number}: pattern='{pattern_str}', file={current_file}")
        
        return matches
    
    def run(self) -> list[Match]:
        """Run the full scan: download diffs in parallel, then search."""
        print(f"\n🔍 Searching for patterns: {self.pattern_strings}")
        print(f"📂 Run folder: {self.run_folder}")
        print(f"⚡ Parallel workers: {self.max_workers}")
        print(f"🔎 Search engine: {'ripgrep' if self.use_ripgrep else 'Python regex'}\n")
        
        # First, collect all PRs to know the total count
        print("📊 Counting PRs...")
        estimated_count = self.get_pr_count()
        self.logger.info(f"Estimated PR count: {estimated_count}")
        print(f"   Estimated PRs: ~{estimated_count}\n")
        
        # Collect PRs first
        prs_list = []
        print("📥 Fetching PR list...")
        fetch_progress = ProgressBar(estimated_count, "Fetching PRs")
        
        for pr in self.get_all_prs():
            prs_list.append(pr)
            fetch_progress.update(len(prs_list), f"PR #{pr['number']}")
        
        fetch_progress.finish()
        
        total_prs = len(prs_list)
        self.logger.info(f"Total PRs to process: {total_prs}")
        print(f"\n📋 Total PRs to process: {total_prs}")
        
        # Download all diffs in parallel
        print(f"\n⬇️  Downloading diffs ({self.max_workers} parallel workers)...\n")
        download_progress = ProgressBar(total_prs, "Downloading")
        
        download_start = time.time()
        self.download_all_parallel(prs_list, download_progress)
        download_progress.finish()
        download_time = time.time() - download_start
        
        print(f"   Downloaded in {download_time:.1f}s ({total_prs / download_time:.1f} PRs/sec)")
        
        # Search phase
        search_start = time.time()
        
        if self.use_ripgrep:
            # Use ripgrep for fast searching
            all_matches = self.search_with_ripgrep()
        else:
            # Fallback to Python regex
            print(f"\n🔍 Searching diffs with Python regex...")
            all_matches = []
            search_progress = ProgressBar(total_prs, "Searching   ")
            
            for i, pr in enumerate(prs_list):
                diff_file = self.diffs_folder / f"PR_{pr['number']}.diff"
                if diff_file.exists():
                    with open(diff_file, 'r', encoding='utf-8', errors='replace') as f:
                        diff_content = f.read()
                    matches = self.search_diff_python(pr, diff_content)
                    all_matches.extend(matches)
                search_progress.update(i + 1, f"PR #{pr['number']}")
            
            search_progress.finish()
        
        search_time = time.time() - search_start
        print(f"   Searched in {search_time:.1f}s")
        
        # Update stats
        with self.stats_lock:
            self.stats['matches_found'] = len(all_matches)
        
        # Print summary
        self._print_summary(all_matches)
        
        return all_matches
    
    def _print_summary(self, matches: list[Match]):
        """Print and log summary."""
        summary = f"""
{'='*60}
📊 SCAN SUMMARY
{'='*60}
   Repository:        {self.repo}
   Run folder:        {self.run_folder}
   
   PRs fetched:       {self.stats['prs_fetched']}
   PRs downloaded:    {self.stats['prs_downloaded']}
   PRs from cache:    {self.stats['prs_cached']}
   Errors:            {self.stats['errors']}
   
   Search engine:     {'ripgrep' if self.use_ripgrep else 'Python regex'}
   Patterns searched: {len(self.pattern_strings)}
   Matches found:     {self.stats['matches_found']}
{'='*60}
"""
        print(summary)
        self.logger.info(summary)
    
    def save_results(self, matches: list[Match], output_file: str = None):
        """Save search results to a JSON file."""
        if output_file is None:
            output_file = self.run_folder / "results.json"
        else:
            output_file = self.run_folder / output_file
        
        results = {
            'metadata': {
                'repo': self.repo,
                'run_folder': str(self.run_folder),
                'timestamp': datetime.now().isoformat(),
                'patterns': self.pattern_strings,
                'stats': self.stats,
                'search_engine': 'ripgrep' if self.use_ripgrep else 'python'
            },
            'matches': []
        }
        
        for m in matches:
            results['matches'].append({
                "pr_number": m.pr_number,
                "pr_title": m.pr_title,
                "pattern": m.pattern,
                "file_path": m.file_path,
                "line_number": m.line_number,
                "line_content": m.line_content,
                "pr_url": f"https://github.com/{self.repo}/pull/{m.pr_number}"
            })
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Results saved to {output_file}")
        print(f"\n💾 Results saved to {output_file}")
        
        # Also save a simple CSV for quick viewing
        csv_file = self.run_folder / "results.csv"
        with open(csv_file, "w", encoding="utf-8") as f:
            f.write("PR Number,PR Title,Pattern,File Path,Line Content,PR URL\n")
            for m in matches:
                # Escape CSV fields
                title = m.pr_title.replace('"', '""')
                content = m.line_content.replace('"', '""')
                f.write(f'{m.pr_number},"{title}","{m.pattern}","{m.file_path}","{content}","https://github.com/{self.repo}/pull/{m.pr_number}"\n')
        
        self.logger.info(f"CSV results saved to {csv_file}")
        print(f"📄 CSV results saved to {csv_file}")
        
        # Generate detailed Markdown report
        self._generate_report(matches)
    
    def _generate_report(self, matches: list[Match]):
        """Generate a detailed Markdown report of all matches."""
        report_file = self.run_folder / "REPORT.md"
        
        # Group matches by PR
        pr_matches = {}
        for match in matches:
            if match.pr_number not in pr_matches:
                pr_matches[match.pr_number] = {
                    'title': match.pr_title,
                    'matches': []
                }
            pr_matches[match.pr_number]['matches'].append(match)
        
        with open(report_file, "w", encoding="utf-8") as f:
            # Header
            f.write(f"# GithubForensicTest Report\n\n")
            f.write(f"**Repository:** [{self.repo}](https://github.com/{self.repo})\n\n")
            f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Search Patterns:**\n")
            for pattern in self.pattern_strings:
                f.write(f"- `{pattern}`\n")
            f.write("\n")
            
            # Summary
            f.write(f"## Summary\n\n")
            f.write(f"| Metric | Value |\n")
            f.write(f"|--------|-------|\n")
            f.write(f"| Total PRs Scanned | {self.stats['prs_fetched']} |\n")
            f.write(f"| PRs with Matches | {len(pr_matches)} |\n")
            f.write(f"| Total Matches | {len(matches)} |\n")
            f.write(f"| Search Engine | {'ripgrep' if self.use_ripgrep else 'Python regex'} |\n")
            f.write("\n")
            
            if not matches:
                f.write("## Results\n\n")
                f.write("✅ **No matches found.**\n")
            else:
                # Table of Contents
                f.write(f"## Matching PRs\n\n")
                f.write("| PR # | Title | Matches |\n")
                f.write("|------|-------|--------:|\n")
                for pr_num in sorted(pr_matches.keys(), reverse=True):
                    data = pr_matches[pr_num]
                    title = data['title'][:50].replace("|", "\\|")
                    pr_link = f"[#{pr_num}](https://github.com/{self.repo}/pull/{pr_num})"
                    f.write(f"| {pr_link} | {title} | {len(data['matches'])} |\n")
                f.write("\n")
                
                # Detailed findings
                f.write("## Detailed Findings\n\n")
                
                for pr_num in sorted(pr_matches.keys(), reverse=True):
                    data = pr_matches[pr_num]
                    f.write(f"### [PR #{pr_num}](https://github.com/{self.repo}/pull/{pr_num}): {data['title']}\n\n")
                    f.write(f"**Matches Found:** {len(data['matches'])}\n\n")
                    
                    # Group by file within PR
                    file_matches = {}
                    for m in data['matches']:
                        if m.file_path not in file_matches:
                            file_matches[m.file_path] = []
                        file_matches[m.file_path].append(m)
                    
                    for file_path, file_match_list in file_matches.items():
                        f.write(f"**File:** `{file_path}`\n\n")
                        for m in file_match_list:
                            f.write(f"- **Pattern:** `{m.pattern}`\n")
                            f.write(f"  - Line {m.line_number}: `{m.line_content[:100]}`\n")
                        f.write("\n")
                    
                    f.write("---\n\n")
        
        self.logger.info(f"Report saved to {report_file}")
        print(f"📋 Report saved to {report_file}")
    
    def save_config_copy(self):
        """Save a copy of the config used for this run."""
        config_copy = self.run_folder / "config_used.json"
        with open(config_copy, "w", encoding="utf-8") as f:
            json.dump(self.config, f, indent=2)
        self.logger.info(f"Config saved to {config_copy}")


def print_matches(matches: list[Match], repo: str):
    """Print matches in a formatted way."""
    if not matches:
        print("\n✅ No matches found!")
        return
    
    print(f"\n{'='*60}")
    print("🎯 MATCHES FOUND")
    print(f"{'='*60}\n")
    
    # Group by PR
    pr_matches = {}
    for match in matches:
        if match.pr_number not in pr_matches:
            pr_matches[match.pr_number] = {
                'title': match.pr_title,
                'matches': []
            }
        pr_matches[match.pr_number]['matches'].append(match)
    
    for pr_num, data in pr_matches.items():
        print(f"PR #{pr_num}: {data['title'][:60]}")
        print(f"   URL: https://github.com/{repo}/pull/{pr_num}")
        for m in data['matches']:
            print(f"   • [{m.pattern}] {m.file_path}")
            print(f"     {m.line_content[:80]}")
        print()


def search_only_mode(diffs_folder: str, config_path: str = "config.json"):
    """Search existing diffs folder without downloading."""
    print("=" * 60)
    print("🔎 GithubForensicTest (Search-Only Mode)")
    print("=" * 60)
    
    diffs_path = Path(diffs_folder)
    if not diffs_path.exists():
        print(f"❌ Diffs folder not found: {diffs_folder}")
        return
    
    # Load config for patterns
    with open(config_path) as f:
        config = json.load(f)
    
    repo = config["repo"]
    pattern_strings = config["search_patterns"]
    
    # Check for ripgrep
    use_ripgrep = shutil.which("rg") is not None
    
    # Create output folder
    repo_parts = repo.replace("/", "-")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_folder = Path("scans/PR") / f"{repo_parts}_{timestamp}_search"
    output_folder.mkdir(parents=True, exist_ok=True)
    
    print(f"\n🔍 Searching for patterns: {pattern_strings}")
    print(f"📂 Diffs folder: {diffs_path}")
    print(f"📂 Output folder: {output_folder}")
    print(f"🔎 Search engine: {'ripgrep' if use_ripgrep else 'Python regex'}\n")
    
    # Count diff files
    diff_files = list(diffs_path.glob("PR_*.diff"))
    print(f"📋 Found {len(diff_files)} diff files\n")
    
    all_matches = []
    
    if use_ripgrep:
        print(f"🚀 Searching with ripgrep ({len(pattern_strings)} patterns)...")
        
        for i, pattern in enumerate(pattern_strings, 1):
            print(f"   [{i}/{len(pattern_strings)}] Searching: {pattern[:50]}...", end=" ", flush=True)
            pattern_matches = 0
            
            try:
                cmd = ["rg", "-n", "-i", "-H", "--no-heading", pattern, str(diffs_path)]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0 and result.stdout:
                    for line in result.stdout.strip().split("\n"):
                        if not line:
                            continue
                        
                        parts = line.split(":", 2)
                        if len(parts) >= 3:
                            filepath = parts[0]
                            line_num = int(parts[1])
                            content = parts[2]
                            
                            if content.startswith("+") and not content.startswith("+++"):
                                filename = Path(filepath).name
                                pr_match = re.search(r'PR_(\d+)\.diff', filename)
                                if pr_match:
                                    pr_number = int(pr_match.group(1))
                                    
                                    match = Match(
                                        pr_number=pr_number,
                                        pr_title=f"PR #{pr_number}",
                                        pattern=pattern,
                                        line_number=line_num,
                                        line_content=content[1:].strip()[:200],
                                        file_path="unknown"
                                    )
                                    all_matches.append(match)
                                    pattern_matches += 1
                
                print(f"✓ {pattern_matches} match(es)")
                
            except Exception as e:
                print(f"error: {e}")
        
        print(f"   ✓ Total matches: {len(all_matches)}")
    else:
        # Python fallback
        patterns = [re.compile(p, re.IGNORECASE) for p in pattern_strings]
        print(f"🔍 Searching with Python regex...")
        
        for diff_file in diff_files:
            pr_match = re.search(r'PR_(\d+)\.diff', diff_file.name)
            if not pr_match:
                continue
            
            pr_number = int(pr_match.group(1))
            
            with open(diff_file, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    if line.startswith("+") and not line.startswith("+++"):
                        for pattern, pattern_str in zip(patterns, pattern_strings):
                            if pattern.search(line):
                                match = Match(
                                    pr_number=pr_number,
                                    pr_title=f"PR #{pr_number}",
                                    pattern=pattern_str,
                                    line_number=line_num,
                                    line_content=line[1:].strip()[:200],
                                    file_path="unknown"
                                )
                                all_matches.append(match)
    
    # Save results
    print(f"\n📊 Found {len(all_matches)} total matches")
    
    # Generate report
    report_file = output_folder / "REPORT.md"
    
    pr_matches = {}
    for match in all_matches:
        if match.pr_number not in pr_matches:
            pr_matches[match.pr_number] = {'title': match.pr_title, 'matches': []}
        pr_matches[match.pr_number]['matches'].append(match)
    
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"# GithubForensicTest Report (Search-Only Mode)\n\n")
        f.write(f"**Repository:** [{repo}](https://github.com/{repo})\n\n")
        f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Diffs Folder:** `{diffs_path}`\n\n")
        f.write(f"**Search Patterns:**\n")
        for pattern in pattern_strings:
            f.write(f"- `{pattern}`\n")
        f.write("\n")
        
        f.write(f"## Summary\n\n")
        f.write(f"| Metric | Value |\n")
        f.write(f"|--------|-------|\n")
        f.write(f"| Diff Files Searched | {len(diff_files)} |\n")
        f.write(f"| PRs with Matches | {len(pr_matches)} |\n")
        f.write(f"| Total Matches | {len(all_matches)} |\n")
        f.write("\n")
        
        if pr_matches:
            f.write(f"## Matching PRs\n\n")
            f.write("| PR # | Matches |\n")
            f.write("|------|--------:|\n")
            for pr_num in sorted(pr_matches.keys(), reverse=True):
                data = pr_matches[pr_num]
                pr_link = f"[#{pr_num}](https://github.com/{repo}/pull/{pr_num})"
                f.write(f"| {pr_link} | {len(data['matches'])} |\n")
            f.write("\n")
            
            f.write("## Detailed Findings\n\n")
            for pr_num in sorted(pr_matches.keys(), reverse=True):
                data = pr_matches[pr_num]
                f.write(f"### [PR #{pr_num}](https://github.com/{repo}/pull/{pr_num})\n\n")
                for m in data['matches']:
                    f.write(f"- **Pattern:** `{m.pattern}`\n")
                    f.write(f"  - Line {m.line_number}: `{m.line_content[:100]}`\n")
                f.write("\n---\n\n")
        else:
            f.write("## Results\n\n✅ **No matches found.**\n")
    
    print(f"📋 Report saved to {report_file}")
    
    # Also save JSON
    results_file = output_folder / "results.json"
    results = {
        'metadata': {
            'repo': repo,
            'diffs_folder': str(diffs_path),
            'timestamp': datetime.now().isoformat(),
            'patterns': pattern_strings,
            'mode': 'search-only'
        },
        'matches': [
            {
                "pr_number": m.pr_number,
                "pattern": m.pattern,
                "line_number": m.line_number,
                "line_content": m.line_content,
                "pr_url": f"https://github.com/{repo}/pull/{m.pr_number}"
            }
            for m in all_matches
        ]
    }
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"💾 Results saved to {results_file}")
    
    print_matches(all_matches, repo)
    print(f"\n✨ Search complete! Check {output_folder} for all outputs.")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="GithubForensicTest - Scan GitHub PR diffs for security patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python github_forensic_test.py                              # Full scan (download + search)
  python github_forensic_test.py --search-only scans/PR/xxx/diffs  # Search existing diffs
        """
    )
    parser.add_argument(
        "--search-only", "-s",
        metavar="DIFFS_FOLDER",
        help="Search existing diffs folder without downloading"
    )
    parser.add_argument(
        "--config", "-c",
        default="config.json",
        help="Path to config file (default: config.json)"
    )
    
    args = parser.parse_args()
    
    if args.search_only:
        search_only_mode(args.search_only, args.config)
        return
    
    print("=" * 60)
    print("🔎 GithubForensicTest")
    print("=" * 60)
    
    try:
        scanner = GitHubPRScanner(args.config)
        scanner.save_config_copy()
        matches = scanner.run()
        print_matches(matches, scanner.repo)
        scanner.save_results(matches)
        
        print(f"\n✨ Scan complete! Check {scanner.run_folder} for all outputs.")
        scanner.logger.info("Scan completed successfully")
        
    except FileNotFoundError as e:
        print(f"❌ Config file not found: {e}")
        print("   Create a config.json with 'repo' and 'search_patterns'")
    except ValueError as e:
        print(f"❌ Configuration error: {e}")
        print("   Create a .env file with GITHUB_TOKENS=token1,token2,...")
    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        raise


if __name__ == "__main__":
    main()
