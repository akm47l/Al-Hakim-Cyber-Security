#!/usr/bin/env python3
"""Audit catalog URLs and public GitHub repository metadata without running tools."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TOOLS_PATH = ROOT / 'Database' / 'tools.json'
SOURCES_PATH = ROOT / 'Database' / 'sources.json'
HISTORY_DIR = ROOT / 'Updates' / 'history'
USER_AGENT = 'Al-Hakim-Cyber-Security-Catalog-Auditor/1.0 (+https://github.com/akm47l/Al-Hakim-Cyber-Security)'


def read_json(path: Path):
    with path.open(encoding='utf-8') as f:
        return json.load(f)


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    tmp.replace(path)


def get_url(url: str, timeout: float, token: str = '', accept: str = '*/*'):
    headers = {'User-Agent': USER_AGENT, 'Accept': accept}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(url, headers=headers, method='GET')
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(1_000_000)
            content_type = response.headers.get('Content-Type', '')
            return {'status_code': response.status, 'final_url': response.geturl(), 'content_type': content_type, 'body': body}
    except urllib.error.HTTPError as exc:
        return {'status_code': exc.code, 'final_url': exc.geturl(), 'content_type': exc.headers.get('Content-Type', ''), 'body': exc.read(16_384)}
    except Exception as exc:
        return {'status_code': None, 'final_url': url, 'content_type': '', 'error': f'{type(exc).__name__}: {exc}'}


def check_link(url: str, timeout: float):
    result = get_url(url, timeout, accept='text/html,application/json,*/*')
    code = result.get('status_code')
    if code is None:
        state = 'unreachable'
    elif 200 <= code < 400:
        state = 'ok'
    elif code in (401, 403, 429):
        state = 'restricted_or_rate_limited'
    else:
        state = 'http_error'
    return {'url': url, 'status': state, 'http_status': code, 'final_url': result.get('final_url'), 'error': result.get('error', '')}


def github_repo_from_url(url: str):
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    if parsed.netloc.lower() not in ('github.com', 'www.github.com'):
        return None
    parts = [p for p in parsed.path.strip('/').split('/') if p]
    if len(parts) != 2 or parts[0].lower() in ('topics', 'orgs', 'users', 'collections', 'marketplace', 'sponsors'):
        return None
    owner, repo = parts
    repo = re.sub(r'\.git$', '', repo)
    return owner, repo


def github_json(url: str, token: str, timeout: float):
    result = get_url(url, timeout, token, accept='application/vnd.github+json')
    code = result.get('status_code')
    if code is None or not (200 <= code < 300):
        return None, code, result.get('error', '')
    try:
        return json.loads(result.get('body', b'{}').decode('utf-8')), code, ''
    except Exception as exc:
        return None, code, f'JSON decode failed: {exc}'


def audit_github_repository(owner: str, repo: str, token: str, timeout: float, checked_at: str):
    base = f'https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}'
    data, code, error = github_json(base, token, timeout)
    if data is None:
        state = 'not_found_or_unavailable' if code == 404 else ('rate_limited_or_forbidden' if code in (403, 429) else 'unavailable')
        return {'repository': f'{owner}/{repo}', 'checked_at': checked_at, 'metadata_status': state, 'http_status': code, 'error': error}

    latest_release, release_code, release_error = github_json(base + '/releases/latest', token, timeout)
    release_name = 'غير متوفر'
    release_tag = 'غير متوفر'
    release_url = 'غير متوفر'
    if latest_release is not None:
        release_name = latest_release.get('name') or latest_release.get('tag_name') or 'غير متوفر'
        release_tag = latest_release.get('tag_name') or 'غير متوفر'
        release_url = latest_release.get('html_url') or 'غير متوفر'
    else:
        tags, tags_code, tags_error = github_json(base + '/tags?per_page=1', token, timeout)
        if isinstance(tags, list) and tags:
            release_tag = tags[0].get('name') or 'غير متوفر'
            release_name = release_tag
            release_url = tags[0].get('commit', {}).get('url') or 'غير متوفر'
        elif tags_code in (403, 429):
            release_error = tags_error or 'GitHub API rate limit/permission response'

    lic = data.get('license') or {}
    spdx = lic.get('spdx_id') or 'غير متوفر'
    return {
        'repository': f'{owner}/{repo}',
        'checked_at': checked_at,
        'metadata_status': 'ok',
        'repository_url': data.get('html_url'),
        'repository_updated_at': data.get('updated_at') or 'غير متوفر',
        'archived': bool(data.get('archived', False)),
        'license_spdx': spdx,
        'license_url': lic.get('url') or 'غير متوفر',
        'latest_release': release_name,
        'latest_tag': release_tag,
        'release_url': release_url,
        'release_check_status': 'ok' if latest_release is not None else ('tag_fallback' if release_tag != 'غير متوفر' else f'not_available_http_{release_code}'),
        'default_branch': data.get('default_branch') or 'غير متوفر',
        'error': release_error,
    }


def unique_history_path(timestamp: str):
    base = HISTORY_DIR / f'audit-{timestamp}.json'
    path = base
    counter = 1
    while path.exists():
        path = HISTORY_DIR / f'audit-{timestamp}-{counter:02d}.json'
        counter += 1
    return path


def main():
    parser = argparse.ArgumentParser(description='Check catalog links and public GitHub metadata; this script does not execute security tools.')
    parser.add_argument('--save', action='store_true', help='Save a unique historical snapshot and update only automated metadata fields.')
    parser.add_argument('--timeout', type=float, default=15.0, help='Per-request timeout in seconds (default: 15).')
    parser.add_argument('--workers', type=int, default=4, help='Concurrent link checks (default: 4; max: 8).')
    args = parser.parse_args()
    workers = max(1, min(args.workers, 8))

    tools = read_json(TOOLS_PATH)
    sources = read_json(SOURCES_PATH)
    checked_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    timestamp = checked_at.replace('-', '').replace(':', '').replace('T', 'T').replace('Z', 'Z')
    token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN') or ''

    urls = set()
    for item in tools:
        for link in item.get('sources', []):
            url = link.get('url')
            if isinstance(url, str) and url.startswith('https://'):
                urls.add(url)
    for source in sources:
        url = source.get('url')
        if isinstance(url, str) and url.startswith('https://'):
            urls.add(url)

    link_results = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(check_link, url, args.timeout): url for url in sorted(urls)}
        for future in as_completed(future_map):
            url = future_map[future]
            try:
                link_results[url] = future.result()
            except Exception as exc:
                link_results[url] = {'url': url, 'status': 'unreachable', 'http_status': None, 'final_url': url, 'error': f'{type(exc).__name__}: {exc}'}

    repo_pairs = {}
    for item in tools:
        for link in item.get('sources', []):
            pair = github_repo_from_url(link.get('url', ''))
            if pair:
                repo_pairs[pair] = f'{pair[0]}/{pair[1]}'
    repo_results = {}
    for owner, repo in sorted(repo_pairs):
        repo_results[f'{owner}/{repo}'] = audit_github_repository(owner, repo, token, args.timeout, checked_at)
        time.sleep(0.08)

    old_metadata = {}
    metadata_changed = False
    for item in tools:
        pair = next((github_repo_from_url(x.get('url', '')) for x in item.get('sources', []) if github_repo_from_url(x.get('url', ''))), None)
        if not pair:
            continue
        key = f'{pair[0]}/{pair[1]}'
        new_meta = repo_results.get(key)
        if not new_meta:
            continue
        old_meta = item.get('upstream_metadata', {})
        old_metadata[item['id']] = old_meta
        item['upstream_metadata'] = {
            'latest_release': new_meta.get('latest_release', 'غير متوفر'),
            'latest_tag': new_meta.get('latest_tag', 'غير متوفر'),
            'last_repository_update': new_meta.get('repository_updated_at', 'غير متوفر'),
            'archived': new_meta.get('archived', 'غير متوفر'),
            'spdx_license': new_meta.get('license_spdx', 'غير متوفر'),
            'metadata_status': new_meta.get('metadata_status', 'غير متوفر'),
            'metadata_checked_at': checked_at,
            'repository_url': new_meta.get('repository_url', 'غير متوفر'),
        }
        if old_meta != item['upstream_metadata']:
            metadata_changed = True

    source_status_by_pair = {}
    for result in link_results.values():
        source_status_by_pair[result['url']] = result
    for source in sources:
        result = source_status_by_pair.get(source.get('url'))
        if result:
            source['last_checked_at'] = checked_at
            source['last_http_status'] = result.get('http_status')
            source['last_check_status'] = result.get('status')
            source['final_url'] = result.get('final_url')

    broken = [r for r in link_results.values() if r['status'] not in ('ok', 'restricted_or_rate_limited')]
    restricted = [r for r in link_results.values() if r['status'] == 'restricted_or_rate_limited']
    redirects = [r for r in link_results.values() if r.get('final_url') and r.get('final_url') != r['url']]
    archived = [k for k,v in repo_results.items() if v.get('archived') is True]
    unavailable = [k for k,v in repo_results.items() if v.get('metadata_status') != 'ok']
    report = {
        'auditor': 'Al-Hakim-Cyber-Security/Scripts/audit_catalog.py',
        'checked_at': checked_at,
        'counts': {'catalog_records': len(tools), 'unique_links': len(urls), 'github_repositories': len(repo_results), 'broken_or_unreachable_links': len(broken), 'restricted_links': len(restricted), 'redirected_links': len(redirects), 'archived_repositories': len(archived), 'unavailable_repository_metadata': len(unavailable)},
        'link_checks': [link_results[u] for u in sorted(link_results)],
        'github_repositories': repo_results,
        'archived_repositories': archived,
        'unavailable_repository_metadata': unavailable,
        'notes': ['HTTP 401/403/429 responses are recorded as restricted or rate-limited, not asserted to be broken.', 'GitHub metadata reflects the public API response at check time.', 'Non-GitHub releases and product lifecycle must be verified from their official publishers.']
    }

    if args.save:
        path = unique_history_path(timestamp)
        report['previous_automated_metadata'] = old_metadata
        write_json(path, report)
        write_json(TOOLS_PATH, tools)
        write_json(SOURCES_PATH, sources)
        print(f'Saved historical audit: {path.relative_to(ROOT)}')
        print('Updated only automated upstream_metadata fields; prior values are preserved in the snapshot.')
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))

    print(json.dumps(report['counts'], ensure_ascii=False))
    if broken:
        return 2
    return 0

if __name__ == '__main__':
    sys.exit(main())
