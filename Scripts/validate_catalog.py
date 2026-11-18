#!/usr/bin/env python3
"""Validate the local catalog shape, identifiers, categories, and source URLs."""
import json
from pathlib import Path
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_TOOL_FIELDS = {
    'id', 'official_name', 'record_type', 'category_ids', 'description', 'security_classification',
    'sources', 'supported_operating_systems', 'requirements', 'programming_languages', 'project_status',
    'license', 'pricing_status', 'official_installation', 'difficulty', 'authorized_uses', 'alternatives',
    'upstream_metadata', 'verification'
}


def load(path):
    with path.open(encoding='utf-8') as handle:
        return json.load(handle)


def main():
    errors = []
    tools = load(ROOT / 'Database' / 'tools.json')
    sources = load(ROOT / 'Database' / 'sources.json')
    categories = load(ROOT / 'Database' / 'categories.json')

    if not isinstance(tools, list) or not isinstance(sources, list) or not isinstance(categories, list):
        print('FAIL: tools, sources, categories must be JSON arrays.')
        return 1

    tool_ids = [x.get('id') for x in tools]
    category_ids = [x.get('id') for x in categories]
    source_ids = [x.get('source_id') for x in sources]
    for label, values in [('tool', tool_ids), ('category', category_ids), ('source', source_ids)]:
        if None in values:
            errors.append(f'{label} record without id')
        if len(values) != len(set(values)):
            errors.append(f'duplicate {label} identifiers')

    known_categories = set(category_ids)
    for tool in tools:
        missing = REQUIRED_TOOL_FIELDS - set(tool)
        if missing:
            errors.append(f"{tool.get('id')}: missing fields {sorted(missing)}")
        for cat in tool.get('category_ids', []):
            if cat not in known_categories:
                errors.append(f"{tool.get('id')}: unknown category {cat}")
        if not isinstance(tool.get('sources'), list):
            errors.append(f"{tool.get('id')}: sources must be an array")
        for source in tool.get('sources', []):
            url = source.get('url', '')
            parsed = urlparse(url)
            if parsed.scheme != 'https' or not parsed.netloc:
                errors.append(f"{tool.get('id')}: invalid/non-HTTPS source URL {url!r}")

    tool_set = set(tool_ids)
    for category in categories:
        listed = category.get('tool_ids', [])
        if len(listed) != len(set(listed)):
            errors.append(f"{category.get('id')}: duplicate tool ids in category")
        for tid in listed:
            if tid not in tool_set:
                errors.append(f"{category.get('id')}: unknown tool id {tid}")
    for source in sources:
        parsed = urlparse(source.get('url', ''))
        if parsed.scheme != 'https' or not parsed.netloc:
            errors.append(f"{source.get('source_id')}: invalid/non-HTTPS source URL {source.get('url')!r}")
        if source.get('record_id') not in tool_set:
            errors.append(f"{source.get('source_id')}: unknown record id {source.get('record_id')}")

    # Ensure every tool-category relation has a matching category index entry.
    for tool in tools:
        for cat_id in tool.get('category_ids', []):
            category = next((c for c in categories if c.get('id') == cat_id), None)
            if category and tool.get('id') not in category.get('tool_ids', []):
                errors.append(f"{tool.get('id')}: absent from category index {cat_id}")

    if errors:
        print('FAIL: catalog validation found issues:')
        for err in errors:
            print(f'- {err}')
        return 1
    unique_urls = len({x['url'] for x in sources})
    print(f'PASS: {len(tools)} records, {len(categories)} categories, {len(sources)} source entries, {unique_urls} distinct source URLs; identifiers and JSON structure are consistent.')
    return 0

if __name__ == '__main__':
    sys.exit(main())
