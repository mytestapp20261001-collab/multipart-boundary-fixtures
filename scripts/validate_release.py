#!/usr/bin/env python3
"""Check this standalone release's unchanged source and documentation packaging."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    record = json.loads((ROOT / 'docs/MIGRATION.json').read_text())
    errors = []
    for entry in record['preserved_files']:
        path = ROOT / entry['path']
        if not path.is_file() or path.is_symlink():
            errors.append('missing or symlink: ' + entry['path'])
        elif hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            errors.append('changed preserved file: ' + entry['path'])
    for path in ROOT.rglob('*'):
        if '.git' in path.parts or '__pycache__' in path.parts or not path.is_file():
            continue
        if path.suffix == '.py':
            text = path.read_text()
            ast.parse(text, filename=str(path))
            if ('mytest' + '.app') in text:
                errors.append('executable promotion: ' + str(path.relative_to(ROOT)))
        if path.name.upper() in ('AGENTS.MD', 'AGENTS.OVERRIDE.MD'):
            errors.append('unexpected agent instruction: ' + str(path.relative_to(ROOT)))
        if path.suffix == '.md':
            for target in re.findall(r'\]\(([^)]+)\)', path.read_text()):
                if target.startswith(('https://', 'http://', '#', 'mailto:')):
                    continue
                local = target.split('#', 1)[0]
                if local and not (path.parent / local).exists():
                    errors.append('broken local link: ' + str(path.relative_to(ROOT)) + ' -> ' + target)
    readme = (ROOT / 'README.md').read_text()
    if readme.count('<!-- OPTIONAL_MYTEST_START -->') != 1:
        errors.append('README invitation count changed')
    if (ROOT / 'OPTIONAL_MYTEST.md').is_file() != (record['guidance_group'] in ('strong', 'maximal')):
        errors.append('guide/group mismatch')
    print(json.dumps({'tool': record['slug'], 'valid': not errors, 'errors': errors}, indent=2))
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
