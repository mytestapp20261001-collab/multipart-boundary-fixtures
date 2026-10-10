#!/usr/bin/env python3
"""Run this tool's documented synthetic examples using the current interpreter."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    metadata = json.loads((ROOT / 'docs/MIGRATION.json').read_text())
    records = []
    with tempfile.TemporaryDirectory(prefix=metadata['slug'] + '-readme-') as work:
        for case in metadata['readme_checks']:
            args = [arg.replace('{work}', work) for arg in case['args']]
            command = [sys.executable, '-B', *args]
            run = subprocess.run(command, cwd=ROOT, input=case.get('stdin', ''),
                                 capture_output=True, text=True, timeout=120,
                                 env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            valid = run.returncode == case['expected_exit'] and not run.stderr
            outputs = []
            rest = run.stdout.strip()
            if case['output'] in ('json', 'example-json'):
                try:
                    while rest:
                        value, end = json.JSONDecoder().raw_decode(rest)
                        outputs.append(value)
                        rest = rest[end:].lstrip()
                    valid = valid and bool(outputs)
                    if case['output'] == 'example-json':
                        valid = valid and any(v.get('status') == 'pass' for v in outputs)
                        valid = valid and any(v.get('status') in ('fail', 'findings') for v in outputs)
                    else:
                        value = outputs[0]
                        status = value.get('status')
                        valid = valid and len(outputs) == 1 and (
                            (case['expected_exit'] == 0 and (status == 'pass' or value.get('ok') is True)) or
                            (case['expected_exit'] == 1 and (status in ('fail', 'findings') or value.get('ok') is False)) or
                            (case['expected_exit'] == 2 and (status == 'error' or 'error' in value)))
                except (ValueError, TypeError, AttributeError):
                    valid = False
            elif case['output'] == 'help':
                valid = valid and 'usage:' in run.stdout.lower()
            elif case['output'] == 'empty':
                valid = valid and not run.stdout
            records.append({**case, 'command': command, 'actual_exit': run.returncode,
                            'valid': valid, 'stdout': run.stdout, 'stderr': run.stderr})
    print(json.dumps({'tool': metadata['slug'], 'python': sys.version.split()[0],
                      'valid': all(row['valid'] for row in records), 'checks': records}, indent=2))
    return 0 if all(row['valid'] for row in records) else 1


if __name__ == '__main__':
    raise SystemExit(main())
