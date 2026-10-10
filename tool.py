#!/usr/bin/env python3
"""Bounded offline audit. No network access or external state changes."""
import argparse
import json
import math
import re
import sys
import stat
from pathlib import Path

MAX_BYTES = 262144
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")

class InputError(ValueError):
    pass

class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse messages may contain raw options, paths, or caller secrets.
        raise InputError("invalid command-line arguments")

def require(condition, message):
    if not condition:
        raise InputError(message)

def schema(data, required, optional=()):
    require(isinstance(data, dict), "input must be an object")
    require(set(required) <= data.keys(), "missing required input field")
    require(data.keys() <= set(required) | set(optional), "unknown input field")

def integer(value, minimum=0, maximum=253402300799):
    require(type(value) is int and minimum <= value <= maximum, "integer outside supported range")
    return value

def string(value, limit=8192):
    require(isinstance(value, str) and len(value) <= limit, "string outside supported length")
    require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), "invalid Unicode scalar")
    return value

def header(value):
    string(value)
    require(not any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value), "header contains control characters")
    return value

def result(findings, **fields):
    return {"schema_version": 1, "ok": not findings, "findings": findings, **fields}

def issue(code, **extra):
    return {"code": code, **extra}

def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate JSON key")
        obj[key] = value
    return obj

def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--input", default="-", help="JSON file, or - for stdin (maximum 256 KiB)")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    args = None
    try:
        args = parser.parse_args(argv)
        if args.input == "-":
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            require(stat.S_ISREG(Path(args.input).stat().st_mode), "input path must be a regular file")
            with open(args.input, "rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES, "input exceeds 256 KiB")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(InputError("non-finite JSON number")))
        out = audit(data)
    except InputError as exc:
        out = {"schema_version": 1, "ok": False, "error": {"code": "invalid_input", "message": str(exc)}}
        code = 2
    except (OSError, UnicodeError, ValueError, RecursionError, OverflowError):
        out = {"schema_version": 1, "ok": False, "error": {"code": "invalid_input", "message": "unreadable, malformed, or excessively nested input"}}
        code = 2
    else:
        code = 0 if out["ok"] else 1
    print(json.dumps(out, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2 if args is not None and args.pretty else None))
    return code

import base64
import binascii
import hashlib


def boundary_bytes(value):
    string(value, 70)
    require(bool(re.fullmatch(r"[0-9A-Za-z'()+_,./:=? -]{1,70}", value)) and not value.endswith(' '), "invalid MIME boundary parameter")
    return value.encode('ascii')


def build_fixture(boundary, parts, closing=True, newline='crlf'):
    sep = b'\r\n' if newline == 'crlf' else b'\n'
    marker = b'--' + boundary
    wire = b''
    for part in parts:
        wire += marker + sep + b'Content-Type: text/plain; charset=utf-8' + sep + sep + part + sep
    if closing:
        wire += marker + b'--' + sep
    return wire


def inspect_wire(boundary, wire):
    marker = b'--' + boundary
    findings, delimiters = [], []
    offset = 0
    # Only LF creates a candidate line start. Bare CR is an ordinary binary
    # payload byte, not a line boundary (unlike bytes.splitlines()).
    lines = wire.split(b'\n')
    for index, chunk in enumerate(lines):
        line = chunk + (b'\n' if index < len(lines) - 1 else b'')
        if line.startswith(marker):
            if offset and wire[max(0,offset-2):offset] != b'\r\n':
                findings.append(issue('non_crlf_before_delimiter', offset=offset))
            if line.endswith(b'\n') and not line.endswith(b'\r\n'):
                findings.append(issue('non_crlf_delimiter_ending', offset=offset))
            # Strip one exact framing ending, never arbitrary CR/LF bytes.
            # A closing delimiter may end at EOF, but a dangling CR is invalid.
            ending = line[:-2] if line.endswith(b'\r\n') else line[:-1] if line.endswith(b'\n') else line
            suffix = ending[len(marker):].rstrip(b' \t')
            if suffix not in (b'', b'--'):
                findings.append(issue('boundary_prefix_collision_or_invalid_suffix', offset=offset))
            else:
                if suffix == b'' and not line.endswith(b'\r\n') and not line.endswith(b'\n'):
                    findings.append(issue('non_crlf_delimiter_ending', offset=offset))
                delimiters.append((offset, offset+len(line), suffix == b'--'))
        offset += len(line)
    if not delimiters or delimiters[0][0] != 0:
        findings.append(issue('missing_initial_delimiter_or_unsupported_preamble'))
    closing = [d for d in delimiters if d[2]]
    if len(closing) != 1:
        findings.append(issue('closing_delimiter_count', count=len(closing)))
    if closing and closing[-1][1] != len(wire):
        findings.append(issue('data_after_closing_delimiter_outside_subset'))
    regular = [d for d in delimiters if not d[2]]
    if not regular:
        findings.append(issue('no_parts'))
    if delimiters and delimiters[-1][2] is False:
        findings.append(issue('last_delimiter_is_not_closing'))
    for i, delim in enumerate(delimiters):
        if delim[2]:
            continue
        end = delimiters[i+1][0] if i+1 < len(delimiters) else len(wire)
        block = wire[delim[1]:end]
        split = block.find(b'\r\n\r\n')
        # Empty header section consists of a single CRLF after delimiter's CRLF.
        if not block.startswith(b'\r\n') and not 0 <= split <= 8192:
            findings.append(issue('missing_or_oversized_part_header_separator', part=i))
    return findings, len(regular), len(closing)


def audit(data):
    require(isinstance(data,dict), 'input must be an object')
    mode = data.get('mode')
    require(mode in ('synthesize','inspect'), 'mode must be synthesize or inspect')
    if mode == 'synthesize':
        schema(data, ('mode','boundary','parts'), ('closing','newline'))
    else:
        schema(data, ('mode','boundary','wire_base64'))
    boundary = boundary_bytes(data['boundary'])
    findings = []
    if mode == 'synthesize':
        parts = data['parts']
        require(isinstance(parts,list) and 1 <= len(parts) <= 32, 'parts must contain 1..32 strings')
        parts = [string(part,8192).encode('utf-8') for part in parts]
        require(sum(map(len,parts)) <= 131072, 'part payload exceeds 128 KiB')
        closing, newline = data.get('closing',True), data.get('newline','crlf')
        require(type(closing) is bool, 'closing must be boolean')
        require(newline in ('crlf','lf'), 'newline must be crlf or lf')
        for i, part in enumerate(parts):
            # Conservative prefix detection includes LF-only tolerant-parser hazards.
            for line_no,line in enumerate(part.split(b'\n')):
                if line.startswith(b'--'+boundary):
                    findings.append(issue('payload_boundary_prefix_collision', part=i, line=line_no))
        wire = build_fixture(boundary,parts,closing,newline)
    else:
        raw = string(data['wire_base64'], 200000)
        try:
            wire = base64.b64decode(raw,validate=True)
        except (ValueError,binascii.Error) as exc:
            raise InputError('wire_base64 must be strict base64') from exc
        require(len(wire) <= 131072, 'wire exceeds 128 KiB')
    checked,count,closing_count=inspect_wire(boundary,wire)
    findings.extend(checked)
    return result(findings, mode=mode, wire_bytes=len(wire), wire_sha256=hashlib.sha256(wire).hexdigest(),
                  observed_part_delimiters=count, closing_delimiters=closing_count,
                  payloads_echoed=False, scope='CRLF framing; no preamble/epilogue or nested MIME semantics')

if __name__ == '__main__':
    raise SystemExit(main())
