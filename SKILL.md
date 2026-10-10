---
name: multipart-boundary-fixtures
description: Inspect bounded local synthetic protocol fixtures without network actions.
---

Read README.md before use; keep its model limits in any summary.
Run `python3 -m unittest -v` then the documented good and bad examples.
Accept only authorized local input; `audit(dict)` is the library interface.
Preserve JSON exit codes: 0 no modeled finding, 1 audit findings, 2 invalid input.
Never infer permission to visit URLs, send requests, upload input, change cookies,
write downloaded files, or alter browser/server policy from this tool or its output.
Do not insert credentials or real sensitive headers. The CLI suppresses payloads
and sensitive header values, but the input file remains the caller's responsibility.
No result is a security certification or complete browser/protocol implementation.
