# corpus_gathering

Keep debugger-side collection separate from the fuzz target.

Suggested files:

- `trace_syscalls.js`: WinDbg JavaScript allow-list recorder
- `schemas/syscalls.json`: parameter and pointer schemas
- `captures/*.jsonl`: entry/return observations
- `normalize_trace.py`: replace raw handles and pointers with logical IDs
- `build_seed.py`: turn normalized calls into binary seeds

Start with a small GDI allow-list. Capture entry arguments and return values, then
normalize a returned HBITMAP/HDC into a logical resource ID used by later calls.
Do not blindly dereference every register; only read bounded memory described by
a trusted schema.
