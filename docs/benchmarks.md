# Performance follow-up

These are local development measurements, not production capacity guarantees.
The starting tree was commit `148a52f`. The native backend was enabled unless
specified; both backend test suites and RFC vectors remain validation gates.

| Workload | Before | After |
|---|---:|---:|
| Authorize last holder among 10,000 grants | 223 µs | 0.53 µs |
| Revoke a root with 5,000 children | 530 ms | 4.63 ms |
| Zone-widening lookup among 10,000 entries | 411 µs | 1.98 µs |
| Contact absent custody addressee among 10,000 bundles | 383 µs | 0.68 µs |
| Route through a chain of 500 centers | 3.01 ms | 250 µs |
| 20,000 journal events, retained allocation | 4.47 MB | 2.23 MB (10,000 retained) |

A separate 50-exchange loopback comparison verified every reply: opening a new
TCP connection for each request took median 465 µs and accepted 50 connections;
the pool took median 43 µs and accepted one connection. Exchanges were sequential,
not multiplexed, and all resources were closed at the end.

After public-constant precomputation, a repeated 2 KB native encryption workload
measured 125 µs through the stateless function versus 65 µs with an explicit
SecureContext. Decryption measured 132 µs versus 73 µs. These compare the two
current APIs on the same data and exclude context construction from per-message
timing; a context is owned and reused for a link key's lifetime.

The repaired benchmark can be reproduced with:

```sh
python experiments/bench.py --iterations 10 --node-frames 2000
```

It verified 2,000/2,000 delivered envelopes at about 9.6 µs/frame in one local run.
Do not compare that with earlier reported node throughput: the previous harness
counted 128 unknown-service replies and 1,872 quota refusals as 2,000 processed
messages, and crypto timing executed once while dividing by 200. New timing uses
three repeated runs, real iteration counts, warmed tables, precomputed decryption
inputs, and a valid two-party VKO exchange whose derived keys must match.
