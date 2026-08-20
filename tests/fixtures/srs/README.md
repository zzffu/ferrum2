# sing-box SRS fixtures

These binary fixtures are immutable qualification inputs for Ferrum2's strict
sing-box rule-set decoder. They were downloaded on 2026-08-20 from commit
`c1a9c12f6883814efc8aab387cdde75cd9e11297` of
`DustinWin/ruleset_geodata` (branch `sing-box-ruleset`). All four files use SRS
format version 2.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `ads.srs` | 782961 | `b14246f9a337098943be120e3fd5b9e1d923341626b694a76906ad4db6df8dfa` |
| `ai.srs` | 1798 | `b88e24a7405bc2fc25c92e5c50e24ba3973b7f4a887762634f4838491131ad96` |
| `cn.srs` | 443816 | `6c1f3537c7b9b93fa32861108b7485ddab8a3271c4f71b1b0bd82a74f540eb8c` |
| `cnip.srs` | 22948 | `3c6cff87a0949890622a953c90a270cf53e4532b8f9a75aab58b23bf78a5555e` |

Pinned source URLs have this form:

```text
https://raw.githubusercontent.com/DustinWin/ruleset_geodata/c1a9c12f6883814efc8aab387cdde75cd9e11297/<name>.srs
```

Do not replace a fixture from a mutable branch URL. Record the new commit,
byte length, SHA-256 digest, fetch date, and SRS generator version whenever a
fixture is intentionally refreshed.
