# Pipeline / account residual · 2026-08-07

## Changes
- New conf: `[app:proxy-server] strict_pipeline = true|false` (default **false**, lab-safe).
- When **true**, unknown or unimplemented pipeline filter names hard-fail startup (exit 1).
- When **false**, keep skip+log (Python-shaped pipeline paste without claiming full Paste).

## allow_account_management
Already implemented: conf → ProxyConfig; account PUT/DELETE → 405 when off.
Unit reaffirmed: `allow_account_management_defaults_false_and_can_enable`.

## Tests
- `pipeline_unknown_filter_note_when_lenient` — ok
- `pipeline_unknown_filter_still_skips` — ok
- `pipeline_strict_conf_parses_true` — ok
- `allow_account_management_defaults_false_and_can_enable` — ok
- broader `pipeline_*` suite: 14/14 ok (`01b-binary-tests.txt`)
- lib suite: 18/18 ok (`01-cargo-test.txt`)

## Verdict
**KEEP for allow_account_management**  
**CLOSED residual for unknown filter** via optional `strict_pipeline` (Paste-like when on; default off for Contabo)

## Not claimed
- Full arbitrary Paste filter implementations
- Contabo conf already using `strict_pipeline=true`
