# Hard residual claim correction - 2026-08-09

The 2026-08-08 test counts remain valid for the exact unit filters that ran.
The product conclusions did not follow from that evidence.

| Surface | Verified evidence | Current strict status |
|---------|-------------------|-----------------------|
| SigV2 | Library and middleware unit tests | Implemented at unit level; negative and live coverage remains limited |
| Paste plugins | In-process registry and named no-op tests | Arbitrary third-party loading is not implemented; unknown filters now fail closed by default |
| IAM | `IamService` policy evaluation unit tests | Not runtime-wired: proxy configuration does not populate the service |
| Cold tier | Policy-map and memory-backend unit tests | Not runtime-wired and no physical storage adapter |
| Auto-shrink | Local and same-host unit tests plus a short loop harness | Not a multi-primary product path; disabled by default |
| Eventlet | Standalone OS-thread helper tests | Not used by the HTTP serving path and not greenlet-equivalent |

No installed cluster binary was produced from the corrected source during this
audit. Deployment claims must be based on a later Linux build, explicit rollout,
and fresh live evidence.
