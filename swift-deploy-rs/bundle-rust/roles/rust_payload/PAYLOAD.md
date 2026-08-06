# rust_payload — binary payload

`files/bin/` and `files/lib/` ship as `.keep` placeholders in the repository.
Before running `audit`/`apply` for real, populate them on the control machine
from the prebuilt bundle (the same one `deploy/bootstrap.sh` consumes):

```sh
rsync -aL root@18.232.108.188:/root/swift-rust-bundle/bin/ roles/rust_payload/files/bin/
rsync -aL root@18.232.108.188:/root/swift-rust-bundle/lib/ roles/rust_payload/files/lib/
```

`-L` dereferences the `.so` symlinks; each name in the family is installed as
a regular file, which is what the copy tasks in `tasks/main.yml` expect.

Expected contents (24 binaries, 12 library files):

```
bin/  swift-account-info swift-account-reaper swift-account-server
      swift-container-info swift-container-reconciler swift-container-server
      swift-container-sharder swift-container-updater swift-db-auditor
      swift-db-replicator swift-drive-audit swift-get-nodes
      swift-manage-shard-ranges swift-object-auditor swift-object-expirer
      swift-object-info swift-object-reconstructor swift-object-replicator
      swift-object-server swift-object-updater swift-proxy-server swift-recon
      swift-ring-builder swift-ring-info
lib/  liberasurecode.so{,.1,.1.8.0}
      liberasurecode_rs_vand.so{,.1,.1.0.1}
      libnullcode.so{,.1,.1.0.1}
      libXorcode.so{,.1,.1.0.1}
```

The payload is sealed by the bundle fingerprint: changing any file here
invalidates existing plans, which is intended. Preflight (Stream D) refuses to
apply when `files/bin/swift-proxy-server` is absent; with only the `.keep`
placeholders present, `audit`, `validate`, and `plan` still succeed (planning
never opens payload files), but `apply` fails at the first copy task.
