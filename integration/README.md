# SMB1 integration test server

Dockerized Samba server configured to accept SMB1 (NT1), used as the blackbox
target for this repo's integration test suite.

## Start / stop

```sh
integration/up.sh    # build + start (idempotent)
integration/down.sh  # stop + remove
```

Both wrap `docker compose` (service `samba`, container `smb1client-test`).
The server listens on host port 10445, mapped to the container's port 445.

## How tests use it

Run from the repo root:

```sh
go test -tags integration -count=1 ./
```

The suite reads these environment variables; the defaults already match this
server, so none need to be set when using it:

| Variable       | Default           |
|----------------|-------------------|
| `SMB_SERVER`   | `localhost:10445` |
| `SMB_USER`     | `smbtest`         |
| `SMB_PASSWORD` | `smbtest`         |
| `SMB_DOMAIN`   | (empty)           |
| `SMB_SHARE`    | `testshare`       |

The share `testshare` is writable by `smbtest` and backed by `/srv/testshare`
inside the container (ephemeral; wiped on `down.sh`).
