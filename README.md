# Flight Control
Flight Control is a service for declarative, GitOps-driven management of edge device fleets running [ostree-based](https://github.com/ostreedev/ostree) Linux system images.

> [!NOTE]
> Flight Control is still in early stage development!

## Building

Prerequisites:
* `git`, `make`, and `go` (>= 1.20), and `podman-compose`

Flightctl agent reports the status of running rootless containers. Ensure the podman socket is enabled:

`systemctl --user enable --now podman.socket`

Checkout the repo and from within the repo run:

```
make build
```

## Running

Start the Flight Control database:

```
podman-compose -f deploy/podman/compose.yaml up
```

Start the Flight Control API server:

```
bin/flightctl-server
```

Note it stores its generated CA cert, server cert, and client-bootstrap cert in `$HOME/.flightctl/certs`.

Use the `flightctl` CLI to apply, get, or delete resources:

```
bin/flightctl apply -f examples/fleet.yaml
bin/flightctl get fleets
```

Use the `devicesimulator` to simulate load from devices:

```
bin/devicesimulator --count=100
```

## Metrics

Start the observability stack:

```
podman-compose deploy/podman/observability.yaml up
```

The Grafana and Prometheus web UIs are then accessible on `http://localhost:3000` and `http://localhost:9090`, respectively.