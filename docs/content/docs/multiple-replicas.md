---
title: "Running multiple replicas"
weight: 26
---

You can run several replicas of the Revaulter server behind a load balancer for high availability.

## Requirements

- A PostgreSQL database (with SQLite, you can only run a single replica)
- The same version of Revaulter on every replica

For high availability, you can run multiple replicas of Revaulter. Because Revaulter uses the Francis actor framework in the embedded mode, it's recommended to run at most 4 replicas.

## Configuration

Every replica uses the same configuration, except for `francisPeerAddress`:

- `databaseDSN`, `secretKey`, and `sessionSigningKey` must have the same values on all replicas. `sessionSigningKey` is required.
- `francisPeerAddress` is the address (host and port) the other replicas use to reach this one. Each replica sets its own address, such as its IP address with port `7571`, and it must be able to listen on that address.

Replicas connect to each other over UDP on the port configured in `francisPeerAddress`. Allow traffic on that port between the replicas only, and don't expose it publicly.

On Kubernetes, you can set `francisPeerAddress` from the pod's IP address:

```yaml
env:
  - name: POD_IP
    valueFrom:
      fieldRef:
        fieldPath: status.podIP
  - name: REVAULTER_FRANCISPEERADDRESS
    value: "$(POD_IP):7571"
```

## Load balancer

You can use any load balancer, such as Nginx, Traefik, Caddy, or HAProxy.

Configure health checks on the `/healthz` path.

## When a replica stops

If the replica a CLI command is waiting on stops, the command ends with an error. Run the command again.

## Upgrading

Stop all replicas, then start them again on the new version.
