# Midn Core Architecture

Modular ECS-driven Private LTE/5G Core Network.

## Crates

| Crate | Role | Phase |
|---|---|---|
| midn-auth | Milenage/TUAK authentication | 1 |
| midn-proto | NAS, S1AP, NGAP, GTP-U | 2 |
| midn-core | MME/AMF + ECS orchestrator | 2 |
| midn-userplane | UPF + eBPF loader | 3 |
| midn-userplane-ebpf | XDP kernel program | 3 |

## Dependency Graph

```
midn-auth
    ↑
midn-proto
    ↑          ↑
midn-core   midn-userplane
                ↑
        midn-userplane-ebpf (kernel, no_std)
```

## Performance Targets

| System | Target |
|---|---|
| Milenage auth vector | < 10 µs |
| GTP-U parse | < 500 ns/packet |
| ECS subscriber capacity | 100k+ |
| XDP routing | line rate |
