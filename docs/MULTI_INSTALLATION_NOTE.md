# Multi-Installation Token Rotation Limitation Note

> [!IMPORTANT]
> **Single-Tenant / Per-Process Scope**: Installation Access Tokens (IAT) in NANTIS are currently cached in an in-memory `Map` within the running Node process.

## Current Behavior & Scope
- **In-Memory Cache**: Installation access tokens are cached per process with a maximum 50-minute lifespan and evicted on access or periodic sweep.
- **Single-Tenant Focus**: The current design targets single-tenant deployments or dedicated worker processes handling one installation context at a time.

## Unsupported Feature
- **Multi-Installation Token Rotation**: Automatic distributed token rotation across multi-installation cluster setups is **not yet supported**. Distributed environments requiring cross-node token sharing should implement a shared Redis/Key-Value store with TTL enforcement.
