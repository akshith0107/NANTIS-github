# NANTIS Worker Execution & Sandbox Security Architecture

## 1. Overview & Security Model

The NANTIS worker package (`packages/worker`) executes static security scans, AST analyses, git history searches, dependency checks, and future compilation/test steps (`tsc`, `pnpm test`, `pnpm build`) against code submitted by untrusted users and strangers (e.g. pull requests, external GitHub repositories).

Executing untrusted code or build scripts on shared infrastructure introduces severe security risks, including arbitrary code execution, credential exfiltration, resource hijacking, and kernel privilege escalation.

NANTIS employs a **Zero-Trust Ephemeral Sandboxing Strategy** governed by defense-in-depth isolation, strict network egress controls, resource caps, and guaranteed post-job destruction.

---

## 2. Isolation Architecture & Spec

### 2.1 Default Container Execution Specification

Each scan job executes inside an isolated OCI container created on demand:

```dockerfile
# OCI Runtime Container Configuration Spec
USER nantis:10001
READONLY_ROOT: true
CAPABILITIES: DROP ALL
NETWORK: isolated-egress-bridge
TMPFS: /tmp:rw,noexec,nosuid,size=500m
CPU_LIMIT: 2.0 cores
MEMORY_LIMIT: 1024MB
PIDS_LIMIT: 100
MAX_JOB_TIME: 60 seconds
```

### 2.2 Security Parameters Explained

1. **Ephemeral Instance per Job (`--rm`)**:
   Every job starts from a clean base image. No container state or file modification persists between separate scan executions.

2. **Read-Only Root Filesystem (`--read-only`)**:
   The container's root filesystem is mounted read-only. Malicious code cannot overwrite system binaries, install persistent backdoors, or mutate container configuration.

3. **Non-Root Execution (`USER nantis:10001`)**:
   Jobs run under a dedicated unprivileged user ID (`uid=10001`, `gid=10001`). Root access inside the container is explicitly forbidden.

4. **Dropped Linux Capabilities (`--cap-drop=ALL`)**:
   All Linux kernel capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_RAW_SOCKET`, `CAP_CHOWN`, etc.) are stripped. The process cannot modify kernel state, configure network interfaces, or mount filesystems.

5. **No Mounted Host Credentials / Secrets**:
   Host credentials (AWS keys, database passwords, Docker sockets, system SSH keys) are never volume-mounted into the container.

6. **Strict Resource Quotas (cgroups v2)**:
   - **CPU**: Max 2.0 cores (`--cpus=2.0`). Prevents CPU starvation for neighboring jobs.
   - **Memory**: Hard limit 1024MB RAM (`--memory=1024m`, `--memory-swap=1024m`). Prevents Out-Of-Memory (OOM) host exhaustion.
   - **Disk (tmpfs)**: Workspace and `/tmp` are mounted as bounded `tmpfs` volumes capped at 500MB with `noexec` and `nosuid` options.
   - **Process Cap**: Max 100 concurrent tasks (`--pids-limit=100`). Mitigates fork bombs.
   - **Execution Time**: Hard 60-second execution wall-clock timeout enforced by worker timer.

---

## 3. Trade-Offs & Multi-Tier Isolation

### 3.1 Isolation Technology Comparison

| Isolation Layer                    | Startup Latency | Overhead          | Syscall Boundary Protection     | Kernel Sharing          |
| ---------------------------------- | --------------- | ----------------- | ------------------------------- | ----------------------- |
| **OCI Container (`runc`)**         | ~100ms          | Minimal (<1%)     | Low (Shares host kernel)        | Shared Linux Kernel     |
| **gVisor (`runsc`)**               | ~150ms          | Low (5-15%)       | High (User-space Sentry kernel) | Isolated Syscall Layer  |
| **MicroVM (`Firecracker / Kata`)** | ~250ms - 500ms  | Moderate (10-20%) | Maximum (KVM Hardware boundary) | Separate Kernel per Job |

### 3.2 When Container Isolation is NOT Enough

Standard OCI container isolation (`runc`) relies on Linux kernel namespaces and cgroups. It is **insufficient** in the following scenarios:

1. **Kernel Zero-Day Exploits**:
   If an untrusted dependency or build script exploits a Linux kernel vulnerability (e.g. `Dirty COW`, `cgroup` escapes), it can escape container bounds and compromise the underlying host node.

2. **Native C/C++ Code Compilation (`node-gyp`, binary addons)**:
   Running `npm install` or `pnpm build` on repositories with native addons executes arbitrary C/C++ build hooks (`preinstall`, `postinstall`, `make`, `gcc`) that interact directly with the kernel syscall interface.

3. **Multi-Tenant Public Execution**:
   When scanning repositories for arbitrary public GitHub users, hardware-assisted virtualization boundaries (**Firecracker** or **gVisor**) **MUST** be enabled to enforce an explicit hardware hypervisor boundary.

---

## 4. Network Egress Enforcement Layer

Network isolation is enforced **at the network and infrastructure layer**, independent of application code. Stating "the core code does not make network calls" is insufficient for untrusted code execution.

```
+-----------------------------------------------------------------------------------+
| CONTAINER SANDBOX (isolated netns)                                               |
|                                                                                   |
|  +-------------------+        +--------------------+                              |
|  | Scan Engine / Node|        | Untrusted Script   |                              |
|  +---------+---------+        +---------+----------+                              |
|            |                            | (BLOCKED)                               |
|            v                            v                                         |
|  +-------------------------------------------------+                              |
|  | veth0 / Container Network Namespace             |                              |
|  +-------------------------+-----------------------+                              |
+----------------------------|------------------------------------------------------+
                             |
                             v
+-----------------------------------------------------------------------------------+
| HOST EGRESS FIREWALL (iptables / nftables / eBPF Cilium)                          |
|                                                                                   |
|  1. DROP LINK-LOCAL METADATA:  169.254.169.254 / 169.254.0.0/16       ==> DROP     |
|  2. ALLOW EGRESS ALLOWLIST:   github.com (443), api.github.com (443)  ==> ACCEPT   |
|                               api.osv.dev (443)                       ==> ACCEPT   |
|  3. DEFAULT POLICY:           0.0.0.0/0 (ALL OTHER DESTINATIONS)      ==> DROP     |
+-----------------------------------------------------------------------------------+
```

### 4.1 Enforcement Controls

1. **Isolated Network Namespace (`netns`)**:
   Each container runs in its own private network namespace connected to a custom Docker bridge network (`nantis-sandbox-net`).

2. **Egress Firewall Rules (`iptables` / `nftables` / eBPF)**:
   Host-level packet filtering rules enforce a strict default-DENY policy:

   ```bash
   # Block Cloud Metadata Services (AWS IMDSv1/v2, GCP metadata)
   iptables -A FORWARD -d 169.254.169.254/32 -j DROP
   iptables -A FORWARD -d 169.254.0.0/16 -j DROP

   # Allow outbound HTTPS only to GitHub and OSV endpoints
   iptables -A FORWARD -p tcp --dport 443 -d github.com -j ACCEPT
   iptables -A FORWARD -p tcp --dport 443 -d api.github.com -j ACCEPT
   iptables -A FORWARD -p tcp --dport 443 -d api.osv.dev -j ACCEPT

   # Default DENY all other outbound traffic
   iptables -A FORWARD -j DROP
   ```

3. **Explicit Proxy & SNI Filtering**:
   Outbound HTTPS traffic passes through an egress proxy that inspects TLS Server Name Indication (SNI) headers, blocking IP-based bypasses or unauthorized domains.

---

## 5. Ephemeral Destruction & Cleanup Lifecycle

NANTIS guarantees complete destruction of the execution environment after every job execution, regardless of success, error, or timeout.

```
Job Triggered -> Token Minted -> Sandboxed Clone -> Scan Execution -> Mandatory Cleanup
                                                                           |
                                 +-----------------------------------------+
                                 |
                                 v  [finally Block]
                   +-----------------------------------+
                   | 1. Container Killed (`docker rm`) |
                   | 2. Processes Killed (`SIGKILL`)   |
                   | 3. Workspace Purged (`rm -rf`)    |
                   | 4. Token Memory Wiped             |
                   | 5. Janitor Scans Stale Folders    |
                   +-----------------------------------+
```

### 5.1 Post-Job Destruction Steps

1. **Process Tree Termination**:
   A `SIGTERM` signal is issued, followed immediately by `SIGKILL` across the entire container PID namespace to terminate all spawned child processes.

2. **Container Removal**:
   The container is forcefully removed (`docker rm -f` / OCI delete).

3. **Ephemeral Disk Purge**:
   The temporary workspace directory (`temp/scans/<scanId>`) and `tmpfs` mounts are forcefully unmounted and deleted (`fs.rmSync(jobTempDir, { recursive: true, force: true })`).

4. **Memory Purge**:
   Short-lived installation tokens are discarded from memory. Zero credential state is saved to disk or persistent databases.

5. **Automated Janitor Process**:
   A background janitor (`cleanStaleWorkspaces`) periodically scans `temp/scans/` and purges any abandoned or orphaned workspace folders older than 10 minutes.

---

## 6. Threat Matrix & Security Controls

| Threat ID     | Threat Vector                                 | Risk / Impact                                          | Mitigation Control                                                                                                                                | Enforcement Tier     |
| ------------- | --------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| **THREAT-01** | **Container Escape / Kernel Exploit**         | Host takeover via zero-day kernel flaw                 | Unprivileged execution (`USER nantis`), `--cap-drop=ALL`, read-only root, and optional `gVisor`/`Firecracker` microVM boundary                    | OS / Kernel Layer    |
| **THREAT-02** | **Exfiltration of Installation Token**        | Unauthorized GitHub API access                         | Short-lived installation tokens kept in memory only; egress locked to `api.github.com` domain; token ID reference logged (never raw token string) | Auth & Network Layer |
| **THREAT-03** | **Cloud Metadata Access (`169.254.169.254`)** | IAM role credential theft from AWS IMDS / GCP metadata | Host firewall `iptables` DROP rules for `169.254.0.0/16` and link-local IP ranges                                                                 | Network Layer        |
| **THREAT-04** | **Crypto-Mining / Resource Hijacking**        | High CPU utilization and host denial-of-service        | Cgroup CPU quota cap (`--cpus=2.0`) & hard 60-second wall-clock execution limit                                                                   | Container Runtime    |
| **THREAT-05** | **Disk Exhaustion (Storage DoS)**             | Host disk space exhaustion via huge files              | Bounded `tmpfs` quota (500MB), max repository size cap (50MB), and mandatory `finally` directory removal                                          | Workspace / OS       |
| **THREAT-06** | **Fork Bombs / Process Exhaustion**           | Process table exhaustion halting host OS               | Cgroup process cap (`--pids-limit=100`) preventing unlimited process creation                                                                     | Container Runtime    |
| **THREAT-07** | **Malicious Build Scripts (`postinstall`)**   | Execution of malware during dependency install         | Disabling git hooks (`core.hooksPath=""`), skipping `npm run build` during scan phase, and running with `--ignore-scripts`                        | Core Scanner Engine  |
| **THREAT-08** | **DNS Tunneling / Data Exfiltration**         | Secret exfiltration via malicious DNS requests         | Outbound UDP port 53 locked to internal DNS resolver; egress proxy SNI domain filtering                                                           | Network Layer        |
| **THREAT-09** | **Cross-Job State Pollution**                 | One tenant accessing files from a prior scan           | Dedicated container instance and temporary folder per job; zero shared disk volumes                                                               | Execution Lifecycle  |
| **THREAT-10** | **Environment Secret Leakage**                | Leaking host environment variables to container        | Environment validator (`apps/web/src/lib/env.ts`); zero host secrets passed into worker container environment                                     | Application Layer    |

---

## 7. Verification & Compliance Checklist

- [x] All untrusted code runs inside unprivileged, ephemeral containers.
- [x] Root filesystem is mounted read-only with dropped Linux capabilities.
- [x] Egress network traffic is restricted at the network/iptables layer to GitHub and OSV endpoints only.
- [x] Cloud metadata IP ranges (`169.254.169.254`) are explicitly dropped.
- [x] Ephemeral disk and container resources are completely destroyed in `finally` blocks.
- [x] Audit log rows record token reference IDs only (raw tokens never logged or persisted).
- [x] Mandatory wording requirement: zero findings display `"no issues found in the checks we run"`. Never use `"secure"`, `"safe"`, or `"production ready"`.
