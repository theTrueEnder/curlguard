# Administrator deployment and threat model (design only)

curlguard remains voluntary user-space protection in both editions. Its policy,
environment, executable path and local audit files are controlled by the invoking
user. Installing a PATH wrapper, even as root, does not establish mandatory
organizational protection. This design does not deploy privileged enforcement.

## Assets, actors and trust boundaries

Protect build inputs before publication, the administrator's policy and trust
material, and acknowledged audit records. Assume an ordinary user may be hostile
and can choose executables, environment, writable configuration, containers and
user namespaces. Assume a compromised publisher or HTTP endpoint can supply
arbitrary bytes. No-match malware detection is not a safety guarantee. A valid
publisher identity proves signing authority at signing time, not benign content.
Host administrator/kernel compromise is outside the proposed boundary.

| Bypass | Current behavior | Proposed independent control |
|---|---|---|
| Absolute `/usr/bin/curl`, copied curl | Skips wrapper | Deny workload direct egress at the host/hypervisor boundary |
| Python, wget, language package clients | Skips wrapper | Same egress boundary, regardless of process name |
| User-writable policy or `CURLGUARD_*` | Changes local decisions | A broker reads only administrator-owned policy and ignores client settings |
| Container with separate PATH/config | Skips host wrapper | Apply network policy before workloads receive network connectivity |
| Nested user/network namespaces | Can escape PATH assumptions | Host-owned network controls; never grant host netns, host capabilities or unrestricted proxy access |
| Writable/downloaded executable | Can perform its own HTTP | Deny general egress, require exact artifact requests through broker |
| Deleted/forged local JSONL | Evidence lost or forged | Independent authenticated collector with acknowledgement and durable queue |
| Approved bootstrap fetching more bytes | Downloads outside wrapper | Independently declare and verify each secondary artifact; no transitive approval |

## Proposed broker deployment

Run a dedicated administrator-owned service outside workload namespaces. Pin its
runtime/verifier and store policy, exact issuer/identity constraints, roots and
signed rule keys in administrator-owned paths inaccessible for workload writes.
Use a narrow authenticated IPC API accepting artifact IDs, never arbitrary shell
commands, arbitrary output paths, user-selected roots or environment overrides.
Resolve IDs to administrator-approved URLs/hashes and permitted final origins.
Stage, verify, scan and publish through a broker-owned content-addressed store;
workloads receive read-only access to accepted bytes. Do not execute artifacts.

An egress proxy that merely tunnels arbitrary HTTPS is insufficient. Workloads
must be denied general outbound connectivity, including direct IP, IPv6, alternate
DNS, inherited sockets, container bridges and host networking. Permit only the
broker interface; the broker alone reaches approved origins. Administrator
runtime/network integration must deny privilege escalation, host namespace joins,
privileged containers and device or socket access that can reconfigure this policy.
Unmanaged personal hosts cannot claim this enforcement without such controls.

## Audit and failure semantics

Send versioned evidence, artifact hash, policy/ruleset/trust generations, authenticated
requestor, decision and monotonic sequence to an independent collector over mTLS.
Give requests unique IDs and make acknowledgement idempotent. In enforced mode,
publish only after durable collector acknowledgement; collector failure blocks or
queues unaccepted artifacts in private storage. Bound queue capacity and fail
closed when full. Distinguish staged, verified, acknowledged and published events;
publication failure needs a follow-up event. Collector retention and tenant access
are administrator policy. Current local JSONL is **best-effort evidence** and has
no collector acknowledgement; it cannot satisfy this requirement.

## Isolated boundary evidence and rollout gates

`python examples/enforcement-boundaries.py` starts an inert loopback server. Absolute
curl and Python urllib succeed despite restrictive wrapper variables; the same
clients fail in an isolated user/network namespace. This demonstrates one kernel
boundary independent of PATH/environment without changing host networking.
The script fails explicitly when namespace creation is unavailable. It was run
successfully in WSL during this implementation. Namespace isolation demonstrates
network denial only; it does not implement a production broker or collector.

Before organization-wide claims, a separate isolated deployment must demonstrate:

1. Workloads cannot reach external endpoints by direct IP, IPv6, DNS, proxy,
   absolute curl, Python, nested namespaces, rootless containers or inherited sockets.
2. Workloads cannot write broker policy/trust/runtime, join host namespaces or
   use container/daemon sockets to change enforcement.
3. Exact bytes, identities and origins are enforced and content findings remain
   independent; bad evidence blocks publication.
4. Collector loss/replay/full queues, broker crashes and trust rotation preserve
   acknowledgement and publication ordering.
5. Allowlisted access succeeds while denied access fails from each supported
   container/runtime topology, with independent observations at the boundary.

These are rollout gates, not claims about this repository's wrapper. Selection of
a host policy engine, deployment privileges, collector service and execution or
sandbox features requires a separate review and deployment authorization.
