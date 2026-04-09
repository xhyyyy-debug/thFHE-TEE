# Architecture Overview

This repository is organized around one clear split:

- `enclave/`: TEE-side protocol logic and authenticated preprocessing generation
- `host/`: orchestration, networking, streaming persistence, and online DKG logic
- `algebra/`: pure ring / sharing / reconstruction utilities with no protocol state

## Layering

### `algebra/`

This directory contains reusable mathematical building blocks:

- `algebra/rings/`: ring element types and ring-specific operations
- `algebra/sharing/`: Shamir sharing, robust open, and host-side Beaver multiplication helpers
- `algebra/polynomial/`: polynomial helper code
- `algebra/base/`: small foundational abstractions and field helpers

Protocol code should depend on `algebra/`, but `algebra/` should not depend on host or enclave workflow code.

### `enclave/`

The enclave owns:

- PRSS / PRZS generation
- authenticated preprocessing generation
- verification of preprocessing records before use
- TEE-local protocol state machines for noise / bits / triples

Important subdirectories:

- `enclave/prss/`: PRSS / PRZS state and PRF implementation
- `enclave/mpc/`: enclave-side batch handlers for bit and triple generation
- `enclave/protocol/`: top-level enclave protocol coordinator (`EnclaveProtocolHandler`)
- `enclave/common/`: host/enclave shared plain data structures

### `host/`

The host side is split into:

- `host/config/`: config parsing and runtime configuration
- `host/transport/`: endpoint/network abstractions
- `host/protocol/`: gRPC-facing request/reply helpers and lightweight text protocol helpers
- `host/dkg/`: DKG planning, encryption helpers, preprocessing storage, and serialization
- `host/apps/`: controller and party executables

## Key DKG Flow

### Preprocessing

1. The controller computes a `DkgPlan`.
2. The controller starts preprocessing rounds on all parties.
3. Each party asks its enclave to generate authenticated local preprocessing material.
4. The controller stores party-local preprocessing artifacts as streamed binary files.

### Key Generation

1. Each party opens its own preprocessing file with a streaming reader.
2. Records are verified by the enclave before use.
3. The host performs online MPC operations (`open`, `mul`) across parties using gRPC.
4. Public key material is streamed directly to disk to avoid retaining the full key in memory.

## Naming Conventions

- `*Params`: immutable parameter groups
- `*Plan`: derived execution plan shared across phases
- `*StreamReader` / `*StreamWriter`: forward-only large artifact IO
- `Shared*Ciphertext`: party-local share of a ciphertext object
- `*Bundle`: artifact intended for serialization

## Open-Source Maintenance Notes

- Prefer adding new protocol logic under `host/dkg/` or `enclave/mpc/` rather than growing app entrypoints.
- Keep host/enclave shared plain structs in `enclave/common/`.
- Avoid introducing new code paths that materialize the full preprocessing output or full public key in memory.
