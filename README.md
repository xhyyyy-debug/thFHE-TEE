# Multi-Party SGX Noise Generation

This repository now runs the noise-generation protocol as a real multi-party system:

- `noise_party`: one process per MPC party, normally one container per party.
- `noise_ctl`: external trigger and verifier.
- each party owns one SGX/Open Enclave enclave instance.
- parties exchange `SHARE` and `ACK` messages over TCP.
- the controller triggers a round, polls progress, reconstructs the final noise, and checks whether it matches the sum of local sampled secrets.

## Runtime config

All party metadata is now loaded from a shared config file, by default [noise.conf](/c:/Users/xuhen/Desktop/科研/TEE+MPC/SGX/noise.conf).

Format:

```txt
party_count = 4
threshold = 1
party = party1, 1, party1, 7000
party = party2, 2, party2, 7000
party = party3, 3, party3, 7000
party = party4, 4, party4, 7000
```

Each `party` line means:

- party logical name
- party id
- host or container DNS name
- listen port

## Architecture

### Enclave side

- `sharegen(round_id)` samples `e_i`, uses Shamir secret sharing, and returns one share package per party.
- `sharegen_batch(...)` lets the enclave generate up to `32` noise values in one ECALL.
- `store_batch(...)` stores one whole chunk of incoming shares in one ECALL.
- `store(share)` verifies the attached tag and stores the incoming share `[e_j]_i`.
- `done_batch(...)` aggregates one whole chunk of noises in one ECALL.
- `done()` sums all stored shares into the aggregate share `[e]_i`.

### Host side

- each `noise_party` process starts one enclave and one TCP listener.
- after receiving `START <round_id> <batch_size>`, the party asks the enclave to generate noise in chunks of at most `32`.
- for each chunk, the party sends one `BATCH_SHARE` message per receiver instead of one `SHARE` per noise.
- `START` now carries `batch_size`, so one external trigger can generate many noise samples in sequence.
- upon receiving a `BATCH_SHARE`, the target party calls `store_batch`, logs success, and replies with one `BATCH_ACK`.
- once a party has stored a whole chunk from all parties, it calls `done_batch()` and reports the aggregate shares via the status API.
- `noise_ctl` polls every party with `STATUS`, waits until all parties reach `DONE`, reconstructs the global noise from `t + 1` aggregate shares, and verifies the result.

## Algebra layer

The enclave protocol code now depends on the reusable algebra code in `algebra/`:

- `algebra/common.hpp`: shared numeric type.
- `algebra/fields.hpp`: compile-time and runtime prime field arithmetic.
- `algebra/polynomial.hpp`: polynomial evaluation over a runtime field.
- `algebra/shamir.hpp`: runtime-capable Shamir secret sharing and reconstruction.
- `algebra/rings.hpp`: ring arithmetic for later RLWE-style extensions.

`enclave/prog_mpc.h` uses `RuntimePrimeField` and `ShamirSecretSharing` directly.

## Build outside Docker

Prerequisites:

- Open Enclave SDK available to CMake.
- SGX/DCAP runtime on the machine.
- `openssl`, `cmake`, a C++17 compiler.

Generate the signing key if it does not exist yet:

```bash
openssl genrsa -out enclave/private.pem 3072
```

Build:

```bash
cmake -S . -B build
cmake --build build -j
```

Run four parties manually in separate terminals:

```bash
./build/host/noise_party ./build/enclave/noise_enclave.signed ./noise.local.conf party1
./build/host/noise_party ./build/enclave/noise_enclave.signed ./noise.local.conf party2
./build/host/noise_party ./build/enclave/noise_enclave.signed ./noise.local.conf party3
./build/host/noise_party ./build/enclave/noise_enclave.signed ./noise.local.conf party4
```

For local host testing, `noise.local.conf` should usually look like:

```txt
party_count = 4
threshold = 1
party = party1, 1, 127.0.0.1, 7001
party = party2, 2, 127.0.0.1, 7002
party = party3, 3, 127.0.0.1, 7003
party = party4, 4, 127.0.0.1, 7004
```

Then trigger one round:

```bash
./build/host/noise_ctl 1 32 ./noise.local.conf
```

Here `32` is `batch_size`, meaning one trigger asks every party to generate and verify 32 noise values.
If `batch_size > 32`, the host automatically splits it into multiple enclave batch calls, each of size at most `32`.

## Docker workflow

### 1. Prepare an Open Enclave base image

The provided `Dockerfile` expects a base image named `openenclave-dev` that already contains:

- Open Enclave SDK
- SGX/DCAP runtime libraries
- `cmake`
- a C++ toolchain
- `openssl`

If your local base image has a different name, build with:

```bash
docker build --build-arg OE_BASE_IMAGE=<your_oe_base_image> -t noise-party .
```

### 2. Start all parties

```bash
docker compose up -d party1 party2 party3 party4
```

Check logs:

```bash
docker compose logs -f party1 party2 party3 party4
```

Each party prints its protocol steps, including:

- round start
- sampled local secret
- each sent share
- each stored share
- each received ack
- aggregate share generation

### 3. Trigger a round from outside

Run the controller service on demand:

```bash
docker compose run --rm controller
```

The default controller command inside `docker-compose.yml` uses `batch_size = 1`. Change it there if you want a larger batch by default.

The controller prints:

- which parties accepted the `START`
- current status for each party
- reconstructed global noise
- expected sum of local secrets
- `SUCCESS` or `FAILED`

## How to scale beyond 4 parties

You need to update:

1. `docker-compose.yml`
2. the `party_count` and `threshold` values in the config file
3. the `party = ...` lines in the config file

All parties must use the same:

- total party count
- threshold
- config ordering and ids

## Important limitation

`sigma` is still a deterministic demo tag used to exercise the protocol flow and message verification logic. It is not a real enclave signature and is not bound to remote attestation. For a stronger design, replace it with:

- enclave-held signing keys
- attested public-key distribution
- signature verification in `store`

## Main files

- `enclave/prog_mpc.h`: enclave protocol state machine and shared data structures.
- `enclave/ecalls.cpp`: Open Enclave ECALL bridge.
- `host/host.cpp`: per-party runtime with enclave lifecycle, TCP server, logs, and protocol execution.
- `host/controller.cpp`: external trigger and final verification tool.
- `host/control_protocol.hpp`: message formats used by parties and controller.
- `host/network.cpp`: small TCP networking helpers.
- `docker-compose.yml`: multi-container launch file.
- `Dockerfile`: image build recipe for parties and controller.
