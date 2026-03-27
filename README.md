# TEE + MPC Threshold Key Generation Demo

This repository implements a two-stage threshold key generation workflow over 4 online party containers:

1. `preprocessing`: TEE-assisted generation of shared `bits`, `noises`, and `triples`
2. `keygen`: online host-side distributed key generation over gRPC, using the saved preprocessing material

The intended execution model is:
- the 4 party containers stay online
- the controller sends one preprocessing command
- the controller then sends one keygen command
- during keygen, the parties perform online `open` and `mul` style interaction over gRPC

**Project Layout**
- `docker-compose.yml`: Docker services for `party1`..`party4` and the controller/tool container
- `noise.docker.conf`: runtime config used inside Docker
- `noise.conf`: local non-Docker config
- `host/apps/noise_preproc_plan_main.cpp`: preprocessing planner entry
- `host/apps/noise_preproc_main.cpp`: preprocessing runner entry
- `host/apps/noise_keygen_main.cpp`: online keygen controller entry
- `host/apps/noise_party_main.cpp`: party service, preprocessing, and online keygen execution
- `host/config/config.cpp`: all supported config keys
- `host/dkg/params.cpp`: built-in DKG presets such as `bc_params_sns`

**Before You Start**
- Make sure SGX/Open Enclave is available on the host
- Make sure the Open Enclave base image required by `Dockerfile.base` is available under `thirdparty`
- The compose file maps:
  - `/dev/sgx_enclave`
  - `/dev/sgx_provision`
- `docker-compose.yml` also mounts `./artifacts:/artifacts` so the party containers and controller can share preprocessing/keygen files

If you want simulation mode, run commands with `OE_SIMULATION=1`.

**Build Docker Images**
```bash
docker compose --profile base build base
docker compose build
```

**Start The Party Containers**
```bash
docker compose up -d party1 party2 party3 party4
```

This starts four host+enclave party services on the internal Docker network `noise-net`.

**Check The Preprocessing Plan**
Before running preprocessing, it is useful to inspect how many bits / triples / noises are needed for the current config:

```bash
docker compose run --rm \
  --entrypoint /app/build/host/apps/noise_preproc_plan \
  controller \
  /app/noise.docker.conf
```

**Run One Full Online Key Generation**
Use a host directory to keep artifacts:

```bash
mkdir -p artifacts
```

Pick:
- a preprocessing session id, for example `1001`
- a keygen round id, for example `2001`

Run preprocessing:

```bash
docker compose run --rm \
  --entrypoint /app/build/host/apps/noise_preproc \
  controller \
  1001 /app/noise.docker.conf /artifacts/preproc
```

This creates a session directory similar to:

```text
artifacts/
  preproc/
    1001/
      party_1/
        meta.txt
        preprocessing.bin
      party_2/
        meta.txt
        preprocessing.bin
      party_3/
        meta.txt
        preprocessing.bin
      party_4/
        meta.txt
        preprocessing.bin
```

Then start one online keygen round:

```bash
docker compose run --rm \
  --entrypoint /app/build/host/apps/noise_keygen \
  controller \
  2001 1001 /app/noise.docker.conf /artifacts/preproc /artifacts/keygen
```

This is one distributed keygen session across all 4 parties. You do not need to invoke `noise_keygen` once per party anymore.

When the round succeeds, each party writes its own summary file under:

```text
artifacts/
  keygen/
    party_1.secret.key
    party_1.public.key
    keygen_party_1.txt
    party_2.secret.key
    party_2.public.key
    keygen_party_2.txt
    party_3.secret.key
    party_3.public.key
    keygen_party_3.txt
    party_4.secret.key
    party_4.public.key
    keygen_party_4.txt
```

When finished:

```bash
docker compose down
```

**What To Edit**

**1. Party Network / Threshold Basics**
Edit `noise.docker.conf`:

```ini
party_count = 4
threshold = 1
noise_degree = 4
noise_bound_bits = 37

party = party1, 1, party1, 7005
party = party2, 2, party2, 7006
party = party3, 3, party3, 7007
party = party4, 4, party4, 7008
```

These fields control:
- `party_count`: number of MPC parties
- `threshold`: corruption threshold `t`
- `noise_degree`: maximum per-round batch size used by the noise service
- `noise_bound_bits`: target final bound for generic noise rounds
- `party = ...`: name / id / host / port for each party

`noise_bound_bits` is interpreted as the target bound of the final reconstructed shared noise.
If `noise_bound_bits = b`, the protocol targets a final TUniform-style range around `[-2^b, 2^b]`.
Because every party contributes a local noise share, each enclave automatically scales down its local sampling range by the party count before aggregation.

**2. DKG Parameter Preset**
Also in `noise.docker.conf`, add or modify:

```ini
dkg_preset = bc_params_sns
dkg_keyset_mode = standard
```

Currently the code supports presets defined in `host/dkg/params.cpp`, including:
- `params_test_bk_sns`
- `bc_params_sns`

If you want to change the built-in preset values themselves, edit:
- `host/dkg/params.cpp`

**3. Fine-Grained DKG Parameters**
If you do not want to rely only on a preset, the config parser also supports explicit overrides in `noise.docker.conf`. Common fields include:

```ini
dkg_lwe_dimension = ...
dkg_lwe_hat_dimension = ...
dkg_glwe_dimension = ...
dkg_polynomial_size = ...

dkg_lwe_noise_bound_bits = ...
dkg_lwe_hat_noise_bound_bits = ...
dkg_glwe_noise_bound_bits = ...

dkg_ks_base_log = ...
dkg_ks_level = ...
dkg_pksk_base_log = ...
dkg_pksk_level = ...
dkg_bk_base_log = ...
dkg_bk_level = ...

dkg_message_modulus = ...
dkg_carry_modulus = ...
dkg_log2_p_fail = ...
dkg_encryption_key_choice = big
```

Compression and SnS-related keys are also supported in the same file. The full list is implemented in:
- `host/config/config.cpp`

**4. Docker Service Settings**
Edit `docker-compose.yml` if you want to change:
- published ports
- SGX device mapping
- artifact mount
- default controller command
- container names

**Typical Docker Workflow**
```bash
docker compose --profile base build base
docker compose build
docker compose up -d party1 party2 party3 party4
docker compose run --rm --entrypoint /app/build/host/apps/noise_preproc_plan controller /app/noise.docker.conf
docker compose run --rm --entrypoint /app/build/host/apps/noise_preproc controller 1001 /app/noise.docker.conf /artifacts/preproc
docker compose run --rm --entrypoint /app/build/host/apps/noise_keygen controller 2001 1001 /app/noise.docker.conf /artifacts/preproc /artifacts/keygen
docker compose down
```

**Current Protocol Notes**
- `noise_preproc` supports multiple runtime noise bounds in one preprocessing session; it launches separate noise rounds as required by the DKG plan.
- preprocessing artifacts are now written per party under `artifacts/preproc/<session_id>/party_<id>/`
- preprocessing material is serialized into `preprocessing.bin`
- each saved local `noise`, `bit`, and `triple` record carries a TEE-generated signature tag
- preprocessing planning now follows the current project design:
  - `total_bits = raw_secret_bits`
  - TUniform noise generation does not consume preprocessing bits
  - triple counts are derived from the actual online multiplication call sites in keygen
- `noise_keygen` is now an online controller command: it sends one `StartKeygen` request to each party and waits until all parties reach `KEYGEN_DONE`.
- During the current online keygen flow, the parties perform online `open` for MPC multiplication through gRPC.
- before using local preprocessing records in keygen, each party sends them back into its enclave for signature verification
- each party now writes two serialized key files:
  - `party_<id>.secret.key`
  - `party_<id>.public.key`
  plus the text summary
- `noise_ctl` is still useful for standalone noise / triple / bit debugging, but the recommended threshold-keygen path is `noise_preproc` followed by `noise_keygen`.

**Current Implementation Caveats**
- The preprocessing store still keeps the collected preprocessing session in a shared artifact directory. This is convenient for bring-up, but it is not yet the final per-party storage layout you would want in a hardened deployment.
- The online keygen path is now distributed and interactive, but the ciphertext/data structures are still the project's current C++ shared representations rather than a fully kms/tfhe-rs-compatible serialization format.
- The current `party_<id>.public.key` file is the public-material bundle produced by that party in this implementation. It is not yet a single globally merged/export-ready public key file in the kms sense.
