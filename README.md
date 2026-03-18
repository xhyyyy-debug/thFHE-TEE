# TEE + MPC Noise Demo

This repo builds a simple multi-party noise generation protocol running inside Open Enclave (SGX). The recommended way to run multi-party tests is via Docker Compose.

## Docker Quick Start

### 1) Build the images

```bash
docker compose build
```

### 2) Start 4 parties (one container per party)

```bash
docker compose up
```

This starts `party1`..`party4` on a dedicated `bridge` network (`noise-net`). Each party runs its own enclave.

### 3) Run the controller (batch runner)

Use the `tools` profile to run the controller container.

```bash
docker compose --profile tools up controller
```

The controller command is configured in `docker-compose.yml` and uses `noise.docker.conf`.

### 4) Stop everything

```bash
docker compose down
```

## Config Files

- `noise.conf`: local (non-Docker) config using `127.0.0.1`
- `noise.docker.conf`: Docker config using service names (`party1`..`party4`) and internal port `7000`

### Noise Parameters

Add TFHE noise parameters in the config file:

```
noise_degree = 1024
noise_bound_bits = 8
```

`noise_degree` maps to the batch size and should match the ring degree (number of coefficients in one ring element).
`noise_bound_bits` controls the TUniform noise bound `2^b`.

## Notes

- This Docker setup uses `bridge` networking. Each container gets its own IP automatically.
- SGX devices are mapped in `docker-compose.yml`:
  - `/dev/sgx_enclave`
  - `/dev/sgx_provision`
- If you want to run in simulation mode, set:

```bash
OE_SIMULATION=1 docker compose up
```

## Typical Workflow

1. `docker compose build`
2. `docker compose up`
3. `docker compose run --rm controller 1 1000000 /app/noise.docker.conf`
4. `docker compose down`

## Large Experiments (Batched)

Run a large experiment by splitting it into batches:

```bash
docker compose run --rm controller 1 26469202 100000 /app/noise.docker.conf
```

Disable full verification for speed/bandwidth:

```bash
NOISE_VERIFY=0 docker compose run --rm controller 1 26469202 100000 /app/noise.docker.conf
```
