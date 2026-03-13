FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# 基础工具
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    gnupg \
    ca-certificates \
    software-properties-common \
    build-essential \
    git \
    pkg-config \
    python3 \
    python3-pip \
    ninja-build \
    openssl \
    libssl-dev \
    gdb

# 配置 Intel SGX 和 Microsoft 源
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' \
    > /etc/apt/sources.list.d/intel-sgx.list && \
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -

RUN echo 'deb [arch=amd64] https://packages.microsoft.com/ubuntu/22.04/prod jammy main' \
    > /etc/apt/sources.list.d/msprod.list && \
    wget -qO - https://packages.microsoft.com/keys/microsoft.asc | apt-key add -

RUN apt-get update

# Open Enclave / SGX 依赖
RUN apt-get install -y \
    llvm-11 \
    libsgx-enclave-common \
    libsgx-quote-ex \
    libprotobuf23 \
    libsgx-dcap-ql \
    libsgx-dcap-ql-dev \
    az-dcap-client

# 新版 cmake
RUN pip3 install cmake

# 安装 Open Enclave SDK
RUN wget https://github.com/openenclave/openenclave/releases/download/v0.19.13/Ubuntu_2204_open-enclave_0.19.13_amd64.deb && \
    dpkg -i Ubuntu_2204_open-enclave_0.19.13_amd64.deb || true && \
    apt-get update && \
    apt-get -f install -y

COPY . /app
RUN rm -rf /app/build

# 仅实验用签名私钥
RUN if [ ! -f /app/enclave/private.pem ]; then \
    openssl genrsa -out /app/enclave/private.pem -3 3072; \
    fi

# 确认 Open Enclave 配置文件位置
RUN find / -name "openenclave-config.cmake" 2>/dev/null || true

# 告诉 CMake 去哪里找 Open Enclave
ENV OpenEnclave_DIR=/opt/openenclave/lib/openenclave/cmake
ENV CMAKE_PREFIX_PATH=/opt/openenclave/lib/openenclave/cmake

RUN cmake -S /app -B /app/build -G Ninja

RUN cmake --build /app/build -j$(nproc)

ENTRYPOINT ["/bin/bash", "-lc"]