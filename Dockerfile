ARG BASE_IMAGE=noise-base:latest
FROM ${BASE_IMAGE}

WORKDIR /app
COPY . /app

RUN rm -rf /app/build

# 仅实验用签名私钥
RUN if [ ! -f /app/enclave/private.pem ]; then \
      openssl genrsa -out /app/enclave/private.pem -3 3072; \
    fi

# 配置并构建
RUN cmake -S /app -B /app/build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_PREFIX_PATH="/opt/grpc;/opt/openenclave/lib/openenclave/cmake" \
      -DOpenEnclave_DIR="/opt/openenclave/lib/openenclave/cmake" \
      -DgRPC_DIR="/opt/grpc/lib/cmake/grpc" \
      -DProtobuf_DIR="/opt/grpc/lib/cmake/protobuf" && \
    cmake --build /app/build -j"$(nproc)"

ENV LD_LIBRARY_PATH="/opt/grpc/lib:/opt/grpc/lib64:/opt/openenclave/lib:${LD_LIBRARY_PATH}"

ENTRYPOINT ["/bin/bash", "-lc"]