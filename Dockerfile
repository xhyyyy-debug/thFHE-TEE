ARG BASE_IMAGE=dkg-base:latest
FROM ${BASE_IMAGE}

WORKDIR /app
COPY . /app

RUN rm -rf /app/build

# Generate an enclave signing key for local experimentation if one is not present.
RUN if [ ! -f /app/enclave/private.pem ]; then \
      openssl genrsa -out /app/enclave/private.pem -3 3072; \
    fi

# Configure and build the project against the system gRPC/Protobuf packages.
RUN cmake -S /app -B /app/build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_PREFIX_PATH="/opt/openenclave/lib/openenclave/cmake;/usr;/usr/lib/x86_64-linux-gnu/cmake;/usr/lib/x86_64-linux-gnu/cmake/grpc;/usr/lib/x86_64-linux-gnu/cmake/protobuf" \
      -DOpenEnclave_DIR="/opt/openenclave/lib/openenclave/cmake" && \
    cmake --build /app/build -j"$(nproc)"

ENV LD_LIBRARY_PATH="/opt/openenclave/lib:${LD_LIBRARY_PATH}"

ENTRYPOINT ["/bin/bash", "-lc"]
