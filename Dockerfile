ARG OE_BASE_IMAGE=openenclave-dev

FROM ${OE_BASE_IMAGE} AS build

WORKDIR /app
COPY . /app

RUN if [ ! -f /app/enclave/private.pem ]; then openssl genrsa -out /app/enclave/private.pem 3072; fi
RUN cmake -S /app -B /app/build
RUN cmake --build /app/build -j

FROM ${OE_BASE_IMAGE} AS runtime

WORKDIR /app
COPY --from=build /app/build /app/build
COPY --from=build /app/enclave/private.pem /app/enclave/private.pem

ENTRYPOINT ["/bin/bash", "-lc"]
