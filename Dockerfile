FROM rust:1.58.1-slim AS builder
RUN apt-get update && apt-get install -y libpq-dev
RUN cargo init tomiko
WORKDIR /tomiko
COPY Cargo.toml .
RUN cargo build --release
RUN rm Cargo.toml src/*
COPY . .
RUN cargo build --release

FROM rust:1.58.1-slim
RUN apt-get update && apt-get install -y libpq-dev
WORKDIR /tomiko
COPY --from=builder /tomiko/target/release/tomikod .
COPY --from=builder /tomiko/target/release/tomiko-util .
ENTRYPOINT "/tomiko/tomikod"
