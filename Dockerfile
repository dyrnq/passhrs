# Build stage
FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Build application
COPY src/ src/
RUN cargo build --release

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata openssh-client

COPY --from=builder /app/target/release/passhrs /usr/local/bin/passhrs

ENTRYPOINT ["/usr/local/bin/passhrs"]
CMD ["--help"]
