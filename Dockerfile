FROM rust:latest

RUN apt-get update && \
    apt-get install -y clang llvm pkg-config nettle-dev

COPY . /workspace

WORKDIR /workspace

VOLUME [ "/workspace/bin" ]

RUN echo cargo build --release --features="nettle" >> execute.sh && \
    echo ls /workspace/target/release >> execute.sh && \
    echo cp /workspace/target/release/openmprdbc-cli /workspace/bin/ >> execute.sh

CMD [ "bash", "execute.sh"]

