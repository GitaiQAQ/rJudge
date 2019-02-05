FROM rust:cn
MAINTAINER Gitai<i@gitai.me>

WORKDIR /root
ADD . /root

ENV RUSTFLAGS="-A dead_code"

ENTRYPOINT ["cargo", "build", "-v"]