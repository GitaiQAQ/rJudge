FROM rust:cn

WORKDIR /root
ADD . /root
RUN cd /root && cargo build