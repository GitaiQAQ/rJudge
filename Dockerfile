FROM rust:cn

ADD railcar /root/railcar
RUN cd /root/railcar && cargo build