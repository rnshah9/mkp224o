FROM ubuntu:22.04 as builder

#Installing all the dependencies
RUN apt update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y gcc libsodium-dev make autoconf build-essential clang

WORKDIR /mkp224o

COPY . /mkp224o/

RUN ./autogen.sh \
  && ./configure \
  && make \
  && cp /mkp224o/mkp224o /usr/local/bin/

RUN clang++ /mkp224o/mayhem/fuzz_base64_valid.cpp -fsanitize=fuzzer,address /mkp224o/base64_from.c.o /mkp224o/base64_to.c.o -o /fuzz

FROM ubuntu:22.04 as package
RUN apt update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libsodium-dev
COPY --from=builder /mkp224o/mkp224o /
COPY --from=builder /fuzz /fuzz_base64_valid
