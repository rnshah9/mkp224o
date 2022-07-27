FROM alpine:3.12.0 as builder

#Installing all the dependencies
RUN apk add --no-cache gcc libsodium-dev make autoconf build-base

WORKDIR /mkp224o

COPY . /mkp224o/

RUN ./autogen.sh \
  && ./configure \
  && make \
  && cp /mkp224o/mkp224o /usr/local/bin/

FROM alpine:3.12.0 as package
RUN apk add --no-cache libsodium-dev
COPY --from=builder /mkp224o/mkp224o /
