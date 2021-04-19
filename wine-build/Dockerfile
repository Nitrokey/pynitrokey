FROM i386/alpine:latest

# Install prerequisites
RUN apk add libnitrokey git wget build-base \
				mingw-w64-binutils mingw-w64-gcc \
				make autoconf automake ncurses freetype libtool \
				gcc g++ wine gnutls rust


RUN mkdir /build

COPY build-wine-docker.sh /build/build-wine-docker.sh
COPY entrypoint.sh /build/entrypoint.sh

ENTRYPOINT ["/build/entrypoint.sh"]


