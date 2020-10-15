FROM i386/alpine:latest

# Install prerequisites
RUN apk add libnitrokey git wget build-base \
				mingw-w64-binutils mingw-w64-gcc \
				make autoconf automake ncurses freetype libtool \
				gcc g++ wine 


RUN mkdir /build

#COPY pulse-client.conf /root/pulse/client.conf
COPY Makefile /build/Makefile
COPY entrypoint.sh /build/entrypoint.sh
COPY nitropy.spec /build/nitropy.spec

ENTRYPOINT ["/build/entrypoint.sh"]


