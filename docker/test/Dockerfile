FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    perl \
    libgtk3-perl \
    libvte-2.91-0 \
    libcairo-perl \
    libglib-perl \
    libpango-perl \
    libsocket6-perl \
    libexpect-perl \
    libyaml-perl \
    libcrypt-cbc-perl \
    libcrypt-blowfish-perl \
    libnet-arp-perl \
    libuuid-tiny-perl \
    libcrypt-rijndael-perl \
    libxml-parser-perl \
    libgtk3-simplelist-perl \
    shellcheck \
    xvfb \
    gir1.2-glib-2.0 \
    libglib-object-introspection-perl \
    gir1.2-vte-2.91 \
    gir1.2-wnck-3.0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . .

COPY docker/test/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
