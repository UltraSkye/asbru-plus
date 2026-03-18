FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# Build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    debhelper \
    dpkg-dev \
    fakeroot \
    lintian \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Runtime deps (needed to install and test the built package)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libvte-2.91-0 \
    libcairo-perl \
    libglib-perl \
    libpango-perl \
    libsocket6-perl \
    libexpect-perl \
    libyaml-perl \
    libcrypt-cbc-perl \
    libcrypt-blowfish-perl \
    libgtk3-perl \
    libnet-arp-perl \
    libossp-uuid-perl \
    openssh-client \
    libcrypt-rijndael-perl \
    libxml-parser-perl \
    libcanberra-gtk-module \
    dbus-x11 \
    libgtk3-simplelist-perl \
    gir1.2-wnck-3.0 \
    gir1.2-vte-2.91 \
    ncat \
    && rm -rf /var/lib/apt/lists/*

# Source goes into /build/src so dpkg-buildpackage outputs go to /build/
WORKDIR /build/src
COPY . .

COPY docker/build-deb/test.sh /test.sh
RUN chmod +x /test.sh

CMD ["/test.sh"]
