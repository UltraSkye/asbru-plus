FROM fedora:40

RUN dnf install -y \
    rpm-build \
    rpmdevtools \
    pkgconfig \
    bash-completion \
    desktop-file-utils \
    perl \
    && dnf clean all

WORKDIR /build/src
COPY . .

COPY docker/build-rpm/test.sh /test.sh
RUN chmod +x /test.sh

CMD ["/test.sh"]
