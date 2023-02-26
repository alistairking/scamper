VERSION 0.6
FROM debian:stable-slim
WORKDIR /scamper

all:
        BUILD +build

deps:
        RUN apt-get update && \
            apt-get install -y \
                    build-essential \
                    autoconf \
                    libtool

# TODO: figure out how to get this to cache properly
build:
        FROM +deps
        COPY --dir --keep-ts \
             *.[ch] lib scamper utils configure.ac Makefile.am m4 \
             ./
        RUN autoreconf -vfi
        RUN ./configure
        RUN make
        ARG TARGETPLATFORM
        SAVE ARTIFACT scamper/scamper ${TARGETPLATFORM}/scamper \
             AS LOCAL ./build/${TARGETPLATFORM}/scamper

# TODO: fix
dist:
        FROM +build
        RUN rm -f scamper-cvs-*.tar.gz
        RUN make dist
        SAVE ARTIFACT scamper-cvs-*.tar.gz \
             AS LOCAL ./dist/

build-multiarch:
        BUILD \
              --platform=linux/arm/v7 \
              --platform=linux/arm/v6 \
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +build

docker:
        ARG TARGETPLATFORM
        COPY +build/${TARGETPLATFORM}/scamper /usr/local/bin/scamper
        ENTRYPOINT ["/usr/local/bin/scamper"]
        ARG EARTHLY_TARGET_TAG_DOCKER
        ARG EARTHLY_GIT_SHORT_HASH
        ARG org="alistairking"
        ARG img="${org}/scamper"
        IF [ "${EARTHLY_TARGET_TAG_DOCKER}" = "master" ]
           ARG latest="${img}:latest"
        END
        SAVE IMAGE --push \
             ${img}:${EARTHLY_TARGET_TAG_DOCKER} \
             ${img}:${EARTHLY_GIT_SHORT_HASH} \
             ${latest}

docker-multiarch:
        BUILD \
              --platform=linux/arm/v7 \
              --platform=linux/arm/v6 \
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +docker

# Earthly has a bug so can't RUN without /bin/sh
# https://github.com/earthly/earthly/issues/1097
pkg-fix:
        FROM kentik/pkg:latest
        SAVE ARTIFACT /pkg kentik-pkg

pkg:
        COPY +pkg-fix/kentik-pkg /usr/bin/pkg
        ARG EARTHLY_TARGET_TAG
        ARG TARGETPLATFORM
        ARG TARGETARCH
        ARG TARGETVARIANT
        ARG type=deb
        ARG version="${EARTHLY_TARGET_TAG}"
        ARG pkg_arch="${TARGETARCH}${TARGETVARIANT}"
        COPY +build/${TARGETPLATFORM}/scamper ./
        COPY package.yml ./
        RUN rm -f *.${type}
        RUN /usr/bin/pkg \
            --name scamper \
            --version ${version} \
            --arch ${pkg_arch} \
            --${type} \
            package.yml
        SAVE ARTIFACT scamper*.${type} \
             AS LOCAL ./pkg/

pkg-deb-rpm:
        BUILD +pkg --type=deb
        BUILD +pkg --type=rpm

pkg-multiarch:
        BUILD \
              --platform=linux/arm/v7 \
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +pkg-deb-rpm

docs-deps:
        RUN apt-get update && \
            apt-get install -y \
                    perl groff ghostscript

docs:
        FROM +docs-deps
        COPY . .
        RUN ./build-man-pdfs.pl
        SAVE ARTIFACT man/*.pdf AS LOCAL docs/

# To support native macos (etc.) builds
# TODO: this feels clunky and repetetive. Is there no better way?
bootstrap-native:
        LOCALLY
        RUN autoreconf -vfi
        RUN ./configure

build-native:
        LOCALLY
        # BUILD +bootstrap-native # LOCALLY doesn't cache, so do this yourself
        RUN make
        ARG native_platform=native
        RUN mkdir -p ./build/${native_platform}
        RUN cp scamper/scamper ./build/${native_platform}/scamper
