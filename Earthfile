VERSION 0.6

all:
        BUILD +build

# TODO: scamper still depends on glibc, so we should really build
# release-specific binaries
base-debian:
        FROM debian:bullseye-slim
        WORKDIR /scamper

base-alpine:
        FROM alpine:latest
        WORKDIR /scamper

deps-debian:
        FROM +base-debian
        RUN apt-get update && \
            apt-get install -y \
                    build-essential \
                    autoconf \
                    libtool

deps-alpine:
        FROM +base-alpine
        RUN apk add --update \
             alpine-sdk \
             autoconf \
             automake \
             libtool \
             linux-headers

# TODO: figure out how to get this to cache properly
build:
        ARG base=debian
        FROM +deps-${base}
        COPY --dir --keep-ts \
             *.[ch] lib scamper tests utils configure.ac Makefile.am m4 \
             ./
        RUN autoreconf -vfi
        RUN ./configure
        RUN make
        ARG TARGETPLATFORM
        SAVE ARTIFACT scamper/scamper ${base}/${TARGETPLATFORM}/scamper \
             AS LOCAL ./build/${base}/${TARGETPLATFORM}/scamper

build-multiarch:
        BUILD \
              --platform=linux/arm/v7 \
              --platform=linux/arm/v6 \
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +build --base=debian
        BUILD \
              --platform=linux/arm/v7 \
              --platform=linux/arm/v6 \
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +build --base=alpine

# TODO: fix
dist:
        FROM +build
        RUN rm -f scamper-cvs-*.tar.gz
        RUN make dist
        SAVE ARTIFACT scamper-cvs-*.tar.gz \
             AS LOCAL ./dist/

docker:
        ARG TARGETPLATFORM
        ARG base=debian
        FROM +base-${base}
        COPY +build/${base}/${TARGETPLATFORM}/scamper /usr/local/bin/scamper
        ENTRYPOINT ["/usr/local/bin/scamper"]
        ARG EARTHLY_TARGET_TAG_DOCKER
        ARG EARTHLY_GIT_SHORT_HASH
        ARG org="alistairking"
        ARG img="${org}/scamper"
        IF [ "${EARTHLY_TARGET_TAG_DOCKER}" = "master" ]
           ARG latest="${img}:latest"
           IF [ "${base}" != "debian" ]
              ARG latest="${base}-${latest}"
           END
        END
        SAVE IMAGE --push \
             ${img}:${base}-${EARTHLY_TARGET_TAG_DOCKER} \
             ${img}:${base}-${EARTHLY_GIT_SHORT_HASH} \
             ${latest}

docker-multiarch:
        BUILD \
              --platform=linux/arm/v7 \
              --platform=linux/arm/v6 \
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +docker --base=debian
        BUILD \
              --platform=linux/arm/v7 \
              --platform=linux/arm/v6 \
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +docker --base=alpine

# Earthly has a bug so can't RUN without /bin/sh
# https://github.com/earthly/earthly/issues/1097
pkg-fix:
        FROM kentik/pkg:latest
        SAVE ARTIFACT /pkg kentik-pkg

pkg:
        FROM +base-debian
        COPY +pkg-fix/kentik-pkg /usr/bin/pkg
        ARG EARTHLY_TARGET_TAG
        ARG TARGETPLATFORM
        ARG TARGETARCH
        ARG TARGETVARIANT
        ARG type=deb
        ARG version="${EARTHLY_TARGET_TAG}"
        ARG pkg_arch="${TARGETARCH}${TARGETVARIANT}"
        COPY +build/debian/${TARGETPLATFORM}/scamper ./
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
        FROM +base-debian
        RUN apt-get update && \
            apt-get install -y \
                    perl groff ghostscript

docs:
        FROM +docs-deps
        COPY . .
        RUN ./build-man-pdfs.pl
        SAVE ARTIFACT man/*.pdf AS LOCAL docs/

# To support native macos (etc.) builds
# TODO: this feels clunky and repetitive. Is there no better way?
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
