VERSION 0.8

all:
        BUILD +build

base-debian:
        ARG release=bullseye
        FROM debian:${release}-slim
        WORKDIR /scamper

base-ubuntu:
        ARG release=focal
        FROM ubuntu:${release}
        WORKDIR /scamper

base-alpine:
        FROM alpine:latest
        WORKDIR /scamper

deps-debian:
        ARG release
        FROM +base-debian --release=${release}
        RUN apt-get update && \
            apt-get install -y \
                    build-essential \
                    autoconf \
                    libtool

deps-ubuntu:
        ARG release
        FROM +base-ubuntu --release=${release}
        RUN apt-get update && \
            apt-get install -y \
                    build-essential \
                    autoconf \
                    libtool

deps-alpine:
        ARG release
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
        ARG release=bullseye
        ARG EARTHLY_TARGET_TAG
        ARG EARTHLY_GIT_SHORT_HASH
        FROM +deps-${base} --release=${release}
        COPY --dir --keep-ts \
             *.[ch] lib scamper tests utils configure.ac Makefile.am m4 set-version.sh \
             ./
        RUN ./set-version.sh "$(grep SCAMPER_VERSION scamper/scamper.h | cut -d \" -f 2)-${EARTHLY_TARGET_TAG}.${EARTHLY_GIT_SHORT_HASH}"
        RUN autoreconf -vfi
        RUN ./configure --disable-libs --disable-utils --enable-scamper-privsep=rootonly --with-openssl=disabled --enable-scamper-ring --disable-scamper-dnp
        RUN make
        RUN echo "Successfully built scamper version: $(./scamper/scamper -v)"
        LET baserelease="${base}"
        IF [ "${base}" = "debian" ]
           SET baserelease="${base}/${release}"
        END
        ARG TARGETPLATFORM
        SAVE ARTIFACT scamper/scamper ${baserelease}/${TARGETPLATFORM}/scamper \
             AS LOCAL ./build/${baserelease}/${TARGETPLATFORM}/scamper

build-multiarch-debian:
        BUILD \
              --platform=linux/arm/v7 \
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +build \
                --base=debian \
                  --release=trixie \
                  --release=bookworm \
                  --release=bullseye
build-multiarch-ubuntu:
        BUILD \
              --platform=linux/arm/v7 \
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +build \
                --base=ubuntu \
                  --release=noble \
                  --release=jammy \
                  --release=focal
build-multiarch-alpine:
        BUILD \
              --platform=linux/arm/v7 \
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
        ARG release=bullseye
        FROM +base-${base}
        LET baserelease="${base}"
        LET relpath="${base}"
        IF [ "${base}" = "debian" ]
           SET baserelease="${base}-${release}"
           SET relpath="${base}/${release}"
        END
        COPY +build/${relpath}/${TARGETPLATFORM}/scamper /usr/local/bin/scamper
        ENTRYPOINT ["/usr/local/bin/scamper"]
        ARG EARTHLY_TARGET_TAG_DOCKER
        ARG EARTHLY_GIT_SHORT_HASH
        ARG EARTHLY_GIT_PROJECT_NAME
        ARG img=${EARTHLY_GIT_PROJECT_NAME}
        LET base_latest=""
        LET latest=""
        IF [ "${EARTHLY_TARGET_TAG_DOCKER}" = "master" ]
           # if the base is debian/bookworm, then make it the default
           IF [ "${base}" = "debian" && "${release}" == "bookworm" ]
              SET latest="${img}:latest"
           END
           # tag this as the latest image for this base
           SET base_latest="${img}:${baserelease}-latest"
        END
        SAVE IMAGE --push \
             ${img}:${baserelease}-${EARTHLY_TARGET_TAG_DOCKER} \
             ${img}:${baserelease}-${EARTHLY_GIT_SHORT_HASH} \
             ${base_latest} \
             ${latest}

docker-multiarch:
        BUILD \
              --platform=linux/arm/v7 \
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +docker --base=debian --release=bullseye
        BUILD \
              --platform=linux/arm/v7 \
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +docker --base=debian --release=bookworm
        BUILD \
              --platform=linux/arm/v7 \
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +docker --base=alpine

# Earthly has a bug so can't RUN without /bin/sh
# https://github.com/earthly/earthly/issues/1097
pkg-fix:
        FROM kentik/pkg:latest
        SAVE ARTIFACT /pkg kentik-pkg

pkg:
        ARG base=debian
        ARG release=bullseye
        FROM +base-debian
        COPY +pkg-fix/kentik-pkg /usr/bin/pkg
        ARG EARTHLY_TARGET_TAG
        ARG TARGETPLATFORM
        ARG TARGETARCH
        ARG TARGETVARIANT
        ARG type=deb
        ARG version="${EARTHLY_TARGET_TAG}"
        ARG pkg_arch="${TARGETARCH}${TARGETVARIANT}"
        COPY +build/${base}/${release}/${TARGETPLATFORM}/scamper ./
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

# TODO: support bookworm/bullseye packages
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
                    perl man-db ghostscript

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
        RUN ./configure --disable-libs --disable-utils --with-openssl=disabled --enable-scamper-ring --disable-scamper-dnp

build-native:
        LOCALLY
        # BUILD +bootstrap-native # LOCALLY doesn't cache, so do this yourself
        RUN make
        ARG native_platform=native
        RUN mkdir -p ./build/${native_platform}
        RUN cp scamper/scamper ./build/${native_platform}/scamper
