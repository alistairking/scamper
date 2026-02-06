VERSION 0.8

ARG --global DEFAULT_RELEASE=trixie

all:
        BUILD +build

base-debian:
        ARG release=${DEFAULT_RELEASE}
        FROM debian:${release}-slim
        WORKDIR /scamper

deps-debian:
        ARG --required release
        FROM +base-debian --release=${release}
        RUN apt-get update && \
            apt-get install -y \
                    build-essential \
                    autoconf \
                    libtool

base-ubuntu:
        ARG --required release
        FROM ubuntu:${release}
        WORKDIR /scamper

deps-ubuntu:
        ARG --required release
        FROM +base-ubuntu --release=${release}
        RUN apt-get update && \
            apt-get install -y \
                    build-essential \
                    autoconf \
                    libtool

base-el:
        ARG --required release
        FROM alpine:latest
        IF [ "$release" = "8" ]
            FROM centos:8
        ELSE
            FROM oraclelinux:9
        END
        WORKDIR /scamper

deps-el:
        ARG --required release
        FROM +base-el --release=${release}
        RUN \
            if grep -iq "el8" /etc/os-release ; then \
              sed -i 's/^mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-Linux-* ; \
              sed -i 's|#baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|g' /etc/yum.repos.d/CentOS-Linux-* ; \
              dnf install -y dnf-plugins-core ; \
              dnf config-manager --set-enabled powertools ; \
            else \
              dnf install -y dnf-plugins-core ; \
            fi && \
            dnf update -y && \
            dnf install -y \
                gcc \
                gcc-c++ \
                make \
                autoconf \
                automake \
                libtool \
                binutils \
                glibc-devel \
                pkgconf-pkg-config

base-alpine:
        FROM alpine:latest
        WORKDIR /scamper

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
        ARG release=${DEFAULT_RELEASE}
        ARG EARTHLY_TARGET_TAG
        ARG EARTHLY_GIT_SHORT_HASH
        FROM +deps-${base} --release=${release}
        COPY --dir --keep-ts \
             *.[ch] lib scamper tests utils configure.ac Makefile.am m4 set-version.sh \
             ./
        RUN ./set-version.sh "$(grep SCAMPER_VERSION scamper/scamper.h | cut -d \" -f 2)-${EARTHLY_TARGET_TAG}.${EARTHLY_GIT_SHORT_HASH}"
        RUN autoreconf -vfi
        RUN ./configure --disable-libs --disable-utils --enable-scamper-privsep=rootonly
        RUN make
        RUN echo "Successfully built scamper version: $(./scamper/scamper -v)"
        LET baserelease="${base}"
        IF [ "${base}" != "alpine" ]
           SET baserelease="${base}/${release}"
        END
        ARG TARGETPLATFORM
        SAVE ARTIFACT scamper/scamper ${baserelease}/${TARGETPLATFORM}/scamper \
             AS LOCAL ./build/${baserelease}/${TARGETPLATFORM}/scamper

build-debian:
        BUILD \
              +build \
                --base=debian \
                  --release=trixie \
                  --release=bookworm \
                  --release=bullseye

build-ubuntu:
        BUILD \
              +build \
                --base=ubuntu \
                  --release=noble \
                  --release=jammy \
                  --release=focal

build-el:
        BUILD \
              +build \
                --base=el \
                  --release=8 \
                  --release=9

build-alpine:
        BUILD +build --base=alpine

build-multiarch:
        BUILD --platform=linux/arm64 \
              --platform=linux/amd64 \
                +build-debian
        BUILD --platform=linux/arm64 \
              --platform=linux/amd64 \
                +build-ubuntu
        BUILD --platform=linux/arm64 \
              --platform=linux/amd64 \
                +build-el
        BUILD --platform=linux/arm64 \
              --platform=linux/amd64 \
                +build-alpine

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
        ARG release=${DEFAULT_RELEASE}
        FROM +base-${base}
        LET baserelease="${base}"
        LET relpath="${base}"
        IF [ "${base}" != "alpine" ]
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
           # if the base is debian/${DEFAULT_RELEASE}, then make it the default
           IF [ "${base}" = "debian" && "${release}" = "${DEFAULT_RELEASE}" ]
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
              --platform=linux/arm64 \
              --platform=linux/amd64 \
              +docker --base=debian
        BUILD \
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
        ARG release=${DEFAULT_RELEASE}
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
        RUN ./configure --disable-libs --disable-utils

build-native:
        LOCALLY
        # BUILD +bootstrap-native # LOCALLY doesn't cache, so do this yourself
        RUN make
        ARG native_platform=native
        RUN mkdir -p ./build/${native_platform}
        RUN cp scamper/scamper ./build/${native_platform}/scamper
