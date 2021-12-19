# scamper

**This is not the official scamper repository**

This is a copy/fork of
[Scamper](https://www.caida.org/catalog/software/scamper/) mostly so
that I can browse the source code on GitHub and send URLs to others.

## Branches

There are three main branches in this repo:

### upstream
The [`upstream`](https://github.com/alistairking/scamper/commits/upstream) branch
contains vanilla scamper code (with only a gitignore added) and exactly tracks
official scamper releases.

### master
The `master` branch contains vanilla scamper code (applied from the `upstream`
branch) but has some modifications applied to make it easier to build directly
and automatically from GitHub (using the instructions below).

### a6r
The [`a6r`](https://github.com/alistairking/scamper/commits/a6r) branch tracks
the master branch (and so should always be based on the latest official
release), but contains modifications that I find useful. Ideally these changes
will eventually end up in an upstream official release, but there's no
guarantee. Check the commit log and release notes for information about changes.

## Releases

There are two types of
[releases](https://github.com/alistairking/scamper/releases) made:

### `YYYYMMDD`
These are "vanilla" releases which should be practically identical to the
official scamper releases. These are tagged from the `master` branch and are
named in the `YYYYMMDD` format that scamper uses.

### `YYYYMMDD.XX-a6r`
These "a6r" releases also track upstream releases, but contain modifications
from the `a6r` branch. They are named in a format like `YYYYMMDD.VV-a6r` where
the date portion of the release refers to the upstream release version, the `VV`
refers to an "a6r" release within that version (i.e., the first a6r release
after an official release will be `XXXXXXXX.01-a6r1`).

## Docker Images

Docker images are published to [Docker
Hub](https://hub.docker.com/repository/docker/alistairking/scamper). They are
tagged with version numbers, as well as `latest` (or `master`) for the master
branch, and `a6r` for the latest a6r branch build.

For example:
```
docker run -it --rm alistairking/scamper:latest
usage: scamper [-?Dv] [-c command] [-p pps] [-w window]
               [-M monitorname] [-l listname] [-L listid] [-C cycleid]
               [-o outfile] [-O options] [-F firewall] [-e pidfile]
               [-n nameserver]
               [-d debugfile]
               [-i IPs | -I cmds | -f file | -P [ip:]port | -R name:port |
                -U unix]
```

## Building

In addition to the build instructions on the [official
website](https://www.caida.org/catalog/software/scamper/), when
cloning from this repo you'll need to first bootstrap some
automake/autoconf things:

```bash
autoreconf -vfi
./configure
make
make install
```

There is also an [Earthly](https://earthly.dev/get-earthly) [Earthfile](Earthfile) to
simplify builds. This is used by the GitHub actions to build binaries, but can
also be used locally:
```
earthly +build   # build linux-amd64 binary
earthly +docs    # generate pdf docs
earhtly +docker  # build docker image
```
