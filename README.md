# scamper

**This is not the official scamper repository**

This is a copy/fork of
[Scamper](https://www.caida.org/catalog/software/scamper/) mostly so
that I can browse the source code on GitHub and send URLs to others.

## Branches

### upstream
The [`upstream`](https://github.com/alistairking/scamper/commits/upstream) branch
contains vanilla scamper code (with only a gitignore added) and exactly tracks
official scamper releases.

### master
The `master` branch has some modifications applied to the latest official
scamper release to make it easier to build directly from GitHub (using the
instructions below).

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
