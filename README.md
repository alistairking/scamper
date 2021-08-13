# scamper

**This is not the official scamper repository**

This is a copy/fork of
[Scamper](https://www.caida.org/catalog/software/scamper/) mostly so
that I can browse the source code on GitHub and send URLs to others.

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
