from setuptools import Extension, setup
import textwrap

setup(
    name = "scamper",
    version = "20250603",
    description = "A module to interact with scamper processes and data",
    author = "Matthew Luckie",
    author_email = "mjl@luckie.org.nz",
    url = "https://www.caida.org/tools/measurement/scamper/",
    project_urls = {
        "Documentation": "https://www.caida.org/catalog/software/scamper/python/",
    },
    license = "GPL-2.0-only",
    ext_modules = [
        Extension("scamper", ["scamper.c"],
                  libraries=["scamperfile", "scamperctrl"]),
    ],
    keywords = ["Internet measurement", "ping", "traceroute", "dns", "http",
                "alias resolution"
    ],
    classifiers = [
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering",
    ],
    long_description_content_type = "text/x-rst",
    long_description = textwrap.dedent("""\
    scamper_ is a tool that actively probes the Internet in order to
    analyze Internet topology and performance.

    This scamper module provides convenient classes and methods for
    interacting with scamper processes and data. The scamper module
    has two related halves - classes for interacting with running
    scamper processes (through ScamperCtrl and related classes) and
    classes for reading and writing data previously collected with
    scamper (ScamperFile). These classes are supported by other
    classes that store measurement results. The types of measurements
    supported by the scamper module include ping, traceroute, alias
    resolution, DNS queries, HTTP, UDP probes, and packet capture.

    See the documentation_ for examples.

    The module requires two scamper libraries (libscamperctrl and
    libscamperfile) to run, and their development headers to build.
    These two scamper libraries are provided in the scamper source
    code distribution, and are packaged for many operating systems, as
    listed on the scamper_ website.  Where possible, use a package
    provided by your operating system before resorting to compiling
    and installing the libraries yourself.  Further, the Python module
    is already provided in packaged form by some operating systems,
    and you should use the packaged module where possible.

    .. _scamper: https://www.caida.org/tools/measurement/scamper/
    .. _documentation: https://www.caida.org/catalog/software/scamper/python/
    """)
)
