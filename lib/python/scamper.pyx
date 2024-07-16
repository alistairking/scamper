# scamper python interface
#
# Author: Matthew Luckie
#
# Copyright (C) 2023-2024 The Regents of the University of California
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""
The scamper module contains a collection of classes for interacting
with running :manpage:`scamper(1)` processes, and to read and write data
stored in :manpage:`warts(5)` files.

Interacting with a running scamper process
==========================================

To interact with a running :manpage:`scamper(1)` process, instantiate a
:class:`ScamperCtrl` object, which manages a collection of running
scamper instances, each identified with a :class:`ScamperInst` object.
:class:`ScamperCtrl` allows the user to add instances that are local scamper
processes with the
:meth:`~scamper.ScamperCtrl.add_inet` and
:meth:`~scamper.ScamperCtrl.add_unix` methods,
which allow connection to a scamper instance
listening on the specified port or unix domain socket, respectively.
:class:`ScamperCtrl` also allows the user to add instances that
are remote scamper processes managed by :manpage:`sc_remoted(1)` and
accessible via a unix domain socket in the local file system with the
:meth:`~scamper.ScamperCtrl.add_remote` and
:meth:`~scamper.ScamperCtrl.add_remote_dir` methods.

The scamper module supports the following measurements:

#. Traceroute (:class:`ScamperTrace`) via \
:meth:`~scamper.ScamperCtrl.do_trace`
#. Ping (:class:`ScamperPing`) via \
:meth:`~scamper.ScamperCtrl.do_ping`
#. Alias resolution (:class:`ScamperDealias`) via \
:meth:`~scamper.ScamperCtrl.do_ally`, \
:meth:`~scamper.ScamperCtrl.do_mercator`, \
:meth:`~scamper.ScamperCtrl.do_midarest`, \
:meth:`~scamper.ScamperCtrl.do_midardisc`, \
:meth:`~scamper.ScamperCtrl.do_prefixscan`, and \
:meth:`~scamper.ScamperCtrl.do_radargun`
#. DNS (:class:`ScamperHost`) via :meth:`~scamper.ScamperCtrl.do_dns`
#. Packet capture (:class:`ScamperSniff`) via \
:meth:`~scamper.ScamperCtrl.do_sniff`
#. MDA traceroute (:class:`ScamperTracelb`) via \
:meth:`~scamper.ScamperCtrl.do_tracelb`
#. HTTP (:class:`ScamperHttp`) via \
:meth:`~scamper.ScamperCtrl.do_http`
#. UDP probes (:class:`ScamperUdpprobe`) via \
:meth:`~scamper.ScamperCtrl.do_udpprobe`

In order to request one of the scamper instances represented by a
:class:`ScamperInst` object conducts a measurement, call the specific
do method to conduct the measurement.
:class:`ScamperCtrl` provides both synchronous and event-based approaches
to retrieving completed measurements.
The following code illustrates the first of two synchronous approaches:

.. code-block::

  from scamper import *

  ctrl = ScamperCtrl(unix="/tmp/scamper")
  o = ctrl.do_ping("192.172.226.122", attempts=3, sync=True)
  print("ping from %s to %s" % (o.src, o.dst))
  for r in o:
    print(r)

This code constructs a :class:`ScamperCtrl`, adding a single local
scamper instance reachable through a unix domain socket.
It then issues a ping measurement with :meth:`~scamper.ScamperCtrl.do_ping`,
sending three attempts; the sync parameter causes the method to block
and return the completed results of the measurement, when they become
available.
Finally, the code prints a summary of the measurement.

The following code illustrates the second of the two synchronous
approaches:

.. code-block::

  from scamper import *

  ctrl = ScamperCtrl(unix="/tmp/scamper")
  ctrl.do_dns("www.caida.org")
  ctrl.do_dns("www.caida.org", qtype='AAAA')
  for o in ctrl.responses():
    for rr in o.ans():
      print(rr)

This code issues two DNS queries -- A and AAAA queries for
www.caida.org, which scamper executes in parallel.
Because :meth:`~scamper.ScamperCtrl.do_dns` is called without a sync
parameter, these methods immediately return a :class:`ScamperTask`
object representing the in-progress measurement, which this code
ignores.
It then waits for these measurements to complete, calling the
:meth:`~scamper.ScamperCtrl.responses` method, which returns
completed measurements, and only yields once all outstanding
:class:`ScamperTask` have completed.

The following code illustrates an event-based approach:

.. code-block::

  from scamper import *
  from datetime import *

  ctrl = ScamperCtrl(unix="/tmp/scamper")
  round_count = 10
  next_tx = datetime.now()

  while not ctrl.is_done():
      now = datetime.now()
      if now < next_tx:
          o = ctrl.poll(until=(next_tx if round_count > 0 else None))
          if isinstance(o, ScamperPing) and o.min_rtt is not None:
              print("%s %.1f" % (o.start.strftime("%H:%M:%S"),
                                 o.min_rtt.total_seconds() * 1000))
      elif round_count > 0:
          ctrl.do_ping("192.172.226.122", attempts=8, wait_probe=0.5,
                       reply_count=4)
          next_tx = next_tx + timedelta(seconds=10)
          round_count -= 1
          if round_count <= 0:
              ctrl.done()

This code sends a batch of pings every 10 seconds.  Each batch of pings
can take a different length of time depending on packet loss, as it can
send up to 8 pings, but can stop after receiving 4 responses.
For each batch of pings, it prints a timestamp that reports when the
measurement started, and the minimum RTT observed in milliseconds.
It passes a parameter to :meth:`~scamper.ScamperCtrl.wait` until it has
no more pings to send, when round_count reaches zero.
The :meth:`~scamper.ScamperCtrl.wait` method can take a parameter that
causes it to return when a given time is reached (the until parameter)
or wait for a specific length of time (the timeout parameter).
If neither parameter is used, then :meth:`~scamper.ScamperCtrl.wait`
will block until it either has data to return, or an exception to raise.
This code called :meth:`~scamper.ScamperCtrl.done` to signal that it
had no further measurements to send, and the overall loop stops once
the :meth:`~scamper.ScamperCtrl.is_done` method signals that the
:class:`ScamperCtrl` has no further measurement results to return.
Calling :meth:`~scamper.ScamperCtrl.done` puts all underlying
:class:`ScamperInst` into a read-only mode, where no further commands
can be sent, but existing measurements can complete.

:class:`ScamperCtrl` can handle multiple scamper instances.
The following code illustrates a simple approach to conducting a
measurement task using multiple :class:`ScamperInst`:

.. code-block::

  import sys
  from scamper import *

  if len(sys.argv) != 3:
    print("usage: single-radius.py $dir $ip")
    sys.exit(-1)

  ctrl = ScamperCtrl(remote_dir=sys.argv[1])
  for i in ctrl.instances():
    ctrl.do_ping(sys.argv[2], inst=i)

  min_rtt = None
  min_vp = None

  for o in ctrl.responses():
    if o.min_rtt is not None and (min_rtt is None or min_rtt > o.min_rtt):
      min_rtt = o.min_rtt
      min_vp = o.inst

  print("%s %.1f ms" % (min_vp.name, min_rtt.total_seconds() * 1000))

This code creates a :class:`ScamperInst` for each instance managed
by :manpage:`sc_remoted(1)` that it finds in the specified directory.
It then issues delay measurements using each instance, and then
retrieves the responses as they arrive.
It keeps track of which Vantage Point (VP) gave the shortest delay,
and prints the name of the VP with the shortest delay at the end.

Reading and writing results to files
====================================

To read results stored in a native scamper :manpage:`warts(5)` file,
instantiate a :class:`ScamperFile` object, passing the name of the file
to open as the first parameter.  Read each object out of the file using the
:meth:`~scamper.ScamperFile.read` method, or by using the built in
Iterator, demonstrated below.  If the file contains objects of different
types, but you are only interested in a subset of the object types, you
can signal the types with the :meth:`~scamper.ScamperFile.filter_types`
method.  Finally, you can close the file when you are finished using the
:meth:`~scamper.ScamperFile.close` method.

The following code illustrates the overall approach:

.. code-block::

  from scamper import *

  addrs = {}
  file = ScamperFile("foo.warts.gz")
  for o in file:
    if isinstance(o, ScamperTrace):
      for hop in o.hops():
        if hop.addr is not None:
          addrs[hop.addr] = 1

  for o in sorted(list(addrs)):
    print(o)

  file.close()

This code reads :class:`ScamperTrace` objects out of foo.warts.gz, storing
addresses observed in each traceroute in a dictionary to identify
the unique addresses.
Finally, it prints the addresses in sorted order.

To write measurements to a file, instantiate a :class:`ScamperFile`
object, passing 'w' as the mode parameter.  By default,
:class:`ScamperFile` will write :manpage:`warts(5)` output, but this can
be changed either by specifying the kind parameter, or by using an
appropriate suffix in the filename.
:class:`ScamperFile` can write compressed :manpage:`warts(5)` output
using "warts.gz", "warts.bz2", or "warts.xz", write json output
with "json", or simple text output with "text".
Write each object out by passing the object to the
:meth:`~scamper.ScamperFile.write` method.

The following code illustrates the overall approach:

.. code-block::

  from scamper import *

  ctrl = ScamperCtrl()
  ctrl.add_unix("/tmp/scamper")
  ctrl.do_ping("192.172.226.122", attempts=3)
  ctrl.do_trace("192.172.226.122")
  ctrl.do_dns("192.172.226.122")
  ctrl.done()

  out = ScamperFile("foo.warts.gz", 'w', mode="warts.gz")
  while not ctrl.is_done():
    o = ctrl.poll()
    out.write(o)
  out.close()

This code issues ping, traceroute, and DNS lookups, and
writes the collected data to a gzip-compressed warts file.
"""

from libc.stdint cimport uint8_t, uint16_t, uint32_t
from libc.stdlib cimport free
from cpython.ref cimport PyObject
from cpython.exc cimport PyErr_CheckSignals
from cpython.mem cimport PyMem_Malloc, PyMem_Free
from cpython.object cimport Py_LT, Py_EQ, Py_GT, Py_LE, Py_NE, Py_GE
from posix.time cimport timeval
import time, datetime
import os, stat
import binascii
import enum
import re

cimport cscamper_addr
cimport cscamper_list
cimport cscamper_file
cimport cscamper_icmpext
cimport cscamper_trace
cimport cscamper_ping
cimport cscamper_tracelb
cimport cscamper_dealias
cimport cscamper_neighbourdisc
cimport cscamper_tbit
cimport cscamper_sting
cimport cscamper_sniff
cimport cscamper_host
cimport cscamper_http
cimport cscamper_udpprobe
cimport clibscamperctrl

# from scamper_file.h
SCAMPER_FILE_OBJ_LIST          = 1
SCAMPER_FILE_OBJ_CYCLE_START   = 2
SCAMPER_FILE_OBJ_CYCLE_DEF     = 3
SCAMPER_FILE_OBJ_CYCLE_STOP    = 4
SCAMPER_FILE_OBJ_ADDR          = 5
SCAMPER_FILE_OBJ_TRACE         = 6
SCAMPER_FILE_OBJ_PING          = 7
SCAMPER_FILE_OBJ_TRACELB       = 8
SCAMPER_FILE_OBJ_DEALIAS       = 9
SCAMPER_FILE_OBJ_NEIGHBOURDISC = 10
SCAMPER_FILE_OBJ_TBIT          = 11
SCAMPER_FILE_OBJ_STING         = 12
SCAMPER_FILE_OBJ_SNIFF         = 13
SCAMPER_FILE_OBJ_HOST          = 14
SCAMPER_FILE_OBJ_HTTP          = 15
SCAMPER_FILE_OBJ_UDPPROBE      = 16

# from libscamperctrl.h
SCAMPER_CTRL_TYPE_DATA  = 1
SCAMPER_CTRL_TYPE_MORE  = 2
SCAMPER_CTRL_TYPE_ERR   = 3
SCAMPER_CTRL_TYPE_EOF   = 4
SCAMPER_CTRL_TYPE_FATAL = 5

# from scamper_trace.h
SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS = 4
SCAMPER_TRACE_FLAG_RXERR           = 0x80
SCAMPER_TRACE_HOP_FLAG_REPLY_TTL   = 0x10

class ScamperTraceStop(enum.IntEnum):
    NoReason = 0x00
    Completed = 0x01
    Unreach = 0x02
    Icmp = 0x03
    Loop = 0x04
    GapLimit = 0x05
    Error = 0x06
    HopLimit = 0x07
    GSS = 0x08
    Halted = 0x09

# from scamper_ping.h
SCAMPER_PING_REPLY_FLAG_REPLY_TTL  = 0x01
SCAMPER_PING_REPLY_FLAG_REPLY_IPID = 0x02
SCAMPER_PING_REPLY_FLAG_PROBE_IPID = 0x04

# from scamper_host.h
SCAMPER_HOST_CLASS_IN    = 1

class ScamperHostType(enum.IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    DS = 43
    SSHFP = 44
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48

# from scamper_sniff.h
class ScamperSniffStop(enum.IntEnum):
    NoReason = 0
    Error = 1
    LimitTime = 2
    LimitPktC = 3
    Halted = 4

# from scamper_tracelb.h
class ScamperTracelbMethod(enum.IntEnum):
    UdpDport = 1
    IcmpEcho = 2
    UdpSport = 3
    TcpSport = 4
    TcpAckSport = 5

####
#### Scamper Address Object
####

cdef class ScamperAddr:
    """
    :class:`ScamperAddr` is used by scamper to store and interpret different
    address types.  This class implements __str__ to render strings of
    :class:`ScamperAddr` objects, __repr__ to show the object, as well as
    functions for sorting and hashing.

    The constructor takes a single parameter, a string, which represents
    an IPv4 or IPv6 address.
    """
    cdef cscamper_addr.scamper_addr_t *_c

    def __init__(self, addr):
        cdef cscamper_addr.scamper_addr_t *c
        cdef uint8_t buf[16]
        cdef int at
        if isinstance(addr, str):
            c = cscamper_addr.scamper_addr_fromstr(0, addr.encode('UTF-8'))
        elif isinstance(addr, bytes):
            if len(addr) == 4:
                at = 1
            elif len(addr) == 16:
                at = 2
            elif len(addr) == 6:
                at = 3
            else:
                raise ValueError("expected bytes array of 4/6/16 bytes")
            for i, b in enumerate(addr):
                buf[i] = b
            c = cscamper_addr.scamper_addr_alloc(at, buf)
        else:
            raise ValueError("invalid address")
        self._c = c

    def __str__(self):
        cdef char buf[128]
        cscamper_addr.scamper_addr_tostr(self._c, buf, sizeof(buf))
        return buf.decode('UTF-8', 'strict')

    def __repr__(self):
        cdef char buf[128]
        cscamper_addr.scamper_addr_tostr(self._c, buf, sizeof(buf))
        return "ScamperAddr('" + buf.decode('UTF-8', 'strict') + "')"

    def __format__(self, format_spec):
        return format(str(self), format_spec)

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_addr.scamper_addr_free(self._c)

    def __richcmp__(self, other, int op):
        if isinstance(other, ScamperAddr):
            x = cscamper_addr.scamper_addr_human_cmp(self._c, (<ScamperAddr>other)._c)
        elif isinstance(other, str):
            c = cscamper_addr.scamper_addr_fromstr(0, other.encode('UTF-8'))
            if c == NULL:
                return NotImplemented
            x = cscamper_addr.scamper_addr_human_cmp(self._c, c)
            cscamper_addr.scamper_addr_free(c)
        else:
            return NotImplemented
        if op == Py_EQ:
            return x == 0
        elif op == Py_NE:
            return x != 0
        elif op == Py_LT:
            return x < 0
        elif op == Py_LE:
            return x <= 0
        elif op == Py_GT:
            return x > 0
        elif op == Py_GE:
            return x >= 0
        return NotImplemented

    def __hash__(self):
        cdef const uint16_t *p16 = <const uint16_t *>cscamper_addr.scamper_addr_addr_get(self._c)
        cdef const uint32_t *p32 = <const uint32_t *>cscamper_addr.scamper_addr_addr_get(self._c)

        if cscamper_addr.scamper_addr_isipv4(self._c):
            return hash((p32[0]))
        elif cscamper_addr.scamper_addr_isipv6(self._c):
            return hash((p32[0], p32[1], p32[2], p32[3]))
        elif cscamper_addr.scamper_addr_isethernet(self._c):
            return hash((p16[0], p16[1], p16[2]))
        elif cscamper_addr.scamper_addr_isfirewire(self._c):
            return hash((p32[0], p32[1]))
        return 0

    @staticmethod
    cdef ScamperAddr from_ptr(cscamper_addr.scamper_addr_t *ptr):
        cdef ScamperAddr addr
        if ptr == NULL:
            return None
        addr = ScamperAddr.__new__(ScamperAddr)
        addr._c = cscamper_addr.scamper_addr_use(ptr)
        return addr

    @property
    def packed(self):
        """
        get method to return a bytes object containing the address.

        :returns: a bytes object containing the address
        :rtype: bytes
        """
        cdef const uint8_t *p = <const uint8_t *>cscamper_addr.scamper_addr_addr_get(self._c)
        cdef size_t pl = cscamper_addr.scamper_addr_len_get(self._c)
        if p == NULL or pl == 0:
            return None
        return p[:pl]

    def is_linklocal(self):
        """
        is the address in link-local address prefix 169.254.0.0/16 or
        fe80::/10?

        :returns: True if the address is in one of the link-local prefixes
        :rtype: bool
        """
        return cscamper_addr.scamper_addr_islinklocal(self._c)

    def is_rfc1918(self):
        """
        is the address in a private address prefix 10.0.0.0/8,
        172.16.0.0/12, or 192.168.0.0/16?

        :returns: True if the address is in one of the private address prefixes
        :rtype: bool
        """
        return cscamper_addr.scamper_addr_isrfc1918(self._c)

    def is_unicast(self):
        """
        is the address in the IPv6 unicast prefix 2000::/3?

        :returns: True if the address is in the unicast prefix
        :rtype: bool
        """
        return cscamper_addr.scamper_addr_isunicast(self._c)

    def is_6to4(self):
        """
        is the address in the IPv6 6to4 prefix 2002::/16?

        :returns: True if the address is in the 6to4 prefix
        :rtype: bool
        """
        return cscamper_addr.scamper_addr_is6to4(self._c)

    def is_reserved(self):
        """
        is the address in one of the reserved prefixes 0.0.0.0/8,
        10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,
        172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24,
        192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
        224.0.0.0/4, 240.0.0.0/4, 2002::/16, 2001::/32, 2001:2::/48,
        2001:3::/32, 2001:4:112::/48, 2001:10::/28, 2001:20::/28,
        or outside of 2000::/3?

        :returns: True if the address is in one of these reserved prefixes
        :rtype: bool
        """
        return cscamper_addr.scamper_addr_isreserved(self._c)

    def is_ipv4(self):
        """
        is the address an IPv4 address?

        :returns: True if the address is an IPv4 address
        :rtype: bool
        """
        return cscamper_addr.scamper_addr_isipv4(self._c)

    def is_ipv6(self):
        """
        is the address an IPv6 address?

        :returns: True if the address is an IPv6 address
        :rtype: bool
        """
        return cscamper_addr.scamper_addr_isipv6(self._c)

####
#### Scamper List Object
####
cdef class ScamperList:
    """
    :class:`ScamperList` is used by scamper to attach common meta-data to
    a set of results collected by scamper.  This class implements
    functions for sorting, and get methods to obtain list parameters.
    """
    cdef cscamper_list.scamper_list_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_list.scamper_list_free(self._c)

    def __eq__(self, other):
        if not isinstance(other, ScamperList):
            return NotImplemented
        return cscamper_list.scamper_list_cmp(self._c, (<ScamperList>other)._c) == 0

    def __ne__(self, other):
        if not isinstance(other, ScamperList):
            return NotImplemented
        return cscamper_list.scamper_list_cmp(self._c, (<ScamperList>other)._c) != 0

    def __lt__(self, other):
        if not isinstance(other, ScamperList):
            return NotImplemented
        return cscamper_list.scamper_list_cmp(self._c, (<ScamperList>other)._c) < 0

    def __le__(self, other):
        if not isinstance(other, ScamperList):
            return NotImplemented
        return cscamper_list.scamper_list_cmp(self._c, (<ScamperList>other)._c) <= 0

    def __gt__(self, other):
        if not isinstance(other, ScamperList):
            return NotImplemented
        return cscamper_list.scamper_list_cmp(self._c, (<ScamperList>other)._c) > 0

    def __ge__(self, other):
        if not isinstance(other, ScamperList):
            return NotImplemented
        return cscamper_list.scamper_list_cmp(self._c, (<ScamperList>other)._c) >= 0

    @staticmethod
    cdef ScamperList from_ptr(cscamper_list.scamper_list_t *ptr):
        cdef ScamperList l;
        if ptr == NULL:
            return None
        l = ScamperList.__new__(ScamperList)
        l._c = cscamper_list.scamper_list_use(ptr)
        return l

    @property
    def id(self):
        """
        get method to obtain the list's id

        :returns: the ID number
        :rtype: int
        """
        if self._c == NULL:
            return None
        return cscamper_list.scamper_list_id_get(self._c)

    @property
    def name(self):
        """
        get method to obtain the list's name

        :returns: the list's name
        :rtype: string
        """
        if self._c == NULL:
            return None
        c_name = cscamper_list.scamper_list_name_get(self._c)
        if c_name == NULL:
            return None
        return c_name.decode('UTF-8', 'strict')

    @property
    def descr(self):
        """
        get method to obtain the list's description

        :returns: the list's description
        :rtype: string
        """
        if self._c == NULL:
            return None
        c_descr = cscamper_list.scamper_list_descr_get(self._c)
        if c_descr == NULL:
            return None
        return c_descr.decode('UTF-8', 'strict')

    @property
    def monitor(self):
        """
        get method to obtain the name of the monitor that scamper
        processed this list on

        :returns: the list's monitor
        :rtype: string
        """
        if self._c == NULL:
            return None
        c_monitor = cscamper_list.scamper_list_monitor_get(self._c)
        if c_monitor == NULL:
            return None
        return c_monitor.decode('UTF-8', 'strict')

####
#### Scamper Cycle Object
####
cdef class ScamperCycle:
    """
    :class:`ScamperCycle` is used by scamper to attach common meta-data to
    a set of results collected with a :class:`ScamperList`.
    This class implements functions for sorting, and get methods to obtain
    cycle parameters.
    """
    cdef cscamper_list.scamper_cycle_t *_c
    cdef uint16_t _type

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_list.scamper_cycle_free(self._c)

    def __eq__(self, other):
        if not isinstance(other, ScamperCycle):
            return NotImplemented
        return cscamper_list.scamper_cycle_cmp(self._c, (<ScamperCycle>other)._c) == 0

    def __ne__(self, other):
        if not isinstance(other, ScamperCycle):
            return NotImplemented
        return cscamper_list.scamper_cycle_cmp(self._c, (<ScamperCycle>other)._c) != 0

    def __lt__(self, other):
        if not isinstance(other, ScamperCycle):
            return NotImplemented
        return cscamper_list.scamper_cycle_cmp(self._c, (<ScamperCycle>other)._c) < 0

    def __le__(self, other):
        if not isinstance(other, ScamperCycle):
            return NotImplemented
        return cscamper_list.scamper_cycle_cmp(self._c, (<ScamperCycle>other)._c) <= 0

    def __gt__(self, other):
        if not isinstance(other, ScamperCycle):
            return NotImplemented
        return cscamper_list.scamper_cycle_cmp(self._c, (<ScamperCycle>other)._c) > 0

    def __ge__(self, other):
        if not isinstance(other, ScamperCycle):
            return NotImplemented
        return cscamper_list.scamper_cycle_cmp(self._c, (<ScamperCycle>other)._c) >= 0

    @staticmethod
    cdef ScamperCycle from_ptr(cscamper_list.scamper_cycle_t *ptr, uint16_t t):
        cdef ScamperCycle cycle;
        if ptr == NULL:
            return None
        cycle = ScamperCycle.__new__(ScamperCycle)
        cycle._type = t
        cycle._c = cscamper_list.scamper_cycle_use(ptr)
        return cycle

    @property
    def id(self):
        """
        get method to obtain the cycle's id

        :returns: the ID number
        :rtype: int
        """
        if self._c == NULL:
            return None
        return cscamper_list.scamper_cycle_id_get(self._c)

    @property
    def start(self):
        """
        get method to obtain the cycle's start time.

        :returns: the start timestamp
        :rtype: datetime
        """
        if self._c == NULL:
            return None
        c_start = cscamper_list.scamper_cycle_start_time_get(self._c)
        if c_start == 0:
            return None
        t = time.gmtime(c_start)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], 0,
                                 tzinfo=datetime.timezone.utc)

    @property
    def stop(self):
        """
        get method to obtain the cycle's stop time.

        :returns: the stop time
        :rtype: datetime
        """
        if self._c == NULL:
            return None
        c_stop = cscamper_list.scamper_cycle_stop_time_get(self._c)
        if c_stop == 0:
            return None
        t = time.gmtime(c_stop)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], 999999,
                                 tzinfo=datetime.timezone.utc)

    @property
    def hostname(self):
        """
        get method to obtain the hostname of the system that the cycle
        was collected on at the time the cycle started.

        :returns: the hostname
        :rtype: string
        """
        if self._c == NULL:
            return None
        c_hostname = cscamper_list.scamper_cycle_hostname_get(self._c)
        if c_hostname == NULL:
            return None
        return c_hostname.decode('UTF-8', 'strict')

####
#### Scamper ICMP Extension Object
####

class ScamperIcmpMplsLabelStackEntry:
    """
    A :class:`ScamperIcmpMplsLabelStackEntry` object contains convenient
    accessor methods for an MPLS ICMP extension
    """
    def __init__(self, ext, i):
        """
        :param ScamperIcmpExt ext: the extension to wrap
        :param int i: the entry in the stack
        """
        self._ext = ext
        self._i = i

    def __str__(self):
        label = self._ext.mpls_label(self._i)
        exp = self._ext.mpls_exp(self._i)
        ttl = self._ext.mpls_ttl(self._i)
        s = self._ext.mpls_s(self._i)
        return "MPLS Label=%d Exp=%d TTL=%d S=%d" % (label, exp, ttl, s)

    @property
    def label(self):
        """
        the MPLS label for this stack entry

        :returns: the MPLS label
        :rtype: int
        """
        return self._ext.mpls_label(self._i)

    @property
    def exp(self):
        """
        the MPLS exp bits for this stack entry

        :returns: the MPLS exp bits
        :rtype: int
        """
        return self._ext.mpls_exp(self._i)

    @property
    def s(self):
        """
        the MPLS bottom-of-stack (S) bit for this stack entry

        :returns: the MPLS S bit
        :rtype: int
        """
        return self._ext.mpls_s(self._i)

    @property
    def ttl(self):
        """
        the MPLS TTL for this stack entry

        :returns: the MPLS TTL value
        :rtype: int
        """
        return self._ext.mpls_ttl(self._i)

class _ScamperIcmpMplsLabelStackIterator:
    def __init__(self, ext):
        self._ext = ext
        self._i = 0
        self._c = ext.mpls_count

    def __iter__(self):
        return self

    def __next__(self):
        if self._i < self._c:
            mpls = self._ext.mpls_lse(self._i)
            self._i += 1
            return mpls
        raise StopIteration

cdef class ScamperIcmpExt:
    """
    :class:`ScamperIcmpExt` is used by scamper to store information from
    an ICMP extension object.  This class implements functions for sorting.
    """
    cdef cscamper_icmpext.scamper_icmpext_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_icmpext.scamper_icmpext_free(self._c)

    def __eq__(self, other):
        if not isinstance(other, ScamperIcmpExt):
            return NotImplemented
        return cscamper_icmpext.scamper_icmpext_cmp(self._c, (<ScamperIcmpExt>other)._c) == 0

    def __ne__(self, other):
        if not isinstance(other, ScamperIcmpExt):
            return NotImplemented
        return cscamper_icmpext.scamper_icmpext_cmp(self._c, (<ScamperIcmpExt>other)._c) != 0

    def __lt__(self, other):
        if not isinstance(other, ScamperIcmpExt):
            return NotImplemented
        return cscamper_icmpext.scamper_icmpext_cmp(self._c, (<ScamperIcmpExt>other)._c) < 0

    def __le__(self, other):
        if not isinstance(other, ScamperIcmpExt):
            return NotImplemented
        return cscamper_icmpext.scamper_icmpext_cmp(self._c, (<ScamperIcmpExt>other)._c) <= 0

    def __gt__(self, other):
        if not isinstance(other, ScamperIcmpExt):
            return NotImplemented
        return cscamper_icmpext.scamper_icmpext_cmp(self._c, (<ScamperIcmpExt>other)._c) > 0

    def __ge__(self, other):
        if not isinstance(other, ScamperIcmpExt):
            return NotImplemented
        return cscamper_icmpext.scamper_icmpext_cmp(self._c, (<ScamperIcmpExt>other)._c) >= 0

    @staticmethod
    cdef ScamperIcmpExt from_ptr(cscamper_icmpext.scamper_icmpext_t *ptr):
        cdef ScamperIcmpExt ext = ScamperIcmpExt.__new__(ScamperIcmpExt)
        if ptr == NULL:
            return None
        ext._c = cscamper_icmpext.scamper_icmpext_use(ptr)
        return ext

    def is_mpls(self):
        """
        get method to determine if this ICMP extension is an MPLS
        extension

        :returns: True if this extension is an MPLS extension
        :rtype: bool
        """
        return cscamper_icmpext.scamper_icmpext_is_mpls(self._c)

    @property
    def mpls_count(self):
        """
        get method to find out the number of label stack entries

        :returns: the number of label stack entries
        :rtype: int
        """
        if not cscamper_icmpext.scamper_icmpext_is_mpls(self._c):
            return 0
        return cscamper_icmpext.scamper_icmpext_mpls_count_get(self._c)

    def mpls(self):
        """
        get method to obtain an iterator for the MPLS label stack entries

        :returns: an iterator for the label stack entries, which contains\
        :class:`ScamperIcmpMplsLabelStackEntry` objects
        :rtype: _ScamperIcmpMplsLabelStackIterator
        """
        if not cscamper_icmpext.scamper_icmpext_is_mpls(self._c):
            return None
        return _ScamperIcmpMplsLabelStackIterator(self)

    def mpls_lse(self, i):
        """
        mpls_lse(i)
        get method to obtain a specific label stack entry from an MPLS
        label stack

        :param int i: the stack entry of interest
        :returns: the label stack entry
        :rtype: ScamperIcmpMplsLabelStackEntry
        """
        if not cscamper_icmpext.scamper_icmpext_is_mpls(self._c):
            return None
        if i >= cscamper_icmpext.scamper_icmpext_mpls_count_get(self._c):
            return None
        return ScamperIcmpMplsLabelStackEntry(self, i)

    def mpls_label(self, i):
        """
        mpls_label(i)
        get method that returns the MPLS label for a specific stack entry

        :param int i: the stack entry of interest
        :returns: the MPLS label
        :rtype: int
        """
        if not cscamper_icmpext.scamper_icmpext_is_mpls(self._c):
            return None
        if i >= cscamper_icmpext.scamper_icmpext_mpls_count_get(self._c):
            return None
        return cscamper_icmpext.scamper_icmpext_mpls_label_get(self._c, i)

    def mpls_ttl(self, i):
        """
        mpls_ttl(i)
        get method that returns the MPLS TTL for a specific stack entry

        :param int i: the stack entry of interest
        :returns: the MPLS TTL
        :rtype: int
        """
        if not cscamper_icmpext.scamper_icmpext_is_mpls(self._c):
            return None
        if i >= cscamper_icmpext.scamper_icmpext_mpls_count_get(self._c):
            return None
        return cscamper_icmpext.scamper_icmpext_mpls_ttl_get(self._c, i)

    def mpls_exp(self, i):
        """
        mpls_exp(i)
        get method that returns the MPLS exp bits for a specific stack entry

        :param int i: the stack entry of interest
        :returns: the MPLS exp bits
        :rtype: int
        """
        if not cscamper_icmpext.scamper_icmpext_is_mpls(self._c):
            return None
        if i >= cscamper_icmpext.scamper_icmpext_mpls_count_get(self._c):
            return None
        return cscamper_icmpext.scamper_icmpext_mpls_exp_get(self._c, i)

    def mpls_s(self, i):
        """
        mpls_s(i)
        get method that returns the MPLS bottom-of-stack (S) bit for a specific stack entry

        :param int i: the stack entry of interest
        :returns: the MPLS S bit
        :rtype: int
        """
        if not cscamper_icmpext.scamper_icmpext_is_mpls(self._c):
            return None
        if i >= cscamper_icmpext.scamper_icmpext_mpls_count_get(self._c):
            return None
        return cscamper_icmpext.scamper_icmpext_mpls_s_get(self._c, i)

####
#### Scamper Trace Object
####

cdef class ScamperTraceHop:
    """
    :class:`ScamperTraceHop` is used by scamper to store information about a
    traceroute response.
    """
    cdef cscamper_trace.scamper_trace_hop_t *_c
    cdef uint32_t _c_t_flags

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        cscamper_trace.scamper_trace_hop_free(self._c)

    def __str__(self):
        cdef char buf[128]
        if self._c == NULL:
            return "*"
        c_a = cscamper_trace.scamper_trace_hop_addr_get(self._c)
        c_rtt = cscamper_trace.scamper_trace_hop_rtt_get(self._c)
        c_name = cscamper_trace.scamper_trace_hop_name_get(self._c)
        usec = (c_rtt.tv_sec * 1000000) + (c_rtt.tv_usec)
        cscamper_addr.scamper_addr_tostr(c_a, buf, sizeof(buf))
        return "%s%s %d.%03d ms" % (
            c_name.decode('UTF-8', 'strict') + " " if c_name != NULL else "",
            buf.decode('UTF-8', 'strict'), usec / 1000, usec % 1000)

    @staticmethod
    cdef ScamperTraceHop from_ptr(cscamper_trace.scamper_trace_hop_t *ptr,
                                  cscamper_trace.scamper_trace_t *trace):
        cdef ScamperTraceHop hop = ScamperTraceHop.__new__(ScamperTraceHop)
        if ptr == NULL:
            return None
        hop = ScamperTraceHop.__new__(ScamperTraceHop)
        hop._c = cscamper_trace.scamper_trace_hop_use(ptr)
        hop._c_t_flags = cscamper_trace.scamper_trace_flags_get(trace)
        return hop

    @property
    def src(self):
        """
        get method to obtain the source address observed for this hop

        :returns: the address object
        :rtype: ScamperAddr
        """
        if self._c == NULL:
            return None
        c = cscamper_trace.scamper_trace_hop_addr_get(self._c)
        return ScamperAddr.from_ptr(c)

    @property
    def name(self):
        """
        get method to obtain the name in a DNS PTR record for the hop's
        address, if scamper looked up the name.

        :returns: the name
        :rtype: string
        """
        if self._c == NULL:
            return None
        c = cscamper_trace.scamper_trace_hop_name_get(self._c)
        if c == NULL:
            return None
        return c.decode('UTF-8', 'strict')

    @property
    def tx(self):
        """
        get method to obtain the transmit time for the probe

        :returns: a timestamp, or None if scamper did not record a timestamp
        :rtype: datetime
        """
        if self._c == NULL:
            return None
        c = cscamper_trace.scamper_trace_hop_tx_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def rtt(self):
        """
        get method to obtain the round-trip-time for this response.

        :returns: the round trip time
        :rtype: timedelta
        """
        if self._c == NULL:
            return None
        c = cscamper_trace.scamper_trace_hop_rtt_get(self._c)
        return datetime.timedelta(seconds=c.tv_sec, microseconds=c.tv_usec)

    @property
    def attempt(self):
        """
        get method to obtain the attempt number for the hop.  The first
        attempt has a value of 1.

        :returns: the attempt number
        :rtype: int
        """
        if self._c == NULL:
            return None
        return cscamper_trace.scamper_trace_hop_probe_id_get(self._c)

    @property
    def probe_ttl(self):
        """
        get method to obtain the probe's TTL value.

        :returns: probe TTL
        :rtype: int
        """
        if self._c == NULL:
            return None
        return cscamper_trace.scamper_trace_hop_probe_ttl_get(self._c)

    @property
    def probe_size(self):
        """
        get method to obtain the size of the probe.

        :returns: probe size
        :rtype: int
        """
        if self._c == NULL:
            return None
        return cscamper_trace.scamper_trace_hop_probe_size_get(self._c)

    @property
    def reply_ttl(self):
        """
        get method to obtain the TTL value in the IP header of the
        response, if known.

        :returns: reply TTL
        :rtype: int
        """
        if (self._c == NULL or
            (cscamper_trace.scamper_trace_hop_flags_get(self._c) &
             SCAMPER_TRACE_HOP_FLAG_REPLY_TTL) == 0):
            return None
        return cscamper_trace.scamper_trace_hop_reply_ttl_get(self._c)

    @property
    def reply_tos(self):
        """
        get method to obtain the TOS value in the IP header of the
        response, if known.

        :returns: reply TOS
        :rtype: int
        """
        if self._c == NULL:
            return None
        sa = cscamper_trace.scamper_trace_hop_addr_get(self._c)
        if sa == NULL or not cscamper_addr.scamper_addr_isipv4(sa):
            return None
        return cscamper_trace.scamper_trace_hop_reply_tos_get(self._c)

    @property
    def icmp_type(self):
        """
        get method to obtain the ICMP type for the response, if the
        response was an ICMP response.

        :returns: ICMP type
        :rtype: int
        """
        if self._c == NULL or not cscamper_trace.scamper_trace_hop_is_icmp(self._c):
            return None
        return cscamper_trace.scamper_trace_hop_icmp_type_get(self._c)

    @property
    def icmp_code(self):
        """
        get method to obtain the ICMP code for the response, if the
        response was an ICMP response.

        :returns: ICMP code
        :rtype: int
        """
        if self._c == NULL or not cscamper_trace.scamper_trace_hop_is_icmp(self._c):
            return None
        return cscamper_trace.scamper_trace_hop_icmp_code_get(self._c)

    @property
    def reply_size(self):
        """
        get method to obtain the size of the reply, if known.

        :returns: reply size
        :rtype: int
        """
        if self._c == NULL:
            return None
        if self._c_t_flags & SCAMPER_TRACE_FLAG_RXERR != 0:
            return None
        return cscamper_trace.scamper_trace_hop_reply_size_get(self._c)

    @property
    def reply_ipid(self):
        """
        get method to obtain the IPID value in the IPv4 header of the
        response, if known.

        :returns: reply IPID
        :rtype: int
        """
        if self._c == NULL:
            return None
        sa = cscamper_trace.scamper_trace_hop_addr_get(self._c)
        if sa == NULL or not cscamper_addr.scamper_addr_isipv4(sa):
            return None
        if self._c_t_flags & SCAMPER_TRACE_FLAG_RXERR != 0:
            return None
        return cscamper_trace.scamper_trace_hop_reply_ipid_get(self._c)

    def is_tcp(self):
        """
        get method to determine if the response was a TCP packet.

        :returns: True if the response was a TCP packet.
        :rtype: bool
        """
        if self._c == NULL:
            return False
        return cscamper_trace.scamper_trace_hop_is_tcp(self._c)

    def is_icmp(self):
        """
        get method to determine if the response was a ICMP packet.

        :returns: True if the response was an ICMP packet.
        :rtype: bool
        """
        if self._c == NULL:
            return False
        return cscamper_trace.scamper_trace_hop_is_icmp(self._c)

    def is_icmp_q(self):
        """
        get method to determine if the response had an ICMP quotation

        :returns: True if the response had an ICMP quotation
        :rtype: bool
        """
        if self._c == NULL:
            return False
        return cscamper_trace.scamper_trace_hop_is_icmp_q(self._c)

    def is_icmp_unreach_port(self):
        """
        get method to determine if the response was an ICMP port unreachable
        message

        :returns: True if the response was an ICMP port unreachable
        :rtype: bool
        """
        if self._c == NULL:
            return False
        return cscamper_trace.scamper_trace_hop_is_icmp_unreach_port(self._c)

    def is_icmp_echo_reply(self):
        """
        get method to determine if the response was an ICMP echo reply

        :returns: True if the response was an ICMP echo reply
        :rtype: bool
        """
        if self._c == NULL:
            return False
        return cscamper_trace.scamper_trace_hop_is_icmp_echo_reply(self._c)

    def is_icmp_ttl_exp(self):
        """
        get method to determine if the response was an ICMP TTL expired
        (time exceeded)

        :returns: True if the response was an ICMP TTL expired message
        :rtype: bool
        """
        if self._c == NULL:
            return False
        return cscamper_trace.scamper_trace_hop_is_icmp_ttl_exp(self._c)

    def is_icmp_ptb(self):
        """
        get method to determine if the response was an ICMP packet too
        big (fragmentation needed)

        :returns: True if the response was an ICMP packet too big
        :rtype: bool
        """
        if self._c == NULL:
            return False
        return cscamper_trace.scamper_trace_hop_is_icmp_ptb(self._c)

    @property
    def icmp_nhmtu(self):
        """
        get method to obtain the next-hop MTU value encoded in an
        ICMP packet too big message

        :returns: the next hop MTU value
        :rtype: int
        """
        if self._c == NULL:
            return None
        if not cscamper_trace.scamper_trace_hop_is_icmp_ptb(self._c):
            return None
        return cscamper_trace.scamper_trace_hop_icmp_nhmtu_get(self._c)

    @property
    def icmp_q_ttl(self):
        """
        get method to obtain the TTL value from the quoted IP packet in
        the ICMP response.

        :returns: the quoted TTL value
        :rtype: int
        """
        if self._c == NULL:
            return None
        if not cscamper_trace.scamper_trace_hop_is_icmp_q(self._c):
            return None
        return cscamper_trace.scamper_trace_hop_icmp_q_ttl_get(self._c)

    @property
    def icmp_q_tos(self):
        """
        get method to obtain the TOS value from the quoted IP packet in
        the ICMP response.

        :returns: the quoted TOS value
        :rtype: int
        """
        if self._c == NULL:
            return None
        if not cscamper_trace.scamper_trace_hop_is_icmp_q(self._c):
            return None
        sa = cscamper_trace.scamper_trace_hop_addr_get(self._c)
        if sa == NULL or not cscamper_addr.scamper_addr_isipv4(sa):
            return None
        return cscamper_trace.scamper_trace_hop_icmp_q_tos_get(self._c)

    @property
    def icmp_q_ipl(self):
        """
        get method to obtain the IP length value from the quoted IP packet
        in the ICMP response.

        :returns: the quoted IP length
        :rtype: int
        """
        if self._c == NULL:
            return None
        if not cscamper_trace.scamper_trace_hop_is_icmp_q(self._c):
            return None
        return cscamper_trace.scamper_trace_hop_icmp_q_ipl_get(self._c)

    @property
    def tcp_flags(self):
        """
        get method to obtain the TCP flags of the TCP response.

        :returns: the TCP flags
        :rtype: int
        """
        if self._c == NULL:
            return None
        if not cscamper_trace.scamper_trace_hop_is_tcp(self._c):
            return None
        return cscamper_trace.scamper_trace_hop_tcp_flags_get(self._c)

    @property
    def icmpext(self):
        """
        get method to obtain any ICMP extension structure, if present.

        :returns: the ICMP extension
        :rtype: ScamperIcmpExt
        """
        if self._c == NULL:
            return None
        ext = cscamper_trace.scamper_trace_hop_icmpext_get(self._c)
        return ScamperIcmpExt.from_ptr(ext)

class _ScamperTraceHopIterator:
    def __init__(self, trace):
        self._trace = trace
        self._index = 0
        self._hopc = trace.hop_count

    def __iter__(self):
        return self

    def __next__(self):
        if self._index < self._hopc:
            hop = self._trace.hop(self._index)
            self._index += 1
            return hop
        raise StopIteration

cdef class ScamperTracePmtud:
    """
    :class:`ScamperTracePmtud` is used by scamper to store results from
    a path MTU discovery measurement.
    """
    cdef cscamper_trace.scamper_trace_pmtud_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_trace.scamper_trace_pmtud_free(self._c)

    @staticmethod
    cdef ScamperTracePmtud from_ptr(cscamper_trace.scamper_trace_pmtud_t *ptr):
        cdef ScamperTracePmtud p
        if ptr == NULL:
            return None
        p = ScamperTracePmtud.__new__(ScamperTracePmtud)
        p._c = cscamper_trace.scamper_trace_pmtud_use(ptr)
        return p

    @property
    def path_mtu(self):
        """
        get method to obtain the end-to-end path MTU

        :returns: the path MTU
        :rtype: int
        """
        return cscamper_trace.scamper_trace_pmtud_pmtu_get(self._c)

    @property
    def if_mtu(self):
        """
        get method to obtain the MTU of the interface to probe

        :returns: the interface MTU
        :rtype: int
        """
        return cscamper_trace.scamper_trace_pmtud_ifmtu_get(self._c)

    @property
    def out_mtu(self):
        """
        get method to obtain the MTU to the first hop

        :returns: MTU to first hop, could be different to the interface MTU
        :rtype: int
        """
        out_mtu = cscamper_trace.scamper_trace_pmtud_outmtu_get(self._c)
        if out_mtu != 0:
            return out_mtu
        return cscamper_trace.scamper_trace_pmtud_ifmtu_get(self._c)

cdef class ScamperTrace:
    """
    :class:`ScamperTrace` is used by scamper to store results from a traceroute
    measurement.
    """
    cdef cscamper_trace.scamper_trace_t *_c
    cdef public ScamperInst _inst

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_trace.scamper_trace_free(self._c)

    @staticmethod
    cdef ScamperTrace from_ptr(cscamper_trace.scamper_trace_t *ptr):
        cdef ScamperTrace trace = ScamperTrace.__new__(ScamperTrace)
        trace._c = ptr
        return trace

    @property
    def inst(self):
        """
        get :class:`ScamperInst` associated with this measurement,
        if the measurement was conducted using a :class:`ScamperCtrl`.

        :returns: the instance
        :rtype: ScamperInst
        """
        return self._inst

    @property
    def list(self):
        """
        get list associated with this measurement.

        :returns: the list
        :rtype: ScamperList
        """
        c = cscamper_trace.scamper_trace_list_get(self._c)
        return ScamperList.from_ptr(c)

    @property
    def cycle(self):
        """
        get cycle associated with this measurement.

        :returns: the cycle
        :rtype: ScamperCycle
        """
        c = cscamper_trace.scamper_trace_cycle_get(self._c)
        return ScamperCycle.from_ptr(c, SCAMPER_FILE_OBJ_CYCLE_DEF)

    @property
    def userid(self):
        """
        get method to obtain the userid parameter.

        :returns: the userid
        :rtype: int
        """
        return cscamper_trace.scamper_trace_userid_get(self._c)

    @property
    def start(self):
        """
        get method to obtain the time this measurement started.

        :returns: the start timestamp
        :rtype: datetime
        """
        c = cscamper_trace.scamper_trace_start_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def stop_reason(self):
        """
        get method to obtain the stop reason.

        :returns: the stop reason
        :rtype: ScamperTraceStop
        """
        c = cscamper_trace.scamper_trace_stop_reason_get(self._c)
        return ScamperTraceStop(c)

    @property
    def src(self):
        """
        get method to obtain the source address for a traceroute.

        :returns: the source address
        :rtype: ScamperAddr
        """
        c_a = cscamper_trace.scamper_trace_src_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def dst(self):
        """
        get method to obtain the destination address for a traceroute.

        :returns: the destination address
        :rtype: ScamperAddr
        """
        c_a = cscamper_trace.scamper_trace_dst_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def rtr(self):
        """
        get method to obtain the non-default router address through
        which this traceroute went.

        :returns: the non-default router's address
        :rtype: ScamperAddr
        """
        c_a = cscamper_trace.scamper_trace_rtr_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    def hop(self, i):
        """
        hop(i)
        get method to obtain a hop at a specific distance, starting at zero.

        :returns: the nominated hop
        :rtype: ScamperTraceHop
        """
        if i < 0 or i > 255:
            raise ValueError("invalid hop index: " + i)
        c_h = cscamper_trace.scamper_trace_hop_get(self._c, i)
        return ScamperTraceHop.from_ptr(c_h, self._c)

    @property
    def hop_count(self):
        """
        get method to obtain the number of hops that were probed in this
        traceroute.

        :returns: the number of hops
        :rtype: int
        """
        return cscamper_trace.scamper_trace_hop_count_get(self._c)

    def hops(self):
        """
        get method to obtain an iterator for recorded hops.

        :returns: an iterator
        :rtype: _ScamperTraceHopIterator
        """
        return _ScamperTraceHopIterator(self)

    @property
    def attempts(self):
        """
        get method to obtain the number of attempts per hop for
        this traceroute.

        :returns: the number of attempts per hop
        :rtype: int
        """
        return cscamper_trace.scamper_trace_attempts_get(self._c)

    @property
    def hoplimit(self):
        """
        get method to obtain the hop limit for this traceroute.

        :returns: the hop limit for this traceroute
        :rtype: int
        """
        return cscamper_trace.scamper_trace_hoplimit_get(self._c)

    @property
    def squeries(self):
        """
        get method to obtain the number of consecutive hops that
        could have been probed before waiting for a response.

        :returns: the number of consecutive hops
        :rtype: int
        """
        return cscamper_trace.scamper_trace_squeries_get(self._c)

    @property
    def gaplimit(self):
        """
        get method to obtain the number of consecutiive unresponse
        hops to probe before halting the traceroute.

        :returns: the number of consecutive unresponsive hops
        :rtype: int
        """
        return cscamper_trace.scamper_trace_gaplimit_get(self._c)

    @property
    def gapaction(self):
        """
        get method to obtain the action to take if the gaplimit
        is reached.

        :returns: an integer representing the gapaction.
        :rtype: int
        """
        return cscamper_trace.scamper_trace_gapaction_get(self._c)

    @property
    def firsthop(self):
        """
        get method to obtain the first hop this traceroute began
        probing at.

        :returns: the first hop probing began at.
        :rtype: int
        """
        return cscamper_trace.scamper_trace_firsthop_get(self._c)

    @property
    def tos(self):
        """
        get method to obtain the IP TOS byte used for this traceroute.

        :returns: the IP TOS byte
        :rtype: int
        """
        return cscamper_trace.scamper_trace_tos_get(self._c)

    @property
    def wait_timeout(self):
        """
        get method to obtain the length of time to wait before declaring
        a probe lost.

        :returns: the timeout value
        :rtype: timedelta
        """
        tv = cscamper_trace.scamper_trace_wait_timeout_get(self._c)
        return datetime.timedelta(seconds=tv.tv_sec, microseconds=tv.tv_usec)

    @property
    def wait_probe(self):
        """
        get method to obtain the minimum time to wait between probes.

        :returns: the minimum time to wait between probes
        :rtype: timedelta
        """
        tv = cscamper_trace.scamper_trace_wait_probe_get(self._c)
        return datetime.timedelta(seconds=tv.tv_sec, microseconds=tv.tv_usec)

    @property
    def confidence(self):
        """
        get method to obtain the confidence parameter that guides the
        number of attempts per hop before probing the next hop.

        :returns: the confidence value used, or zero if no parameter
        :rtype: int
        """
        return cscamper_trace.scamper_trace_confidence_get(self._c)

    @property
    def probe_size(self):
        """
        get method to obtain the probe size to used for this traceroute.

        :returns: the probe size used.
        :rtype: int
        """
        return cscamper_trace.scamper_trace_probe_size_get(self._c)

    @property
    def payload(self):
        """
        get method to obtain the payload used.

        :returns: payload
        :rtype: bytes
        """
        cdef const uint8_t *data
        data = cscamper_trace.scamper_trace_payload_get(self._c)
        length = cscamper_trace.scamper_trace_payload_len_get(self._c)
        if data == NULL or length == 0:
            return None
        return data[:length]

    @property
    def probe_sport(self):
        """
        get method to obtain the (base) source port used for this
        traceroute, if the traceroute used TCP or UDP probes.

        :returns: the (base) source port value used.
        :rtype: int
        """
        if (cscamper_trace.scamper_trace_type_is_udp(self._c) or
            cscamper_trace.scamper_trace_type_is_tcp(self._c)):
            return cscamper_trace.scamper_trace_sport_get(self._c)
        return None

    @property
    def probe_dport(self):
        """
        get method to obtain the (base) destination port used for this
        traceroute, if the traceroute used TCP or UDP probes.

        :returns: the (base) destination port value used.
        :rtype: int
        """
        if (cscamper_trace.scamper_trace_type_is_udp(self._c) or
            cscamper_trace.scamper_trace_type_is_tcp(self._c)):
            return cscamper_trace.scamper_trace_dport_get(self._c)
        return None

    @property
    def probe_icmp_sum(self):
        """
        get method to obtain the ICMP checksum value used in probes,
        if the traceroute was an ICMP paris traceroute.

        :returns: the checksum value used.
        :rtype: int
        """
        trace_type = cscamper_trace.scamper_trace_type_get(self._c)
        if (trace_type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS and
            cscamper_trace.scamper_trace_flag_is_icmpcsumdp(self._c)):
            return cscamper_trace.scamper_trace_dport_get(self._c)
        return None

    @property
    def offset(self):
        """
        get method to obtain the IP offset value used in this traceroute.

        :returns: the IP offset value used.
        :rtype: int
        """
        return cscamper_trace.scamper_trace_offset_get(self._c)

    @property
    def probe_count(self):
        """
        get method to obtain the total number of probes sent for this
        traceroute.

        :returns: the number of probes.
        :rtype: int
        """
        return cscamper_trace.scamper_trace_probec_get(self._c)

    @property
    def pmtud(self):
        """
        get method to obtain any path MTU information recorded for this
        traceroute.

        :returns: path MTU information.
        :rtype: ScamperTracePmtud
        """
        c = cscamper_trace.scamper_trace_pmtud_get(self._c)
        return ScamperTracePmtud.from_ptr(c)

    def is_udp(self):
        """
        get method to determine if this traceroute used UDP probes.

        :returns: True if this traceroute used UDP probes.
        :rtype: bool
        """
        return cscamper_trace.scamper_trace_type_is_udp(self._c)

    def is_tcp(self):
        """
        get method to determine if this traceroute used TCP probes.

        :returns: True if this traceroute used TCP probes.
        :rtype: bool
        """
        return cscamper_trace.scamper_trace_type_is_tcp(self._c)

    def is_icmp(self):
        """
        get method to determine if this traceroute used ICMP probes.

        :returns: True if this traceroute used ICMP probes.
        :rtype: bool
        """
        return cscamper_trace.scamper_trace_type_is_icmp(self._c)

    def is_stop_noreason(self):
        """
        get method to determine if this traceroute has no stop reason.

        :returns: True if this traceroute has no stop reason.
        :rtype: bool
        """
        stop = cscamper_trace.scamper_trace_stop_reason_get(self._c)
        if stop == ScamperTraceStop.NoReason:
            return True
        return False

    def is_stop_completed(self):
        """
        get method to determine if this traceroute stopped because
        it reached the destination.

        :returns: True if this traceroute reached the destination.
        :rtype: bool
        """
        stop = cscamper_trace.scamper_trace_stop_reason_get(self._c)
        if stop == ScamperTraceStop.Completed:
            return True
        return False

    def is_stop_unreach(self):
        """
        get method to determine if this traceroute stopped because
        it received an ICMP Destination Unreachable message.

        :returns: True if this traceroute received an ICMP unreachable.
        :rtype: bool
        """
        stop = cscamper_trace.scamper_trace_stop_reason_get(self._c)
        if stop == ScamperTraceStop.Unreach:
            return True
        return False

    def is_stop_icmp(self):
        """
        get method to determine if this traceroute stopped because
        it received an ICMP message that was not a destination
        unreachable.

        :returns: True if this traceroute received an unexpected ICMP message.
        :rtype: bool
        """
        stop = cscamper_trace.scamper_trace_stop_reason_get(self._c)
        if stop == ScamperTraceStop.ICMP:
            return True
        return False

    def is_stop_loop(self):
        """
        get method to determine if this traceroute stopped because
        it encountered a loop.

        :returns: True if this traceroute encountered a loop.
        :rtype: bool
        """
        stop = cscamper_trace.scamper_trace_stop_reason_get(self._c)
        if stop == ScamperTraceStop.Loop:
            return True
        return False

    def is_stop_gaplimit(self):
        """
        get method to determine if this traceroute stopped because
        it observed a consecutive series of unresponsive hops.

        :returns: True if this traceroute reached the gaplimit.
        :rtype: bool
        """
        stop = cscamper_trace.scamper_trace_stop_reason_get(self._c)
        if stop == ScamperTraceStop.Gaplimit:
            return True
        return False

    def is_stop_error(self):
        """
        get method to determine if this traceroute stopped because
        of an unexpected operating system error.

        :returns: True if this traceroute encountered an error.
        :rtype: bool
        """
        stop = cscamper_trace.scamper_trace_stop_reason_get(self._c)
        if stop == ScamperTraceStop.Error:
            return True
        return False

    def is_stop_hoplimit(self):
        """
        get method to determine if this traceroute stopped because
        it reached the hoplimit defined for this traceroute.

        :returns: True if this traceroute reached the hoplimit.
        :rtype: bool
        """
        stop = cscamper_trace.scamper_trace_stop_reason_get(self._c)
        if stop == ScamperTraceStop.HopLimit:
            return True
        return False

    def is_stop_gss(self):
        """
        get method to determine if this traceroute stopped because
        it received a response from an address in this traceroute's
        global stop set.

        :returns: True if this traceroute received a response from an\
        address in the global stop set.
        :rtype: bool
        """
        stop = cscamper_trace.scamper_trace_stop_reason_get(self._c)
        if stop == ScamperTraceStop.GSS:
            return True
        return False

    def is_stop_halted(self):
        """
        get method to determine if this traceroute stopped because
        it was halted by the user.

        :returns: True if this traceroute was halted.
        :rtype: bool
        """
        stop = cscamper_trace.scamper_trace_stop_reason_get(self._c)
        if stop == ScamperTraceStop.Halted:
            return True
        return False

####
#### Scamper Ping Object
####

cdef class ScamperPingReply:
    """
    :class:`ScamperPingReply` is used by scamper to store and interpret
    individual ping replies.
    This class implements __str__ to render strings of
    :class:`ScamperPingReply` objects.
    """
    cdef cscamper_ping.scamper_ping_reply_t *_c
    cdef bint _fromdst

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_ping.scamper_ping_reply_free(self._c)

    def __str__(self):
        cdef char buf[128]
        c_a = cscamper_ping.scamper_ping_reply_addr_get(self._c)
        c_rtt = cscamper_ping.scamper_ping_reply_rtt_get(self._c)
        usec = (c_rtt.tv_sec * 1000000) + (c_rtt.tv_usec)
        cscamper_addr.scamper_addr_tostr(c_a, buf, sizeof(buf))
        return "%d bytes from %s, seq=%d ttl=%d time=%d.%03d ms" % (
            cscamper_ping.scamper_ping_reply_size_get(self._c),
            buf.decode('UTF-8', 'strict'),
            cscamper_ping.scamper_ping_reply_probe_id_get(self._c),
            cscamper_ping.scamper_ping_reply_ttl_get(self._c),
            usec / 1000, usec % 1000)

    @staticmethod
    cdef ScamperPingReply from_ptr(cscamper_ping.scamper_ping_reply_t *ptr,
                                   cscamper_ping.scamper_ping_t *ping):
        cdef ScamperPingReply reply
        if ptr == NULL:
            return None
        reply = ScamperPingReply.__new__(ScamperPingReply)
        reply._c = cscamper_ping.scamper_ping_reply_use(ptr)
        reply._fromdst = cscamper_ping.scamper_ping_reply_is_from_target(ping,
                                                                         ptr)
        return reply

    def is_from_target(self):
        """
        get method to determine if the reply came from the target.

        :returns: True if the reply came from the target.
        :rtype: bool
        """
        return self._fromdst

    @property
    def src(self):
        """
        get method to obtain the address the reply came from.

        :returns: the address in the response, if any.
        :rtype: ScamperAddr
        """
        c = cscamper_ping.scamper_ping_reply_addr_get(self._c)
        return ScamperAddr.from_ptr(c)

    @property
    def tx(self):
        """
        get method to obtain the transit timestamp of the probe, if available.

        :returns: the transmit time of the corresponding probe.
        :rtype: datetime
        """
        c = cscamper_ping.scamper_ping_reply_tx_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def rtt(self):
        """
        get method to obtain the round-trip-time for this response.

        :returns: the round trip time
        :rtype: timedelta
        """
        c = cscamper_ping.scamper_ping_reply_rtt_get(self._c)
        return datetime.timedelta(seconds=c.tv_sec, microseconds=c.tv_usec)

    @property
    def rx(self):
        """
        get method to obtain the receive time for this response, if
        available.

        :returns: the receive time
        :rtype: datetime
        """
        txc = cscamper_ping.scamper_ping_reply_tx_get(self._c)
        if txc == NULL:
            return None
        t = time.gmtime(txc.tv_sec)
        rttc = cscamper_ping.scamper_ping_reply_rtt_get(self._c)

        dt = datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], txc.tv_usec,
                               tzinfo=datetime.timezone.utc)
        td = datetime.timedelta(seconds=rttc.tv_sec, microseconds=rttc.tv_usec)

        return dt + td;

    @property
    def attempt(self):
        """
        get method to obtain the attempt number for this probe.  The
        first attempt has a value of 1.

        :returns: the attempt number
        :rtype: int
        """
        return cscamper_ping.scamper_ping_reply_probe_id_get(self._c) + 1

    @property
    def probe_ipid(self):
        """
        get method to obtain the IPID value set for this probe.

        :returns: the IPID value
        :rtype: int
        """
        flags = cscamper_ping.scamper_ping_reply_flags_get(self._c)
        if (flags & SCAMPER_PING_REPLY_FLAG_PROBE_IPID) == 0:
            return None
        return cscamper_ping.scamper_ping_reply_probe_ipid_get(self._c)

    @property
    def reply_proto(self):
        """
        get method to obtain the IP protocol for this reply.

        :returns: the IP protocol value
        :rtype: int
        """
        return cscamper_ping.scamper_ping_reply_proto_get(self._c)

    @property
    def reply_ttl(self):
        """
        get method to obtain the IP TTL value for this reply.

        :returns: the IP TTL value for this reply.
        :rtype: int
        """
        flags = cscamper_ping.scamper_ping_reply_flags_get(self._c)
        if (flags & SCAMPER_PING_REPLY_FLAG_REPLY_TTL) == 0:
            return None
        return cscamper_ping.scamper_ping_reply_ttl_get(self._c)

    @property
    def reply_size(self):
        """
        get method to obtain the size of the reply.

        :returns: the size of the reply.
        :rtype: int
        """
        return cscamper_ping.scamper_ping_reply_size_get(self._c)

    @property
    def reply_ipid(self):
        """
        get method to obtain the IPID value in the reply, if available.

        :returns: the IPID value in the reply.
        :rtype: int
        """
        flags = cscamper_ping.scamper_ping_reply_flags_get(self._c)
        if (flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID) == 0:
            return None
        sa = cscamper_ping.scamper_ping_reply_addr_get(self._c)
        if cscamper_addr.scamper_addr_isipv4(sa):
            return cscamper_ping.scamper_ping_reply_ipid_get(self._c)
        else:
            return cscamper_ping.scamper_ping_reply_ipid32_get(self._c)

    def is_icmp(self):
        """
        get method to determine if the reply was an ICMP response.

        :returns: True if the reply was an ICMP response.
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_reply_is_icmp(self._c)

    def is_tcp(self):
        """
        get method to determine if the reply was an TCP response.

        :returns: True if the reply was an TCP response.
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_reply_is_tcp(self._c)

    def is_udp(self):
        """
        get method to determine if the reply was an UDP response.

        :returns: True if the reply was an UDP response.
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_reply_is_udp(self._c)

    def is_icmp_echo_reply(self):
        """
        get method to determine if the reply was an ICMP echo reply.

        :returns: True if the reply was an ICMP echo reply
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_reply_is_icmp_echo_reply(self._c)

    def is_icmp_unreach(self):
        """
        get method to determine if the reply was an ICMP destination unreachable

        :returns: True if the reply was an ICMP destination unreachable.
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_reply_is_icmp_unreach(self._c)

    def is_icmp_unreach_port(self):
        """
        get method to determine if the reply was an ICMP destination
        unreachable -- port unreachable

        :returns: True if the reply was an ICMP port unreachable
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_reply_is_icmp_unreach_port(self._c)

    def is_icmp_ttl_exp(self):
        """
        get method to determine if the reply was an ICMP TTL expired message

        :returns: True if the reply was an ICMP TTL expired message.
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_reply_is_icmp_ttl_exp(self._c)

    def is_icmp_tsreply(self):
        """
        get method to determine if the reply was an ICMP timestamp reply.

        :returns: True if the reply was an ICMP timestamp reply.
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_reply_is_icmp_tsreply(self._c)

    @property
    def icmp_type(self):
        """
        get method to obtain the ICMP type of the reply, if the
        reply was an ICMP response.

        :returns: the ICMP type.
        :rtype: int
        """
        if not cscamper_ping.scamper_ping_reply_is_icmp(self._c):
            return None
        return cscamper_ping.scamper_ping_reply_icmp_type_get(self._c)

    @property
    def icmp_code(self):
        """
        get method to obtain the ICMP code of the reply, if the
        reply was an ICMP response.

        :returns: the ICMP code.
        :rtype: int
        """
        if not cscamper_ping.scamper_ping_reply_is_icmp(self._c):
            return None
        return cscamper_ping.scamper_ping_reply_icmp_code_get(self._c)

    @property
    def tcp_flags(self):
        """
        get method to obtain the TCP flags of the reply, if the
        reply was a TCP response.

        :returns: the TCP flags.
        :rtype: int
        """
        if not cscamper_ping.scamper_ping_reply_is_tcp(self._c):
            return None
        return cscamper_ping.scamper_ping_reply_tcp_flags_get(self._c)

    @property
    def ifname(self):
        """
        get method to obtain the name of the interface that received the
        reply, if recorded.

        :return: the name of the interface.
        :rtype: string
        """
        c = cscamper_ping.scamper_ping_reply_ifname_get(self._c)
        if c == NULL:
            return None
        return c.decode('UTF-8', 'strict')

cdef class ScamperPing:
    """
    :class:`ScamperPing` is used by scamper to store results from a ping
    measurement.  The basic properties of the measurement are stored in
    a :class:`ScamperPing` object, while the properties of individual
    responses are stored in :class:`ScamperPingReply` objects.
    The total number of probes sent can be found with :attr:`probe_count`.
    Individual responses can be obtained using :meth:`reply`.

    .. code-block::

      print("ping from %s to %s" % (ping.src, ping.dst))
        for i in range(ping.probe_count):
          r = ping.reply(i)
          if r is None:
            print("no reply for attempt %d" % (i+1))
          else:
            print("reply from %s, attempt %d" % (i+1))

    To iterate over all probes with responses, use the iterator.

    .. code-block::

      print("ping from %s to %s" % (ping.src, ping.dst))
        for r in ping:
          print("reply from %s, attempt %d" % (r.src, r.attempt))

    """
    cdef cscamper_ping.scamper_ping_t *_c
    cdef cscamper_ping.scamper_ping_stats_t *_c_s
    cdef uint16_t _i, _sent
    cdef public ScamperInst _inst

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c_s != NULL:
            cscamper_ping.scamper_ping_stats_free(self._c_s)
        if self._c != NULL:
            cscamper_ping.scamper_ping_free(self._c)

    def __iter__(self):
        self._i = 0
        self._sent = cscamper_ping.scamper_ping_sent_get(self._c)
        return self

    def __next__(self):
        while self._i < self._sent:
            c_r = cscamper_ping.scamper_ping_reply_get(self._c, self._i)
            self._i += 1
            if c_r != NULL: #iterate to the next reply
                return ScamperPingReply.from_ptr(c_r, self._c)
        raise StopIteration

    @staticmethod
    cdef ScamperPing from_ptr(cscamper_ping.scamper_ping_t *ptr):
        cdef ScamperPing ping = ScamperPing.__new__(ScamperPing)
        ping._c = ptr
        return ping

    @property
    def inst(self):
        """
        get :class:`ScamperInst` associated with this measurement,
        if the measurement was conducted using a :class:`ScamperCtrl`.

        :returns: the instance
        :rtype: ScamperInst
        """
        return self._inst

    @property
    def list(self):
        """
        get list associated with this measurement.

        :returns: the list
        :rtype: ScamperList
        """
        c = cscamper_ping.scamper_ping_list_get(self._c)
        return ScamperList.from_ptr(c)

    @property
    def cycle(self):
        """
        get cycle associated with this measurement.

        :returns: the cycle
        :rtype: ScamperCycle
        """
        c = cscamper_ping.scamper_ping_cycle_get(self._c)
        return ScamperCycle.from_ptr(c, SCAMPER_FILE_OBJ_CYCLE_DEF)

    @property
    def src(self):
        """
        get method to obtain the source address for a ping measurement.

        :returns: the source address
        :rtype: ScamperAddr
        """
        c_a = cscamper_ping.scamper_ping_src_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def dst(self):
        """
        get method to obtain the destination address for ping measurement.

        :returns: the destination address
        :rtype: ScamperAddr
        """
        c_a = cscamper_ping.scamper_ping_dst_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def rtr(self):
        """
        get method to obtain the non-default router address through
        which this ping went.

        :returns: the non-default router's address
        :rtype: ScamperAddr
        """
        c_a = cscamper_ping.scamper_ping_rtr_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def userid(self):
        """
        get method to obtain the userid parameter.

        :returns: the userid
        :rtype: int
        """
        return cscamper_ping.scamper_ping_userid_get(self._c)

    @property
    def start(self):
        """
        get method to obtain the time this measurement started.

        :returns: the start timestamp
        :rtype: datetime
        """
        c = cscamper_ping.scamper_ping_start_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def attempts(self):
        """
        get method to obtain the number of attempts for this
        ping measurement.

        :returns: the number of attempts.
        :rtype: int
        """
        return cscamper_ping.scamper_ping_probe_count_get(self._c)

    @property
    def probe_size(self):
        """
        get method to obtain the size of the ping probes.

        :returns: probe size
        :rtype: int
        """
        return cscamper_ping.scamper_ping_probe_size_get(self._c)

    @property
    def payload(self):
        """
        get method to obtain the payload used.

        :returns: payload
        :rtype: bytes
        """
        cdef const uint8_t *data
        data = cscamper_ping.scamper_ping_probe_data_get(self._c)
        length = cscamper_ping.scamper_ping_probe_datalen_get(self._c)
        if data == NULL or length == 0:
            return None
        return data[:length]

    def is_icmp(self):
        """
        get method to determine if the ping measurement sent ICMP packets.

        :returns: True if the ping measurement sent ICMP packets.
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_method_is_icmp(self._c)

    def is_icmp_time(self):
        """
        get method to determine if the ping measurement sent ICMP timestamp
        request packets.

        :returns: True if the ping measurement sent ICMP timestamp requests
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_method_is_icmp_time(self._c)

    def is_tcp(self):
        """
        get method to determine if the ping measurement sent TCP packets.

        :returns: True if the ping measurement sent TCP packets.
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_method_is_tcp(self._c)

    def is_tcp_ack_sport(self):
        """
        get method to determine if the ping measurement sent TCP ACK packets
        where the source port changed for each packet.

        :returns: True if the ping measurement sent these TCP ACK packets.
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_method_is_tcp_ack_sport(self._c)

    def is_udp(self):
        """
        get method to determine if the ping measurement sent UDP packets.

        :returns: True if the ping measurement sent UDP packets.
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_method_is_udp(self._c)

    def is_vary_sport(self):
        """
        get method to determine if the ping measurement sent TCP or UDP
        packets where the source port changed for each packet.

        :returns: True if the ping measurement sent these TCP or UDP packets
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_method_is_vary_sport(self._c)

    def is_vary_dport(self):
        """
        get method to determine if the ping measurement sent TCP or UDP
        packets where the destination port changed for each packet.

        :returns: True if the ping measurement sent these TCP or UDP packets
        :rtype: bool
        """
        return cscamper_ping.scamper_ping_method_is_vary_dport(self._c)

    @property
    def probe_ttl(self):
        """
        get method to get the probe TTL value used in this ping measurement.

        :returns: the probe TTL value
        :rtype: int
        """
        return cscamper_ping.scamper_ping_probe_ttl_get(self._c)

    @property
    def probe_tos(self):
        """
        get method to get the probe TOS value used in this ping measurement.

        :returns: the probe TOS value
        :rtype: int
        """
        return cscamper_ping.scamper_ping_probe_tos_get(self._c)

    @property
    def wait_timeout(self):
        """
        get method to obtain the length of time to wait before declaring
        a probe lost.

        :returns: the timeout value
        :rtype: timedelta
        """
        tv = cscamper_ping.scamper_ping_wait_timeout_get(self._c)
        return datetime.timedelta(seconds=tv.tv_sec, microseconds=tv.tv_usec)

    @property
    def wait_probe(self):
        """
        get method to obtain the minimum time to wait between probes.

        :returns: the minimum time to wait between probes
        :rtype: timedelta
        """
        tv = cscamper_ping.scamper_ping_wait_probe_get(self._c)
        return datetime.timedelta(seconds=tv.tv_sec, microseconds=tv.tv_usec)

    @property
    def probe_sport(self):
        """
        get method to obtain the (base) source port used for this
        ping measurement, if the ping used TCP or UDP probes.

        :returns: the (base) source port value used.
        :rtype: int
        """
        if (cscamper_ping.scamper_ping_method_is_tcp(self._c) or
            cscamper_ping.scamper_ping_method_is_udp(self._c)):
            return cscamper_ping.scamper_ping_probe_sport_get(self._c)
        return None

    @property
    def probe_dport(self):
        """
        get method to obtain the (base) destination port used for this
        ping measurement, if the ping used TCP or UDP probes.

        :returns: the (base) destination port value used.
        :rtype: int
        """
        if (cscamper_ping.scamper_ping_method_is_tcp(self._c) or
            cscamper_ping.scamper_ping_method_is_udp(self._c)):
            return cscamper_ping.scamper_ping_probe_dport_get(self._c)
        return None

    @property
    def probe_icmp_sum(self):
        """
        get method to obtain the ICMP checksum value used for this
        ping measurement, if the ping used ICMP probes.

        :returns: the ICMP checksum
        :rtype: int
        """
        if cscamper_ping.scamper_ping_method_is_icmp(self._c):
            return cscamper_ping.scamper_ping_probe_icmpsum_get(self._c)
        return None

    @property
    def probe_tcp_seq(self):
        """
        get method to obtain the TCP sequence value used for this
        ping measurement, if the ping used TCP probes.

        :returns: the ICMP checksum
        :rtype: int
        """
        if cscamper_ping.scamper_ping_method_is_tcp(self._c):
            return cscamper_ping.scamper_ping_probe_tcpseq_get(self._c)
        return None

    @property
    def probe_tcp_ack(self):
        """
        get method to obtain the TCP acknowledgement value used for this
        ping measurement, if the ping used TCP probes.

        :returns: the ICMP checksum
        :rtype: int
        """
        if cscamper_ping.scamper_ping_method_is_tcp(self._c):
            return cscamper_ping.scamper_ping_probe_tcpack_get(self._c)
        return None

    @property
    def stop_count(self):
        """
        get method to obtain the number of replies required at which time
        probing may cease.

        :returns: the number of replies
        :rtype: int
        """
        return cscamper_ping.scamper_ping_reply_count_get(self._c)

    @property
    def reply_pmtu(self):
        """
        get method to obtain the pseudo-MTU value used for this ping,
        if it used the too-big-trick.

        :returns: the psuedo MTU value
        :rtype: int
        """
        return cscamper_ping.scamper_ping_reply_pmtu_get(self._c)

    @property
    def probe_count(self):
        """
        get method to obtain the total number of probes sent for this
        measurement.

        :returns: the number of probes.
        :rtype: int
        """
        return cscamper_ping.scamper_ping_sent_get(self._c)

    def reply(self, i):
        """
        reply(i)
        get method to obtain a reply for a specific attempt, starting at zero.

        :returns: the nominated reply
        :rtype: ScamperPingReply
        """
        c = cscamper_ping.scamper_ping_reply_get(self._c, i)
        return ScamperPingReply.from_ptr(c, self._c)

    def _stats(self):
        if self._c_s == NULL:
            self._c_s = cscamper_ping.scamper_ping_stats_alloc(self._c)
        return

    @property
    def nreplies(self):
        """
        get method to obtain the number of probes for which scamper
        received at least one reply from the destination.

        :returns: the number of probes with replies
        :rtype: int
        """
        self._stats()
        if self._c_s == NULL:
            return None
        return cscamper_ping.scamper_ping_stats_nreplies_get(self._c_s)

    @property
    def ndups(self):
        """
        get method to obtain the total number of additional replies
        that scamper received from the destination.

        :returns: the number of additional replies
        :rtype: int
        """
        self._stats()
        if self._c_s == NULL:
            return None
        return cscamper_ping.scamper_ping_stats_ndups_get(self._c_s)

    @property
    def nloss(self):
        """
        get method to obtain the number of probes for which scamper did not
        receive any reply.

        :returns: the number of packets with no reply
        :rtype: int
        """
        self._stats()
        if self._c_s == NULL:
            return None
        return cscamper_ping.scamper_ping_stats_nloss_get(self._c_s)

    @property
    def nerrs(self):
        """
        get method to obtain the number of response packets that were not
        from the destination.

        :returns: the number of error packets received
        :rtype: int
        """
        self._stats()
        if self._c_s == NULL:
            return None
        return cscamper_ping.scamper_ping_stats_nerrs_get(self._c_s)

    @property
    def min_rtt(self):
        """
        get method to obtain the minimum RTT for a response from the
        destination.

        :returns: the minimum RTT
        :rtype: timedelta
        """
        self._stats()
        if self._c_s == NULL:
            return None
        c = cscamper_ping.scamper_ping_stats_min_rtt_get(self._c_s)
        if c == NULL:
            return None
        return datetime.timedelta(seconds=c.tv_sec, microseconds=c.tv_usec)

    @property
    def max_rtt(self):
        """
        get method to obtain the maximum RTT for a response from the
        destination.

        :returns: the maximum RTT
        :rtype: timedelta
        """
        self._stats()
        if self._c_s == NULL:
            return None
        c = cscamper_ping.scamper_ping_stats_max_rtt_get(self._c_s)
        if c == NULL:
            return None
        return datetime.timedelta(seconds=c.tv_sec, microseconds=c.tv_usec)

    @property
    def avg_rtt(self):
        """
        get method to obtain the average RTT for a response from the
        destination.

        :returns: the average RTT
        :rtype: timedelta
        """
        self._stats()
        if self._c_s == NULL:
            return None
        c = cscamper_ping.scamper_ping_stats_avg_rtt_get(self._c_s)
        if c == NULL:
            return None
        return datetime.timedelta(seconds=c.tv_sec, microseconds=c.tv_usec)

    @property
    def stddev_rtt(self):
        """
        get method to obtain the standard deviation for the RTTs for
        responses from the destination.

        :returns: the RTT standard deviation
        :rtype: timedelta
        """
        self._stats()
        if self._c_s == NULL:
            return None
        c = cscamper_ping.scamper_ping_stats_stddev_rtt_get(self._c_s)
        if c == NULL:
            return None
        return datetime.timedelta(seconds=c.tv_sec, microseconds=c.tv_usec)

####
#### Scamper Tracelb Object
####

class _ScamperTracelbNodeIterator:
    def __init__(self, trace):
        self._trace = trace
        self._index = 0
        self._nodec = trace.node_count

    def __iter__(self):
        return self

    def __next__(self):
        if self._index < self._nodec:
            node = self._trace.node(self._index)
            self._index += 1
            return node
        raise StopIteration

class _ScamperTracelbLinkIterator:
    def __init__(self, x):
        self._x = x
        self._index = 0
        self._linkc = x.link_count

    def __iter__(self):
        return self

    def __next__(self):
        if self._index < self._linkc:
            link = self._x.link(self._index)
            self._index += 1
            return link
        raise StopIteration

cdef class ScamperTracelbReply:
    """
    :class:`ScamperTracelbReply` is used by scamper to store information
    about a reply to a probe.
    """
    cdef cscamper_tracelb.scamper_tracelb_reply_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_tracelb.scamper_tracelb_reply_free(self._c)

    @staticmethod
    cdef ScamperTracelbReply from_ptr(cscamper_tracelb.scamper_tracelb_reply_t *ptr):
        cdef ScamperTracelbReply r
        if ptr == NULL:
            return None
        r = ScamperTracelbReply.__new__(ScamperTracelbReply)
        r._c = cscamper_tracelb.scamper_tracelb_reply_use(ptr)
        return r

    @property
    def src(self):
        """
        get method to obtain the source address of a reply

        :returns: the source address
        :rtype: ScamperAddr
        """
        c = cscamper_tracelb.scamper_tracelb_reply_from_get(self._c)
        return ScamperAddr.from_ptr(c)

    @property
    def rx(self):
        """
        get method that returns the time when a response was received.

        :returns: the time the response was received.
        :rtype: datetime
        """
        c = cscamper_tracelb.scamper_tracelb_reply_rx_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def ipid(self):
        """
        get method to obtain the IPID value in the reply, if available.

        :returns: the IPID value in the reply.
        :rtype: int
        """
        c = cscamper_tracelb.scamper_tracelb_reply_from_get(self._c)
        if c == NULL or cscamper_addr.scamper_addr_isipv4(c) == False:
            return None
        return cscamper_tracelb.scamper_tracelb_reply_ipid_get(self._c)

    @property
    def ttl(self):
        """
        get method to obtain the TTL value in the IP header of the
        response, if known.

        :returns: reply TTL
        :rtype: int
        """
        if not cscamper_tracelb.scamper_tracelb_reply_is_reply_ttl(self._c):
            return None
        return cscamper_tracelb.scamper_tracelb_reply_ttl_get(self._c)

    @property
    def icmp_type(self):
        """
        get method to obtain the ICMP type for the response, if the
        response was an ICMP response.

        :returns: ICMP type
        :rtype: int
        """
        if not cscamper_tracelb.scamper_tracelb_reply_is_icmp(self._c):
            return None
        return cscamper_tracelb.scamper_tracelb_reply_icmp_type_get(self._c)

    @property
    def icmp_code(self):
        """
        get method to obtain the ICMP code for the response, if the
        response was an ICMP response.

        :returns: ICMP code
        :rtype: int
        """
        if not cscamper_tracelb.scamper_tracelb_reply_is_icmp(self._c):
            return None
        return cscamper_tracelb.scamper_tracelb_reply_icmp_code_get(self._c)

    @property
    def icmp_q_ttl(self):
        """
        get method to obtain the TTL value from the quoted IP packet in
        the ICMP response.

        :returns: the quoted TTL value
        :rtype: int
        """
        if not cscamper_tracelb.scamper_tracelb_reply_is_icmp_q(self._c):
            return None
        return cscamper_tracelb.scamper_tracelb_reply_icmp_q_ttl_get(self._c)

    @property
    def icmp_q_tos(self):
        """
        get method to obtain the TOS value from the quoted IP packet in
        the ICMP response.

        :returns: the quoted TOS value
        :rtype: int
        """
        if not cscamper_tracelb.scamper_tracelb_reply_is_icmp_q(self._c):
            return None
        return cscamper_tracelb.scamper_tracelb_reply_icmp_q_tos_get(self._c)

    @property
    def tcp_flags(self):
        """
        get method to obtain the TCP flags of the TCP response.

        :returns: the TCP flags
        :rtype: int
        """
        if not cscamper_tracelb.scamper_tracelb_reply_is_tcp(self._c):
            return None
        return cscamper_tracelb.scamper_tracelb_reply_tcp_flags_get(self._c)

    @property
    def icmpext(self):
        """
        get method to obtain any ICMP extension structure, if present.

        :returns: the ICMP extension
        :rtype: ScamperIcmpExt
        """
        c = cscamper_tracelb.scamper_tracelb_reply_icmp_ext_get(self._c)
        return ScamperIcmpExt.from_ptr(c)

cdef class ScamperTracelbProbe:
    """
    :class:`ScamperTracelbProbe` is used by scamper to store information
    about an individual probe sent along a link to solicit a response.
    """
    cdef cscamper_tracelb.scamper_tracelb_probe_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_tracelb.scamper_tracelb_probe_free(self._c)

    def __str__(self):
        c = cscamper_tracelb.scamper_tracelb_probe_tx_get(self._c)
        out = "probe flowid: %d, ttl: %d, attempt: %d, tx: %d.%06d" % (
            cscamper_tracelb.scamper_tracelb_probe_flowid_get(self._c),
            cscamper_tracelb.scamper_tracelb_probe_ttl_get(self._c),
            cscamper_tracelb.scamper_tracelb_probe_attempt_get(self._c) + 1,
            c.tv_sec, c.tv_usec)
        return out

    @staticmethod
    cdef ScamperTracelbProbe from_ptr(cscamper_tracelb.scamper_tracelb_probe_t *ptr):
        cdef ScamperTracelbProbe p
        if ptr == NULL:
            return None
        p = ScamperTracelbProbe.__new__(ScamperTracelbProbe)
        p._c = cscamper_tracelb.scamper_tracelb_probe_use(ptr)
        return p

    @property
    def tx(self):
        """
        get method that returns the time when the probe was sent.

        :returns: the transmit time for the probe
        :rtype: datetime
        """
        c = cscamper_tracelb.scamper_tracelb_probe_tx_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def flowid(self):
        """
        get method that returns the flowid associated with the probe

        :returns: the flowid
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_probe_flowid_get(self._c)

    @property
    def ttl(self):
        """
        get method that returns the TTL set in the probe packet

        :returns: the TTL
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_probe_ttl_get(self._c)

    @property
    def attempt(self):
        """
        get method to obtain the attempt number for the hop.  The first
        attempt has a value of 1.

        :returns: the attempt number
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_probe_attempt_get(self._c) + 1

    @property
    def reply_count(self):
        """
        get method that returns the number of replies recorded for this probe

        :returns: the number of replies recorded
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_probe_rxc_get(self._c)

    def reply(self, i):
        """
        get method that returns a specific reply recorded for this probe

        :returns: the reply
        :rtype: ScamperTracelbReply
        """
        c = cscamper_tracelb.scamper_tracelb_probe_rx_get(self._c, i)
        return ScamperTracelbReply.from_ptr(c)

cdef class ScamperTracelbProbeset:
    """
    :class:`ScamperTracelbProbeset` is used by scamper to store information
    about probes sent along a link to solicit responses.
    """
    cdef cscamper_tracelb.scamper_tracelb_probeset_t *_c
    cdef uint16_t _i, _probec

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_tracelb.scamper_tracelb_probeset_free(self._c)

    @staticmethod
    cdef ScamperTracelbProbeset from_ptr(cscamper_tracelb.scamper_tracelb_probeset_t *ptr):
        cdef ScamperTracelbProbeset ps
        if ptr == NULL:
            return None
        ps = ScamperTracelbProbeset.__new__(ScamperTracelbProbeset)
        ps._c = cscamper_tracelb.scamper_tracelb_probeset_use(ptr)
        ps._probec = cscamper_tracelb.scamper_tracelb_probeset_probec_get(ptr)
        return ps

    def __len__(self):
        return self._probec

    def __iter__(self):
        self._i = 0
        return self

    def __next__(self):
        if self._i >= self._probec:
            raise StopIteration
        c = cscamper_tracelb.scamper_tracelb_probeset_probe_get(self._c,self._i)
        self._i = self._i + 1
        return ScamperTracelbProbe.from_ptr(c)

    @property
    def probe_count(self):
        """
        get method that returns the number of probes sent in this set

        :returns: the number of probes sent
        :rtype: int
        """
        return self._probec

    def probe(self, i):
        """
        get method that returns a specific probe in this probeset

        :returns: the probe identified
        :rtype: ScamperTracelbProbe
        """
        c = cscamper_tracelb.scamper_tracelb_probeset_probe_get(self._c, i)
        return ScamperTracelbProbe.from_ptr(c)

cdef class ScamperTracelbNode:
    """
    :class:`ScamperTracelbNode` is used by scamper to store information
    about a single node observed in an MDA traceroute.
    """
    cdef cscamper_tracelb.scamper_tracelb_node_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_tracelb.scamper_tracelb_node_free(self._c)

    @staticmethod
    cdef ScamperTracelbNode from_ptr(cscamper_tracelb.scamper_tracelb_node_t *ptr):
        cdef ScamperTracelbNode n
        if ptr == NULL:
            return None
        n = ScamperTracelbNode.__new__(ScamperTracelbNode)
        n._c = cscamper_tracelb.scamper_tracelb_node_use(ptr)
        return n

    @property
    def src(self):
        """
        get method to obtain the address of a node

        :returns: the source address
        :rtype: ScamperAddr
        """
        c = cscamper_tracelb.scamper_tracelb_node_addr_get(self._c)
        return ScamperAddr.from_ptr(c)

    @property
    def name(self):
        """
        get method to obtain the name in a DNS PTR record for the node's
        address, if scamper looked up the name.

        :returns: the name
        :rtype: string
        """
        c = cscamper_tracelb.scamper_tracelb_node_name_get(self._c)
        if c == NULL:
            return None
        return c.decode('UTF-8', 'strict')

    @property
    def icmp_q_ttl(self):
        """
        get method to obtain the TTL value from the quoted IP packet in
        the ICMP response for this node.

        :returns: the quoted TTL value
        :rtype: int
        """
        if cscamper_tracelb.scamper_tracelb_node_is_q_ttl(self._c):
            return cscamper_tracelb.scamper_tracelb_node_q_ttl_get(self._c)
        return None

    @property
    def link_count(self):
        """
        get method to obtain the number of links for this node.

        :returns: the number of links
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_node_linkc_get(self._c)

    def link(self, i):
        """
        link(i)
        get method to obtain a specific link attached to this node starting at zero.

        :returns: the nominated link
        :rtype: ScamperTracelbLink
        """
        c = cscamper_tracelb.scamper_tracelb_node_link_get(self._c, i)
        return ScamperTracelbLink.from_ptr(c)

    def links(self):
        return _ScamperTracelbLinkIterator(self)

cdef class ScamperTracelbLink:
    """
    :class:`ScamperTracelbNode` is used by scamper to store information
    about a single node observed in an MDA traceroute.
    """
    cdef cscamper_tracelb.scamper_tracelb_link_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_tracelb.scamper_tracelb_link_free(self._c)

    def __str__(self):
        cdef char buf[128]

        n = cscamper_tracelb.scamper_tracelb_link_from_get(self._c)
        a = cscamper_tracelb.scamper_tracelb_node_addr_get(n)
        if a != NULL:
            cscamper_addr.scamper_addr_tostr(a, buf, sizeof(buf))
            out = buf.decode('UTF-8', 'strict')
        else:
            out = "*"

        hopc = cscamper_tracelb.scamper_tracelb_link_hopc_get(self._c)
        for j in range(hopc-1):
            ps = cscamper_tracelb.scamper_tracelb_link_probeset_get(self._c, j)
            sm = cscamper_tracelb.scamper_tracelb_probeset_summary_alloc(ps)
            nullc = cscamper_tracelb.scamper_tracelb_probeset_summary_nullc_get(sm)
            addrc = cscamper_tracelb.scamper_tracelb_probeset_summary_addrc_get(sm)
            if nullc > 0 and addrc == 0:
                out = out + " -> *"
            else:
                out = out + "("
                for k in range(addrc):
                    if k > 0:
                        out = out + ", "
                    a = cscamper_tracelb.scamper_tracelb_probeset_summary_addr_get(sm, k)
                    cscamper_addr.scamper_addr_tostr(a, buf, sizeof(buf))
                    out = out + buf.decode('UTF-8', 'strict')
                if nullc > 0:
                    out = out + ", *)"
                else:
                    out = out + ")"
            cscamper_tracelb.scamper_tracelb_probeset_summary_free(sm)

        n = cscamper_tracelb.scamper_tracelb_link_to_get(self._c)
        a = cscamper_tracelb.scamper_tracelb_node_addr_get(n)
        if a != NULL:
            cscamper_addr.scamper_addr_tostr(a, buf, sizeof(buf))
            out = out + " -> " + buf.decode('UTF-8', 'strict')
        else:
            out = out + " -> *"

        return out

    @staticmethod
    cdef ScamperTracelbLink from_ptr(cscamper_tracelb.scamper_tracelb_link_t *ptr):
        cdef ScamperTracelbLink l
        if ptr == NULL:
            return None
        l = ScamperTracelbLink.__new__(ScamperTracelbLink)
        l._c = cscamper_tracelb.scamper_tracelb_link_use(ptr)
        return l

    def near(self):
        """
        get method to obtain the node at the near side of this link

        :returns: the node at the near side of this link
        :rtype: ScamperTracelbNode:
        """
        c = cscamper_tracelb.scamper_tracelb_link_from_get(self._c)
        return ScamperTracelbNode.from_ptr(c)

    def far(self):
        """
        get method to obtain the node at the far side of this link

        :returns: the node at the far side of this link
        :rtype: ScamperTracelbNode:
        """
        c = cscamper_tracelb.scamper_tracelb_link_to_get(self._c)
        return ScamperTracelbNode.from_ptr(c)

    def length(self):
        """
        get method to obtain the length of this link, in hops.

        :returns: the length of this link, in hops.
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_link_hopc_get(self._c)

    def probeset(self, i):
        """
        get method to obtain a probeset for a part of a link.

        :returns: a probeset.
        :rtype: ScamperTracelbProbeset
        """
        c = cscamper_tracelb.scamper_tracelb_link_probeset_get(self._c, i)
        return ScamperTracelbProbeset.from_ptr(c)

cdef class ScamperTracelb:
    """
    :class:`ScamperTracelb` is used by scamper to store results from a
    MDA traceroute measurement.
    """
    cdef cscamper_tracelb.scamper_tracelb_t *_c
    cdef public ScamperInst _inst

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_tracelb.scamper_tracelb_free(self._c)

    @staticmethod
    cdef ScamperTracelb from_ptr(cscamper_tracelb.scamper_tracelb_t *ptr):
        cdef ScamperTracelb tracelb = ScamperTracelb.__new__(ScamperTracelb)
        tracelb._c = ptr
        return tracelb

    @property
    def list(self):
        """
        get list associated with this measurement.

        :returns: the list
        :rtype: ScamperList
        """
        c = cscamper_tracelb.scamper_tracelb_list_get(self._c)
        return ScamperList.from_ptr(c)

    @property
    def cycle(self):
        """
        get cycle associated with this measurement.

        :returns: the cycle
        :rtype: ScamperCycle
        """
        c = cscamper_tracelb.scamper_tracelb_cycle_get(self._c)
        return ScamperCycle.from_ptr(c, SCAMPER_FILE_OBJ_CYCLE_DEF)

    @property
    def inst(self):
        """
        get :class:`ScamperInst` associated with this measurement,
        if the measurement was conducted using a :class:`ScamperCtrl`.

        :returns: the instance
        :rtype: ScamperInst
        """
        return self._inst

    @property
    def method(self):
        """
        get the method used in this MDA traceroute.

        :returns: the method
        :rtype: ScamperTracelbMethod
        """
        m = cscamper_tracelb.scamper_tracelb_type_get(self._c)
        return ScamperTracelbMethod(m)

    @property
    def userid(self):
        """
        get method to obtain the userid parameter.

        :returns: the userid
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_userid_get(self._c)

    @property
    def start(self):
        """
        get method to obtain the time this measurement started.

        :returns: the start timestamp
        :rtype: datetime
        """
        c = cscamper_tracelb.scamper_tracelb_start_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def src(self):
        """
        get method to obtain the source address for this measurement.

        :returns: the source address
        :rtype: ScamperAddr
        """
        c_a = cscamper_tracelb.scamper_tracelb_src_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def dst(self):
        """
        get method to obtain the destination address for this measurement.

        :returns: the destination address
        :rtype: ScamperAddr
        """
        c_a = cscamper_tracelb.scamper_tracelb_dst_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def rtr(self):
        """
        get method to obtain the non-default router address through
        which this measurement went.

        :returns: the non-default router's address
        :rtype: ScamperAddr
        """
        c_a = cscamper_tracelb.scamper_tracelb_rtr_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    def node(self, i):
        """
        node(i)
        get method to obtain a specific node, starting at zero.

        :returns: the nominated node
        :rtype: ScamperTracelbNode
        """
        c = cscamper_tracelb.scamper_tracelb_node_get(self._c, i)
        return ScamperTracelbNode.from_ptr(c)

    @property
    def node_count(self):
        """
        get method to obtain the number of nodes recorded in this measurement.

        :returns: the number of nodes
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_nodec_get(self._c)

    def nodes(self):
        """
        get method to obtain an iterator for recorded nodes.

        :returns: an iterator
        :rtype: _ScamperTracelbNodeIterator
        """
        return _ScamperTracelbNodeIterator(self)

    def link(self, i):
        """
        link(i)
        get method to obtain a specific link starting at zero.

        :returns: the nominated link
        :rtype: ScamperTracelbLink
        """
        c = cscamper_tracelb.scamper_tracelb_link_get(self._c, i)
        return ScamperTracelbLink.from_ptr(c)

    @property
    def link_count(self):
        """
        get method to obtain the number of links recorded in this measurement.

        :returns: the number of links
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_linkc_get(self._c)

    def links(self):
        """
        get method to obtain an iterator for recorded links.

        :returns: an iterator
        :rtype: _ScamperTracelbLinkIterator
        """
        return _ScamperTracelbLinkIterator(self)

    @property
    def attempts(self):
        """
        get method to obtain the number of attempts per probe for
        this measurement.

        :returns: the number of attempts per probe
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_attempts_get(self._c)

    @property
    def gaplimit(self):
        """
        get method to obtain the number of consecutiive unresponse
        hops to probe before halting the traceroute.

        :returns: the number of consecutive unresponsive hops
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_gaplimit_get(self._c)

    @property
    def firsthop(self):
        """
        get method to obtain the first hop this measurement began
        probing at.

        :returns: the first hop probing began at.
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_firsthop_get(self._c)

    @property
    def tos(self):
        """
        get method to obtain the IP TOS byte used for this traceroute.

        :returns: the IP TOS byte
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_tos_get(self._c)

    @property
    def wait_timeout(self):
        """
        get method to obtain the length of time to wait before declaring
        a probe lost.

        :returns: the timeout value.
        :rtype: timedelta
        """
        tv = cscamper_tracelb.scamper_tracelb_wait_timeout_get(self._c)
        return datetime.timedelta(seconds=tv.tv_sec, microseconds=tv.tv_usec)

    @property
    def wait_probe(self):
        """
        get method to obtain the minimum time to wait between probes.

        :returns: the minimum time to wait between probes
        :rtype: timedelta
        """
        tv = cscamper_tracelb.scamper_tracelb_wait_probe_get(self._c)
        return datetime.timedelta(seconds=tv.tv_sec, microseconds=tv.tv_usec)

    @property
    def confidence(self):
        """
        get method to obtain the confidence parameter that guides the
        number of attempts per hop before probing the next hop.

        :returns: the confidence value used, or zero if no parameter
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_confidence_get(self._c)

    @property
    def probe_count(self):
        """
        get method to obtain the total number of probes sent for this
        measurement.

        :returns: the number of probes.
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_probec_get(self._c)

    @property
    def probe_size(self):
        """
        get method to obtain the probe size to used for this measurement.

        :returns: the probe size used.
        :rtype: int
        """
        return cscamper_tracelb.scamper_tracelb_probe_size_get(self._c)

    @property
    def probe_sport(self):
        """
        get method to obtain the (base) source port used for this
        traceroute, if the traceroute used TCP or UDP probes.

        :returns: the (base) source port value used.
        :rtype: int
        """
        if (cscamper_tracelb.scamper_tracelb_type_is_udp(self._c) or
            cscamper_tracelb.scamper_tracelb_type_is_tcp(self._c)):
            return cscamper_tracelb.scamper_tracelb_sport_get(self._c)
        return None

    @property
    def probe_dport(self):
        """
        get method to obtain the (base) destination port used for this
        traceroute, if the traceroute used TCP or UDP probes.

        :returns: the (base) destination port value used.
        :rtype: int
        """
        if (cscamper_tracelb.scamper_tracelb_type_is_udp(self._c) or
            cscamper_tracelb.scamper_tracelb_type_is_tcp(self._c)):
            return cscamper_tracelb.scamper_tracelb_dport_get(self._c)
        return None

    @property
    def probe_icmp_id(self):
        """
        get method to obtain the ICMP id value used in probes,
        if the measurement used an ICMP method.

        :returns: the ICMP ID value used.
        :rtype: int
        """
        if cscamper_tracelb.scamper_tracelb_type_is_icmp(self._c):
            return cscamper_tracelb.scamper_tracelb_sport_get(self._c)
        return None

    def is_udp(self):
        """
        get method to determine if this measurement used UDP probes.

        :returns: True if this measurement used UDP probes.
        :rtype: bool
        """
        return cscamper_tracelb.scamper_tracelb_type_is_udp(self._c)

    def is_tcp(self):
        """
        get method to determine if this measurement used TCP probes.

        :returns: True if this measurement used TCP probes.
        :rtype: bool
        """
        return cscamper_tracelb.scamper_tracelb_type_is_tcp(self._c)

    def is_icmp(self):
        """
        get method to determine if this measurement used ICMP probes.

        :returns: True if this measurement used ICMP probes.
        :rtype: bool
        """
        return cscamper_tracelb.scamper_tracelb_type_is_icmp(self._c)

####
#### Scamper Dealias Object
####

cdef class ScamperDealiasReply:
    """
    The :class:`ScamperDealiasReply` object stores information for
    individual alias resolution probes.
    """
    cdef cscamper_dealias.scamper_dealias_reply_t *_c
    cdef bint _fromdst

    def __init__(self):
        raise TypeError("This class cannot be insantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_dealias.scamper_dealias_reply_free(self._c)

    @staticmethod
    cdef ScamperDealiasReply from_ptr(cscamper_dealias.scamper_dealias_reply_t *ptr,
                                      cscamper_dealias.scamper_dealias_probe_t *probe):
        cdef ScamperDealiasReply r
        if ptr == NULL:
            return None
        r = ScamperDealiasReply.__new__(ScamperDealiasReply)
        r._c = cscamper_dealias.scamper_dealias_reply_use(ptr)
        r._fromdst = cscamper_dealias.scamper_dealias_reply_from_target(probe, ptr)
        return r

    def is_from_target(self):
        """
        get method to determine if the reply came from the target.

        :returns: True if the reply came from the target.
        :rtype: bool
        """
        return self._fromdst

    @property
    def src(self):
        """
        get method to obtain the source address of a reply

        :returns: the source address
        :rtype: ScamperAddr
        """
        c_a = cscamper_dealias.scamper_dealias_reply_src_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def rx(self):
        """
        get method that returns the time when a response was received.

        :returns: the time when this response was received, or None if no response
        :rtype: datetime
        """
        c = cscamper_dealias.scamper_dealias_reply_rx_get(self._c)
        if c == NULL or (c.tv_sec == 0 and c.tv_usec == 0):
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def ttl(self):
        """
        get method to obtain the TTL value in the IP header of the
        response, if known.

        :returns: reply TTL
        :rtype: int
        """
        return cscamper_dealias.scamper_dealias_reply_ttl_get(self._c)

    @property
    def size(self):
        """
        get method to obtain the size of the response

        :returns: the size of the response
        :rtype: int
        """
        return cscamper_dealias.scamper_dealias_reply_size_get(self._c)

    @property
    def tcp_flags(self):
        """
        get method to obtain the TCP flags of the response, if the
        response was a TCP response.

        :returns: TCP flags
        :rtype: int
        """
        if not cscamper_dealias.scamper_dealias_reply_is_tcp(self._c):
            return None
        return cscamper_dealias.scamper_dealias_reply_tcp_flags_get(self._c)

    @property
    def icmp_type(self):
        """
        get method to obtain the ICMP type for the response, if the
        response was an ICMP response.

        :returns: ICMP type
        :rtype: int
        """
        if not cscamper_dealias.scamper_dealias_reply_is_icmp(self._c):
            return None
        return cscamper_dealias.scamper_dealias_reply_icmp_type_get(self._c)

    @property
    def icmp_code(self):
        """
        get method to obtain the ICMP code for the response, if the
        response was an ICMP response.

        :returns: ICMP code
        :rtype: int
        """
        if not cscamper_dealias.scamper_dealias_reply_is_icmp(self._c):
            return None
        return cscamper_dealias.scamper_dealias_reply_icmp_code_get(self._c)

    @property
    def icmp_q_ttl(self):
        """
        get method to obtain the TTL value from the quoted IP packet in
        the ICMP response.

        :returns: the quoted TTL value
        :rtype: int
        """
        if not cscamper_dealias.scamper_dealias_reply_is_icmp_q(self._c):
            return None
        return cscamper_dealias.scamper_dealias_reply_icmp_q_ttl_get(self._c)

    @property
    def ipid(self):
        """
        get method to obtain the IPID value in the reply, if available.

        :returns: the IPID value in the reply.
        :rtype: int
        """
        sa = cscamper_dealias.scamper_dealias_reply_src_get(self._c)
        if sa == NULL:
            return None
        if cscamper_addr.scamper_addr_isipv4(sa):
            return cscamper_dealias.scamper_dealias_reply_ipid_get(self._c)
        elif cscamper_dealias.scamper_dealias_reply_is_ipid32(self._c):
            return cscamper_dealias.scamper_dealias_reply_ipid32_get(self._c)
        return None

    def is_tcp(self):
        """
        get method to determine if the response was a TCP packet.

        :returns: True if the response was a TCP packet.
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_reply_is_tcp(self._c)

    def is_icmp(self):
        """
        get method to determine if the response was a ICMP packet.

        :returns: True if the response was an ICMP packet.
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_reply_is_icmp(self._c)

    def is_icmp_ttl_exp(self):
        """
        get method to determine if the response was an ICMP TTL expired
        (time exceeded)

        :returns: True if the response was an ICMP TTL expired message
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_reply_is_icmp_ttl_exp(self._c)

    def is_icmp_unreach(self):
        """
        get method to determine if the reply was an ICMP destination unreachable

        :returns: True if the reply was an ICMP destination unreachable.
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_reply_is_icmp_unreach(self._c)

    def is_icmp_unreach_port(self):
        """
        get method to determine if the response was an ICMP port unreachable
        message

        :returns: True if the response was an ICMP port unreachable
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_reply_is_icmp_unreach_port(self._c)

cdef class ScamperDealiasMidardiscRound:
    """
    The :class:`ScamperDealiasMidardiscRound` object stores information about
    a single round in a :class:`ScamperDealias` midardisc measurement.
    The constructor takes three parameters:

    - start: a :class:`datetime.timedelta` that represents when this round \
    should start.
    - begin: an integer representing the probedef index where this round \
    should begin.
    - end: an integer representing the probedef index where this round \
    should end.
    """
    cdef cscamper_dealias.scamper_dealias_midardisc_round_t *_c

    def __init__(self, start, begin, end):
        cdef timeval tv

        self._c = cscamper_dealias.scamper_dealias_midardisc_round_alloc()
        if self._c == NULL:
            raise MemoryError

        if not isinstance(start, datetime.timedelta):
            raise TypeError("expected timedelta for start")
        if not isinstance(begin, int):
            raise TypeError("expected int for begin")
        if not isinstance(end, int):
            raise TypeError("expected int for end")

        tv.tv_sec = start.seconds
        tv.tv_usec = start.microseconds
        cscamper_dealias.scamper_dealias_midardisc_round_start_set(self._c, &tv)
        cscamper_dealias.scamper_dealias_midardisc_round_begin_set(self._c, begin)
        cscamper_dealias.scamper_dealias_midardisc_round_end_set(self._c, end)

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_dealias.scamper_dealias_midardisc_round_free(self._c)

    def __str__(self):
        cdef const timeval *start
        cdef uint32_t begin
        cdef uint32_t end
        start = cscamper_dealias.scamper_dealias_midardisc_round_start_get(self._c)
        begin = cscamper_dealias.scamper_dealias_midardisc_round_begin_get(self._c)
        end = cscamper_dealias.scamper_dealias_midardisc_round_end_get(self._c)
        return f"{start.tv_sec}.{start.tv_usec:06}:{begin}:{end}"

    @property
    def start(self):
        """
        get method to get the time this round should start, relative to other rounds.

        :returns: the start time
        :rtype: timedelta
        """
        tv = cscamper_dealias.scamper_dealias_midardisc_round_start_get(self._c)
        return datetime.timedelta(seconds=tv.tv_sec, microseconds=tv.tv_usec)

    @property
    def begin(self):
        """
        get method to obtain the begin index of the probedefs to use for this round.

        :returns: the begin index
        :rtype: int
        """
        return cscamper_dealias.scamper_dealias_midardisc_round_begin_get(self._c)

    @property
    def end(self):
        """
        get method to obtain the end index of the probedefs to use for this round.

        :returns: the end index
        :rtype: int
        """
        return cscamper_dealias.scamper_dealias_midardisc_round_end_get(self._c)

cdef class ScamperDealiasProbedef:
    """
    The :class:`ScamperDealiasProbedef` object stores information for a set of
    related alias resolution probes.  This class implements __str__ to
    render strings that scamper accepts, and __repr__ to show the object.
    The :class:`ScamperDealiasProbedef` constructor takes the following
    parameters; the first parameter is mandatory, but the remainder
    are optional.

    - method: a string identifying the name of the probing strategy to use.
    - src: the source IP address to use when probing.  This can be a string, \
    or a :class:`ScamperAddr`.
    - dst: the destination IP address to probe.  This can be a string, \
    or a :class:`ScamperAddr`.
    - ttl: the IP TTL to sent in probe packets.
    - size: the size of packets to send.  The size includes the IP and \
    transport headers.
    - sport: the source port value to use, for TCP or UDP probe methods.
    - dport: the destination port value to use, for TCP or UDP probe methods.
    - icmp_id: the ID value to use in probes, for ICMP probe methods.
    - icmp_sum: the checksum to use in an ICMP probe.
    """
    cdef cscamper_dealias.scamper_dealias_probedef_t *_c

    def __init__(self, method, src=None, dst=None, ttl=None, size=None,
                 sport=None, dport=None, icmp_id=None, icmp_sum=None):
        cdef cscamper_addr.scamper_addr_t *a

        self._c = cscamper_dealias.scamper_dealias_probedef_alloc()
        if self._c == NULL:
            raise MemoryError

        # check that the method is valid; the rest of the methods depend
        # on the method
        if not isinstance(method, str):
            raise TypeError("expected string for method")
        m = method.encode('UTF-8')
        if cscamper_dealias.scamper_dealias_probedef_method_set(self._c,m) != 0:
            raise ValueError(f"unknown method {method}")

        # set the addresses, if provided
        if src is not None:
            if isinstance(src, ScamperAddr) and (<ScamperAddr>src)._c != NULL:
                a = (<ScamperAddr>src)._c
                if cscamper_dealias.scamper_dealias_probedef_src_set(self._c, a) != 0:
                    raise ValueError(f"invalid address {src}")
            elif isinstance(src, str):
                a = cscamper_addr.scamper_addr_fromstr(0, src.encode('UTF-8'))
                if a == NULL:
                    raise ValueError(f"invalid address {src}")
                x = cscamper_dealias.scamper_dealias_probedef_src_set(self._c, a)
                cscamper_addr.scamper_addr_free(a)
                if x != 0:
                    raise ValueError(f"invalid address {src}")
            else:
                raise TypeError("invalid src")
        if dst is not None:
            if isinstance(dst, ScamperAddr) and (<ScamperAddr>dst)._c != NULL:
                a = (<ScamperAddr>dst)._c
                if cscamper_dealias.scamper_dealias_probedef_dst_set(self._c, a) != 0:
                    raise ValueError(f"invalid address {dst}")
            elif isinstance(dst, str):
                a = cscamper_addr.scamper_addr_fromstr(0, dst.encode('UTF-8'))
                if a == NULL:
                    raise ValueError(f"invalid address {dst}")
                x = cscamper_dealias.scamper_dealias_probedef_dst_set(self._c, a)
                cscamper_addr.scamper_addr_free(a)
                if x != 0:
                    raise ValueError(f"invalid address {dst}")
            else:
                raise TypeError("invalid dst")

        # set other IP-header-level fields
        if ttl is not None:
            ttl = int(ttl)
            if ttl < 0 or ttl > 255:
                raise ValueError("invalid TTL")
            cscamper_dealias.scamper_dealias_probedef_ttl_set(self._c, ttl)
        if size is not None:
            size = int(size)
            if size < 0 or size > 65535:
                raise ValueError("invalid size")
            cscamper_dealias.scamper_dealias_probedef_size_set(self._c, size)

        # set transport header values
        udp = cscamper_dealias.scamper_dealias_probedef_udp_get(self._c)
        icmp = cscamper_dealias.scamper_dealias_probedef_icmp_get(self._c)
        tcp = cscamper_dealias.scamper_dealias_probedef_tcp_get(self._c)
        if dport is not None:
            dport = int(dport)
            if dport < 0 or dport > 65535:
                raise ValueError("invalid dport")
            if udp != NULL:
                cscamper_dealias.scamper_dealias_probedef_udp_dport_set(udp, dport)
            elif tcp != NULL:
                cscamper_dealias.scamper_dealias_probedef_tcp_dport_set(tcp, dport)
            else:
                raise ValueError(f"dport invalid for method {method}")
        if sport is not None:
            sport = int(sport)
            if sport < 0 or sport > 65535:
                raise ValueError("invalid sport")
            if udp != NULL:
                cscamper_dealias.scamper_dealias_probedef_udp_sport_set(udp, sport)
            elif tcp != NULL:
                cscamper_dealias.scamper_dealias_probedef_tcp_sport_set(tcp, sport)
            else:
                raise ValueError(f"sport invalid for method {method}")
        if icmp_id is not None:
            icmp_id = int(icmp_id)
            if icmp_id < 0 or icmp_id > 65535:
                raise ValueError("invalid icmp_id")
            if icmp != NULL:
                cscamper_dealias.scamper_dealias_probedef_icmp_id_set(icmp, icmp_id)
            else:
                raise ValueError(f"icmp_id invalid for method {method}")
        if icmp_sum is not None:
            icmp_sum = int(icmp_sum)
            if icmp_sum < 0 or icmp_sum > 65535:
                raise ValueError("invalid icmp_sum")
            if icmp != NULL:
                cscamper_dealias.scamper_dealias_probedef_icmp_csum_set(icmp, icmp_sum)
            else:
                raise ValueError(f"icmp_sum invalid for method {method}")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_dealias.scamper_dealias_probedef_free(self._c)

    def __str__(self):
        cdef char buf[128]
        if self._c == NULL:
            return None
        cscamper_dealias.scamper_dealias_probedef_method_tostr(self._c, buf,
                                                               sizeof(buf))
        out = "-P " + buf.decode('UTF-8', 'strict')
        ttl = cscamper_dealias.scamper_dealias_probedef_ttl_get(self._c)
        size = cscamper_dealias.scamper_dealias_probedef_size_get(self._c)
        udp = cscamper_dealias.scamper_dealias_probedef_udp_get(self._c)
        icmp = cscamper_dealias.scamper_dealias_probedef_icmp_get(self._c)
        tcp = cscamper_dealias.scamper_dealias_probedef_tcp_get(self._c)
        dst = cscamper_dealias.scamper_dealias_probedef_dst_get(self._c)
        if icmp != NULL:
            csum = cscamper_dealias.scamper_dealias_probedef_icmp_csum_get(icmp)
            if csum != 0:
                out += f" -c {csum}"
        if udp != NULL or tcp != NULL:
            if udp != NULL:
                sport = cscamper_dealias.scamper_dealias_probedef_udp_sport_get(udp)
                dport = cscamper_dealias.scamper_dealias_probedef_udp_dport_get(udp)
            else:
                sport = cscamper_dealias.scamper_dealias_probedef_tcp_sport_get(tcp)
                dport = cscamper_dealias.scamper_dealias_probedef_tcp_dport_get(tcp)
            if dport != 0:
                out += f" -d {dport}"
            if sport != 0:
                out += f" -F {sport}"
        if dst != NULL:
            cscamper_addr.scamper_addr_tostr(dst, buf, sizeof(buf))
            out += " -i " + buf.decode('UTF-8', 'strict')
        if size != 0:
            out += f" -s {size}"
        if ttl != 0:
            out += f" -t {ttl}"
        return out

    def __repr__(self):
        cdef char buf[128]
        if self._c == NULL:
            return None
        ttl = cscamper_dealias.scamper_dealias_probedef_ttl_get(self._c)
        size = cscamper_dealias.scamper_dealias_probedef_size_get(self._c)
        udp = cscamper_dealias.scamper_dealias_probedef_udp_get(self._c)
        icmp = cscamper_dealias.scamper_dealias_probedef_icmp_get(self._c)
        tcp = cscamper_dealias.scamper_dealias_probedef_tcp_get(self._c)
        src = cscamper_dealias.scamper_dealias_probedef_src_get(self._c)
        dst = cscamper_dealias.scamper_dealias_probedef_dst_get(self._c)

        cscamper_dealias.scamper_dealias_probedef_method_tostr(self._c, buf,
                                                               sizeof(buf))
        out = "ScamperDealiasProbedef('" + buf.decode('UTF-8', 'strict') + "'"

        if src != NULL:
            cscamper_addr.scamper_addr_tostr(src, buf, sizeof(buf))
            out += ", src='" + buf.decode('UTF-8', 'strict') + "'"
        if dst != NULL:
            cscamper_addr.scamper_addr_tostr(dst, buf, sizeof(buf))
            out += ", dst='" + buf.decode('UTF-8', 'strict') + "'"
        if ttl != 0:
            out += f", ttl={ttl}"
        if size != 0:
            out += f", size={size}"

        if udp != NULL:
            sp = cscamper_dealias.scamper_dealias_probedef_udp_sport_get(udp)
            dp = cscamper_dealias.scamper_dealias_probedef_udp_dport_get(udp)
            if sp != 0:
                out += f", sport={sp}"
            if dp != 0:
                out += f", dport={dp}"
        elif tcp != NULL:
            sp = cscamper_dealias.scamper_dealias_probedef_tcp_sport_get(tcp)
            dp = cscamper_dealias.scamper_dealias_probedef_tcp_dport_get(tcp)
            if sp != 0:
                out += f", sport={sp}"
            if dp != 0:
                out += f", dport={dp}"
        elif icmp != NULL:
            icmpid = cscamper_dealias.scamper_dealias_probedef_icmp_id_get(icmp)
            csum = cscamper_dealias.scamper_dealias_probedef_icmp_csum_get(icmp)
            if icmpid != 0:
                out += f", icmp_id={icmpid}"
            if csum != 0:
                out += f", icmp_sum={csum}"
        out += ")"
        return out

    @staticmethod
    cdef ScamperDealiasProbedef from_ptr(cscamper_dealias.scamper_dealias_probedef_t *ptr):
        cdef ScamperDealiasProbedef pd
        if ptr == NULL:
            return None
        pd = ScamperDealiasProbedef.__new__(ScamperDealiasProbedef)
        pd._c = cscamper_dealias.scamper_dealias_probedef_use(ptr)
        return pd

    @property
    def dst(self):
        """
        get method to obtain the destination address from a probedef

        :returns: the destination address
        :rtype: ScamperAddr
        """
        c_a = cscamper_dealias.scamper_dealias_probedef_dst_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def src(self):
        """
        get method to obtain the source address from a probedef

        :returns: the source address
        :rtype: ScamperAddr
        """
        c_a = cscamper_dealias.scamper_dealias_probedef_src_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def ttl(self):
        """
        get method to obtain the TTL for this probedef

        :returns: the TTL value
        :rtype: int
        """
        return cscamper_dealias.scamper_dealias_probedef_ttl_get(self._c)

    @property
    def size(self):
        """
        get method to obtain the packet size for this probedef

        :returns: the packet size
        :type: int
        """
        return cscamper_dealias.scamper_dealias_probedef_size_get(self._c)

    @property
    def sport(self):
        """
        get method to obtain the source port for this probedef, if the
        probedef is a TCP or UDP packet.

        :returns: the source port
        :rtype: int
        """
        udp = cscamper_dealias.scamper_dealias_probedef_udp_get(self._c)
        if udp != NULL:
            return cscamper_dealias.scamper_dealias_probedef_udp_sport_get(udp)
        tcp = cscamper_dealias.scamper_dealias_probedef_tcp_get(self._c)
        if tcp != NULL:
            return cscamper_dealias.scamper_dealias_probedef_tcp_sport_get(tcp)
        return None

    @property
    def dport(self):
        """
        get method to obtain the destination port for this probedef, if the
        probedef is a TCP or UDP packet.

        :returns: the destination port
        :rtype: int
        """
        udp = cscamper_dealias.scamper_dealias_probedef_udp_get(self._c)
        if udp != NULL:
            return cscamper_dealias.scamper_dealias_probedef_udp_dport_get(udp)
        tcp = cscamper_dealias.scamper_dealias_probedef_tcp_get(self._c)
        if tcp != NULL:
            return cscamper_dealias.scamper_dealias_probedef_tcp_dport_get(tcp)
        return None

    @property
    def icmp_id(self):
        """
        get method to obtain the ICMP ID for this probedef, if the
        probedef is an ICMP packet

        :returns: the ICMP ID value
        :rtype: int
        """
        icmp = cscamper_dealias.scamper_dealias_probedef_icmp_get(self._c)
        if icmp == NULL:
            return None
        return cscamper_dealias.scamper_dealias_probedef_icmp_id_get(icmp)

    @property
    def icmp_sum(self):
        """
        get method to obtain the ICMP checksum for this probedef, if the
        probedef is an ICMP packet

        :returns: the ICMP checksum value
        :rtype: int
        """
        icmp = cscamper_dealias.scamper_dealias_probedef_icmp_get(self._c)
        if icmp == NULL:
            return None
        return cscamper_dealias.scamper_dealias_probedef_icmp_csum_get(icmp)

    def is_udp(self):
        """
        get method that reports if probe used UDP probes.

        :returns: True if the probe used UDP probes.
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_probedef_is_udp(self._c)

    def is_icmp(self):
        """
        get method that reports if probe used ICMP probes.

        :returns: True if the probe used ICMP probes.
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_probedef_is_icmp(self._c)

    def is_tcp(self):
        """
        get method that reports if probe used TCP probes.

        :returns: True if the probe used TCP probes.
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_probedef_is_tcp(self._c)

class _ScamperDealiasReplyIterator:
    def __init__(self, probe):
        self._probe = probe
        self._i = 0
        self._c = probe.reply_count

    def __iter__(self):
        return self

    def __next__(self):
        if self._i < self._c:
            reply = self._probe.reply(self._i)
            self._i += 1
            return reply
        raise StopIteration

cdef class ScamperDealiasProbe:
    """
    The :class:`ScamperDealiasProbe` object stores information about an
    individual probe sent as part of an alias resolution measurement.
    """
    cdef cscamper_dealias.scamper_dealias_probe_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_dealias.scamper_dealias_probe_free(self._c)

    @staticmethod
    cdef ScamperDealiasProbe from_ptr(cscamper_dealias.scamper_dealias_probe_t *ptr):
        cdef ScamperDealiasProbe p
        if ptr == NULL:
            return None
        p = ScamperDealiasProbe.__new__(ScamperDealiasProbe)
        p._c = cscamper_dealias.scamper_dealias_probe_use(ptr)
        return p

    @property
    def probedef(self):
        """
        get method that returns the probedef associated with this probe

        :returns: the probedef associated with this probe
        :rtype: ScamperDealiasProbedef
        """
        c = cscamper_dealias.scamper_dealias_probe_def_get(self._c)
        return ScamperDealiasProbedef.from_ptr(c)

    @property
    def seq(self):
        """
        get method that returns the sequence among probes sent for this
        alias resolution.

        :returns: the sequence number
        :rtype: int
        """
        return cscamper_dealias.scamper_dealias_probe_seq_get(self._c)

    @property
    def tx(self):
        """
        get method that returns the time when the probe was sent.

        :returns: the transmit time for the probe
        :rtype: datetime
        """
        c = cscamper_dealias.scamper_dealias_probe_tx_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    def reply(self, i=0):
        """
        reply(i=0)
        get method that returns a specific reply for this probe.

        :param int i: the specific reply sought
        :returns: the reply
        :rtype: ScamperDealiasReply
        """
        r = cscamper_dealias.scamper_dealias_probe_reply_get(self._c, i)
        return ScamperDealiasReply.from_ptr(r, self._c)

    @property
    def reply_count(self):
        """
        get method that returns the number of replies received for this probe

        :returns: the number of replies
        :rtype: int
        """
        return cscamper_dealias.scamper_dealias_probe_replyc_get(self._c)

    def replies(self):
        return _ScamperDealiasReplyIterator(self)

    @property
    def ipid(self):
        """
        get method that returns the IPID value set in the probe

        :returns: the IPID value
        :rtype: int
        """
        return cscamper_dealias.scamper_dealias_probe_ipid_get(self._c)

class _ScamperDealiasProbeIterator:
    def __init__(self, dealias):
        self._dealias = dealias
        self._i = 0
        self._c = dealias.probe_count

    def __iter__(self):
        return self

    def __next__(self):
        if self._i < self._c:
            probe = self._dealias.probe(self._i)
            self._i += 1
            return probe
        raise StopIteration

class _ScamperDealiasProbedefIterator:
    def __init__(self, dealias):
        self._dealias = dealias
        self._i = 0
        self._c = dealias.probedef_count

    def __iter__(self):
        return self

    def __next__(self):
        if self._i < self._c:
            pd = self._dealias.probedef(self._i)
            self._i += 1
            return pd
        raise StopIteration

cdef class ScamperDealias:
    """
    The :class:`ScamperDealias` object stores results from an alias resolution
    measurement
    """
    cdef cscamper_dealias.scamper_dealias_t *_c
    cdef public ScamperInst _inst

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_dealias.scamper_dealias_free(self._c)

    @staticmethod
    cdef ScamperDealias from_ptr(cscamper_dealias.scamper_dealias_t *ptr):
        cdef ScamperDealias dealias = ScamperDealias.__new__(ScamperDealias)
        dealias._c = ptr
        return dealias

    @property
    def inst(self):
        """
        get :class:`ScamperInst` associated with this measurement,
        if the measurement was conducted using a :class:`ScamperCtrl`.

        :returns: the instance
        :rtype: ScamperInst
        """
        return self._inst

    @property
    def list(self):
        """
        get list associated with this measurement.

        :returns: the list
        :rtype: ScamperList
        """
        c = cscamper_dealias.scamper_dealias_list_get(self._c)
        return ScamperList.from_ptr(c)

    @property
    def cycle(self):
        """
        get cycle associated with this measurement.

        :returns: the cycle
        :rtype: ScamperCycle
        """
        c = cscamper_dealias.scamper_dealias_cycle_get(self._c)
        return ScamperCycle.from_ptr(c, SCAMPER_FILE_OBJ_CYCLE_DEF)

    @property
    def userid(self):
        """
        get method to obtain the userid parameter.

        :returns: the userid
        :rtype: int
        """
        return cscamper_dealias.scamper_dealias_userid_get(self._c)

    @property
    def start(self):
        """
        get method to obtain the time this measurement started.

        :returns: the start timestamp
        :rtype: datetime
        """
        c = cscamper_dealias.scamper_dealias_start_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    def is_ally(self):
        """
        get method to determine if the alias resolution method was ally

        :returns: True if method was ally
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_method_is_ally(self._c)

    def is_mercator(self):
        """
        get method to determine if the alias resolution method was mercator

        :returns: True if the method was mercator
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_method_is_mercator(self._c)

    def is_prefixscan(self):
        """
        get method to determine if the alias resolution method was prefixscan

        :return: True if the method was prefixscan
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_method_is_prefixscan(self._c)

    def is_radargun(self):
        """
        get method to determine if the alias resolution method was radargun

        :return: True if the method was radargun
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_method_is_radargun(self._c)

    def is_bump(self):
        """
        get method to determine if the alias resolution method was bump

        :return: True if the method was bump
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_method_is_bump(self._c)

    def is_midarest(self):
        """
        get method to determine if the alias resolution method was midarest

        :return: True if the method was midarest
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_method_is_midarest(self._c)

    def is_midardisc(self):
        """
        get method to determine if the alias resolution method was midardisc

        :return: True if the method was midardisc
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_method_is_midardisc(self._c)

    def has_aliases(self):
        """
        get method to determine if the method has aliases to return.  this
        method only works with mercator, ally, and prefixscan.

        :returns True if the measurement has aliases to report
        :rtype: bool
        """
        return cscamper_dealias.scamper_dealias_result_is_aliases(self._c)

    def aliases(self):
        """
        get method to return pairs of aliases inferred, if any.  this method
        only works with mercator, ally, and prefixscan.

        :returns: a pair of :class:`ScamperAddr` structures representing aliases
        :rtype: tuple of ScamperAddr
        """
        if not cscamper_dealias.scamper_dealias_result_is_aliases(self._c):
            return None
        if cscamper_dealias.scamper_dealias_method_is_mercator(self._c):
            mc = cscamper_dealias.scamper_dealias_mercator_get(self._c)
            pd = cscamper_dealias.scamper_dealias_mercator_def_get(mc)
            sa = cscamper_dealias.scamper_dealias_probedef_dst_get(pd)
            probec = cscamper_dealias.scamper_dealias_probec_get(self._c)
            for i in range(probec):
                p = cscamper_dealias.scamper_dealias_probe_get(self._c, i)
                if p == NULL:
                    continue
                replyc = cscamper_dealias.scamper_dealias_probe_replyc_get(p)
                for j in range(replyc):
                    r = cscamper_dealias.scamper_dealias_probe_reply_get(p, j)
                    sb = cscamper_dealias.scamper_dealias_reply_src_get(r)
                    if(cscamper_dealias.scamper_dealias_reply_from_target(p, r)
                       and cscamper_addr.scamper_addr_cmp(sa, sb) != 0):
                        return (ScamperAddr.from_ptr(sa),
                                ScamperAddr.from_ptr(sb))
        elif cscamper_dealias.scamper_dealias_method_is_ally(self._c):
            ally = cscamper_dealias.scamper_dealias_ally_get(self._c)
            pd = cscamper_dealias.scamper_dealias_ally_def0_get(ally)
            addr = cscamper_dealias.scamper_dealias_probedef_dst_get(pd)
            a = ScamperAddr.from_ptr(addr)
            pd = cscamper_dealias.scamper_dealias_ally_def1_get(ally)
            addr = cscamper_dealias.scamper_dealias_probedef_dst_get(pd)
            b = ScamperAddr.from_ptr(addr)
            return (a, b)
        elif cscamper_dealias.scamper_dealias_method_is_prefixscan(self._c):
            pf = cscamper_dealias.scamper_dealias_prefixscan_get(self._c)
            addr = cscamper_dealias.scamper_dealias_prefixscan_a_get(pf)
            a = ScamperAddr.from_ptr(addr)
            addr = cscamper_dealias.scamper_dealias_prefixscan_ab_get(pf)
            b = ScamperAddr.from_ptr(addr)
            return (a, b)
        return None

    def probedef(self, i=0):
        """
        probedef(i=0)
        get method to obtain a specific probedef

        :returns: the probedef requested
        :rtype: ScamperDealiasProbedef
        """
        if i < 0:
            return None
        if cscamper_dealias.scamper_dealias_method_is_mercator(self._c):
            mc = cscamper_dealias.scamper_dealias_mercator_get(self._c)
            if i != 0:
                return None
            c = cscamper_dealias.scamper_dealias_mercator_def_get(mc)
            return ScamperDealiasProbedef.from_ptr(c)
        elif cscamper_dealias.scamper_dealias_method_is_ally(self._c):
            ally = cscamper_dealias.scamper_dealias_ally_get(self._c)
            if i == 0:
                c = cscamper_dealias.scamper_dealias_ally_def0_get(ally)
            elif i == 1:
                c = cscamper_dealias.scamper_dealias_ally_def1_get(ally)
            else:
                return None
            return ScamperDealiasProbedef.from_ptr(c)
        elif cscamper_dealias.scamper_dealias_method_is_prefixscan(self._c):
            pf = cscamper_dealias.scamper_dealias_prefixscan_get(self._c)
            c = cscamper_dealias.scamper_dealias_prefixscan_def_get(pf, i)
            return ScamperDealiasProbedef.from_ptr(c)
        elif cscamper_dealias.scamper_dealias_method_is_radargun(self._c):
            rg = cscamper_dealias.scamper_dealias_radargun_get(self._c)
            c = cscamper_dealias.scamper_dealias_radargun_def_get(rg, i)
            return ScamperDealiasProbedef.from_ptr(c)
        elif cscamper_dealias.scamper_dealias_method_is_midarest(self._c):
            me = cscamper_dealias.scamper_dealias_midarest_get(self._c)
            c = cscamper_dealias.scamper_dealias_midarest_def_get(me, i)
            return ScamperDealiasProbedef.from_ptr(c)
        elif cscamper_dealias.scamper_dealias_method_is_midardisc(self._c):
            md = cscamper_dealias.scamper_dealias_midardisc_get(self._c)
            c = cscamper_dealias.scamper_dealias_midardisc_def_get(md, i)
            return ScamperDealiasProbedef.from_ptr(c)
        return None

    @property
    def probedef_count(self):
        """
        get method to obtain the number of probedefs for this dealias
        measurement.

        :returns: the number of probedefs defined in this measurement.
        :rtype: int
        """
        if cscamper_dealias.scamper_dealias_method_is_mercator(self._c):
            return 1
        elif cscamper_dealias.scamper_dealias_method_is_ally(self._c):
            return 2
        elif cscamper_dealias.scamper_dealias_method_is_prefixscan(self._c):
            pf = cscamper_dealias.scamper_dealias_prefixscan_get(self._c)
            if pf != NULL:
                return cscamper_dealias.scamper_dealias_prefixscan_defc_get(pf)
        elif cscamper_dealias.scamper_dealias_method_is_radargun(self._c):
            rg = cscamper_dealias.scamper_dealias_radargun_get(self._c)
            if rg != NULL:
                return cscamper_dealias.scamper_dealias_radargun_defc_get(rg)
        elif cscamper_dealias.scamper_dealias_method_is_bump(self._c):
            return 2
        elif cscamper_dealias.scamper_dealias_method_is_midarest(self._c):
            me = cscamper_dealias.scamper_dealias_midarest_get(self._c)
            if me != NULL:
                return cscamper_dealias.scamper_dealias_midarest_defc_get(me)
        elif cscamper_dealias.scamper_dealias_method_is_midardisc(self._c):
            md = cscamper_dealias.scamper_dealias_midardisc_get(self._c)
            if md != NULL:
                return cscamper_dealias.scamper_dealias_midardisc_defc_get(md)
        return None

    def probedefs(self):
        """
        get method to obtain an iterator to process available probedefs.

        :returns: an iterator to access the probedefs.
        :rtype: _ScamperDealiasProbedefIterator
        """
        return _ScamperDealiasProbedefIterator(self)

    def probe(self, i=0):
        """
        probe(i=0)
        get method to obtain a specific probe

        :returns: the probe requested
        :rtype: ScamperDealiasProbe
        """
        if i < 0:
            return None
        p = cscamper_dealias.scamper_dealias_probe_get(self._c, i)
        return ScamperDealiasProbe.from_ptr(p)

    @property
    def probe_count(self):
        """
        get method to obtain the number of probes sent in this dealias
        measurement.

        :returns: the number of probes sent
        :rtype: int
        """
        return cscamper_dealias.scamper_dealias_probec_get(self._c)

    def probes(self):
        """
        get method to obtain an iterator to process available probes.

        :returns: an iterator to access the probedefs.
        :rtype: _ScamperDealiasProbeIterator
        """
        return _ScamperDealiasProbeIterator(self)

    @property
    def startat(self):
        """
        get method to obtain the scheduled time for the measurement.

        :returns: the scheduled time for the measurement.
        :rtype: datetime
        """
        if cscamper_dealias.scamper_dealias_method_is_midardisc(self._c):
            md = cscamper_dealias.scamper_dealias_midardisc_get(self._c)
            tv = cscamper_dealias.scamper_dealias_midardisc_startat_get(md)
        else:
            return None
        if tv == NULL:
            return None
        t = time.gmtime(tv.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], tv.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def wait_probe(self):
        """
        get method to obtain the minimum time to wait between probes.

        :returns: the minimum time to wait between probes
        :rtype: timedelta
        """
        if cscamper_dealias.scamper_dealias_method_is_mercator(self._c):
            mc = cscamper_dealias.scamper_dealias_mercator_get(self._c)
            if mc == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_mercator_wait_timeout_get(mc)
        elif cscamper_dealias.scamper_dealias_method_is_ally(self._c):
            ally = cscamper_dealias.scamper_dealias_ally_get(self._c)
            if ally == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_ally_wait_probe_get(ally)
        elif cscamper_dealias.scamper_dealias_method_is_prefixscan(self._c):
            pf = cscamper_dealias.scamper_dealias_prefixscan_get(self._c)
            if pf == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_prefixscan_wait_probe_get(pf)
        elif cscamper_dealias.scamper_dealias_method_is_radargun(self._c):
            rg = cscamper_dealias.scamper_dealias_radargun_get(self._c)
            if rg == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_radargun_wait_probe_get(rg)
        elif cscamper_dealias.scamper_dealias_method_is_bump(self._c):
            bump = cscamper_dealias.scamper_dealias_bump_get(self._c)
            if bump == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_bump_wait_probe_get(bump)
        elif cscamper_dealias.scamper_dealias_method_is_midarest(self._c):
            me = cscamper_dealias.scamper_dealias_midarest_get(self._c)
            if me == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_midarest_wait_probe_get(me)
        else:
            return None

        return datetime.timedelta(seconds=tv.tv_sec, microseconds=tv.tv_usec)

    @property
    def wait_round(self):
        """
        get method to obtain the minimum time to wait between rounds.

        :returns: the minimum time to wait between rounds
        :rtype: timedelta
        """
        if cscamper_dealias.scamper_dealias_method_is_radargun(self._c):
            rg = cscamper_dealias.scamper_dealias_radargun_get(self._c)
            if rg == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_radargun_wait_round_get(rg)
        elif cscamper_dealias.scamper_dealias_method_is_midarest(self._c):
            me = cscamper_dealias.scamper_dealias_midarest_get(self._c)
            if me == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_midarest_wait_round_get(me)
        else:
            return None

        return datetime.timedelta(seconds=tv.tv_sec, microseconds=tv.tv_usec)

    @property
    def wait_timeout(self):
        """
        get method to obtain the length of time to wait before declaring
        a probe lost.

        :returns: the timeout value.
        :rtype: timedelta
        """
        if cscamper_dealias.scamper_dealias_method_is_mercator(self._c):
            mc = cscamper_dealias.scamper_dealias_mercator_get(self._c)
            if mc == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_mercator_wait_timeout_get(mc)
        elif cscamper_dealias.scamper_dealias_method_is_ally(self._c):
            ally = cscamper_dealias.scamper_dealias_ally_get(self._c)
            if ally == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_ally_wait_timeout_get(ally)
        elif cscamper_dealias.scamper_dealias_method_is_prefixscan(self._c):
            pf = cscamper_dealias.scamper_dealias_prefixscan_get(self._c)
            if pf == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_prefixscan_wait_timeout_get(pf)
        elif cscamper_dealias.scamper_dealias_method_is_radargun(self._c):
            rg = cscamper_dealias.scamper_dealias_radargun_get(self._c)
            if rg == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_radargun_wait_timeout_get(rg)
        elif cscamper_dealias.scamper_dealias_method_is_midarest(self._c):
            me = cscamper_dealias.scamper_dealias_midarest_get(self._c)
            if me == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_midarest_wait_timeout_get(me)
        elif cscamper_dealias.scamper_dealias_method_is_midardisc(self._c):
            md = cscamper_dealias.scamper_dealias_midardisc_get(self._c)
            if md == NULL:
                return None
            tv = cscamper_dealias.scamper_dealias_midardisc_wait_timeout_get(md)
        else:
            return None

        return datetime.timedelta(seconds=tv.tv_sec, microseconds=tv.tv_usec)

####
#### Scamper Neighbourdisc Object
####
cdef class ScamperNeighbourdisc:
    cdef cscamper_neighbourdisc.scamper_neighbourdisc_t *_c
    cdef public ScamperInst _inst

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_neighbourdisc.scamper_neighbourdisc_free(self._c)

    @staticmethod
    cdef ScamperNeighbourdisc from_ptr(cscamper_neighbourdisc.scamper_neighbourdisc_t *ptr):
        cdef ScamperNeighbourdisc nd
        nd = ScamperNeighbourdisc.__new__(ScamperNeighbourdisc)
        nd._c = ptr
        return nd

    @property
    def inst(self):
        """
        get :class:`ScamperInst` associated with this measurement,
        if the measurement was conducted using a :class:`ScamperCtrl`.

        :returns: the instance
        :rtype: ScamperInst
        """
        return self._inst

####
#### Scamper Tbit Object
####

cdef class ScamperTbit:
    cdef cscamper_tbit.scamper_tbit_t *_c
    cdef public ScamperInst _inst

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_tbit.scamper_tbit_free(self._c)

    @staticmethod
    cdef ScamperTbit from_ptr(cscamper_tbit.scamper_tbit_t *ptr):
        cdef ScamperTbit tbit = ScamperTbit.__new__(ScamperTbit)
        tbit._c = ptr
        return tbit

    @property
    def inst(self):
        """
        get :class:`ScamperInst` associated with this measurement,
        if the measurement was conducted using a :class:`ScamperCtrl`.

        :returns: the instance
        :rtype: ScamperInst
        """
        return self._inst

####
#### Scamper Sting Object
####

cdef class ScamperSting:
    cdef cscamper_sting.scamper_sting_t *_c
    cdef public ScamperInst _inst

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_sting.scamper_sting_free(self._c)

    @staticmethod
    cdef ScamperSting from_ptr(cscamper_sting.scamper_sting_t *ptr):
        cdef ScamperSting sting = ScamperSting.__new__(ScamperSting)
        sting._c = ptr
        return sting

    @property
    def inst(self):
        """
        get :class:`ScamperInst` associated with this measurement,
        if the measurement was conducted using a :class:`ScamperCtrl`.

        :returns: the instance
        :rtype: ScamperInst
        """
        return self._inst

####
#### Scamper Sniff Object
####

cdef class ScamperSniffPkt:
    """
    :class:`ScamperSniffPkt` is used by scamper to store information about
    a single packet captured in a :class:`ScamperSniff`.
    """
    cdef cscamper_sniff.scamper_sniff_pkt_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_sniff.scamper_sniff_pkt_free(self._c)

    @staticmethod
    cdef ScamperSniffPkt from_ptr(cscamper_sniff.scamper_sniff_pkt_t *ptr):
        cdef ScamperSniffPkt pkt = ScamperSniffPkt.__new__(ScamperSniffPkt)
        pkt._c = cscamper_sniff.scamper_sniff_pkt_use(ptr)
        return pkt

    @property
    def rx(self):
        """
        get method that returns the time the packet was received.

        :returns: the time when this packet was received
        :rtype: datetime
        """
        c = cscamper_sniff.scamper_sniff_pkt_tv_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def data(self):
        """
        get method to obtain the contents of the packet

        :returns: contents of the packet including IP header
        :rtype: bytes
        """
        cdef const uint8_t *data
        data = cscamper_sniff.scamper_sniff_pkt_data_get(self._c)
        length = cscamper_sniff.scamper_sniff_pkt_len_get(self._c)
        if data == NULL or length == 0:
            return None
        return data[:length]

cdef class ScamperSniff:
    """
    :class:`ScamperSniff` is used by scamper to store information about
    packets captured in a :class:`ScamperSniff` measurement.  Each
    packet is available in a :class:`ScamperSniffPkt` object.
    """
    cdef cscamper_sniff.scamper_sniff_t *_c
    cdef uint32_t _i, _pktc
    cdef public ScamperInst _inst

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_sniff.scamper_sniff_free(self._c)

    def __len__(self):
        return self._pktc

    def __iter__(self):
        self._i = 0
        return self

    def __next__(self):
        if self._i >= self._pktc:
            raise StopIteration
        c = cscamper_sniff.scamper_sniff_pkt_get(self._c, self._i)
        self._i = self._i + 1
        return ScamperSniffPkt.from_ptr(c)

    @staticmethod
    cdef ScamperSniff from_ptr(cscamper_sniff.scamper_sniff_t *ptr):
        cdef ScamperSniff sniff = ScamperSniff.__new__(ScamperSniff)
        sniff._c = ptr
        sniff._pktc = cscamper_sniff.scamper_sniff_pktc_get(ptr)
        return sniff

    @property
    def inst(self):
        """
        get :class:`ScamperInst` associated with this measurement,
        if the measurement was conducted using a :class:`ScamperCtrl`.

        :returns: the instance
        :rtype: ScamperInst
        """
        return self._inst

    @property
    def list(self):
        """
        get list associated with this measurement.

        :returns: the list
        :rtype: ScamperList
        """
        c = cscamper_sniff.scamper_sniff_list_get(self._c)
        return ScamperList.from_ptr(c)

    @property
    def cycle(self):
        """
        get cycle associated with this measurement.

        :returns: the cycle
        :rtype: ScamperCycle
        """
        c = cscamper_sniff.scamper_sniff_cycle_get(self._c)
        return ScamperCycle.from_ptr(c, SCAMPER_FILE_OBJ_CYCLE_DEF)

    @property
    def stop_reason(self):
        """
        get method to obtain the stop reason.

        :returns: the stop reason
        :rtype: ScamperSniffStop
        """
        c = cscamper_sniff.scamper_sniff_stop_reason_get(self._c)
        return ScamperSniffStop(c)

    @property
    def userid(self):
        """
        get method to obtain the userid parameter.

        :returns: the userid
        :rtype: int
        """
        return cscamper_sniff.scamper_sniff_userid_get(self._c)

    @property
    def src(self):
        """
        get method to obtain the source address of the interface listened
        on.

        :returns: the source address
        :rtype: ScamperAddr
        """
        c = cscamper_sniff.scamper_sniff_src_get(self._c)
        return ScamperAddr.from_ptr(c)

    @property
    def start(self):
        """
        get method to obtain the time this measurement started.

        :returns: the start timestamp
        :rtype: datetime
        """
        c = cscamper_sniff.scamper_sniff_start_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def finish(self):
        """
        get method to obtain the time this measurement finished.

        :returns: the finish timestamp
        :rtype: datetime
        """
        c = cscamper_sniff.scamper_sniff_finish_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def limit_pkt_count(self):
        """
        get method to obtain the maximum number of packets that this sniff
        measurement would have waited for before finishing.

        :returns: the packet limit
        :rtype: int
        """
        return cscamper_sniff.scamper_sniff_limit_pktc_get(self._c)

    @property
    def limit_time(self):
        """
        get method to obtain the maximum length of time that this sniff
        measurement would have waited for before finishing.

        :returns: the time limit
        :rtype: timedelta
        """
        c = cscamper_sniff.scamper_sniff_limit_time_get(self._c)
        return datetime.timedelta(seconds=c.tv_sec,
                                  microseconds=c.tv_usec)

    @property
    def icmp_id(self):
        """
        get method to obtain the ICMP ID sniffed

        :returns: the ICMP ID sniffed
        :rtype: int
        """
        return cscamper_sniff.scamper_sniff_icmpid_get(self._c)

    @property
    def pkt_count(self):
        """
        get method to obtain the number of packets captured

        :returns: the number of captured packets
        :rtype: int
        """
        return cscamper_sniff.scamper_sniff_pktc_get(self._c)

    def pkt(self, i=0):
        """
        pkt(i=0)
        get method to obtain a specific packet

        :returns: the requested packet
        :rtype: ScamperSniffPkt
        """
        c = cscamper_sniff.scamper_sniff_pkt_get(self._c, i)
        return ScamperSniffPkt.from_ptr(c)

####
#### Scamper Host Object
####

cdef class ScamperHostMX:
    """
    The :class:`ScamperHostMX` object stores fields from the MX resource record.
    """
    cdef cscamper_host.scamper_host_rr_mx_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_host.scamper_host_rr_mx_free(self._c)

    @staticmethod
    cdef ScamperHostMX from_ptr(cscamper_host.scamper_host_rr_mx_t *ptr):
        cdef ScamperHostMX mx
        if ptr == NULL:
            return None
        mx = ScamperHostMX.__new__(ScamperHostMX)
        mx._c = cscamper_host.scamper_host_rr_mx_use(ptr)
        return mx

    @property
    def pref(self):
        """
        get method to obtain the preference value as encoded in the
        preference field of the MX resource record.

        :returns: the preference value
        :rtype: int
        """
        return cscamper_host.scamper_host_rr_mx_preference_get(self._c)

    @property
    def exch(self):
        """
        get method to obtain the exchange string as encoded in the
        exchange field of the MX resource record.

        :returns: the mail exchanger
        :rtype: string
        """
        mx_exch = cscamper_host.scamper_host_rr_mx_exchange_get(self._c)
        if mx_exch == NULL:
            return None
        return mx_exch.decode('UTF-8', 'strict')

cdef class ScamperHostSOA:
    """
    The :class:`ScamperHostSOA` object stores fields from the SOA resource
    record.
    """
    cdef cscamper_host.scamper_host_rr_soa_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_host.scamper_host_rr_soa_free(self._c)

    @staticmethod
    cdef ScamperHostSOA from_ptr(cscamper_host.scamper_host_rr_soa_t *ptr):
        cdef ScamperHostSOA soa
        if ptr == NULL:
            return None
        soa = ScamperHostSOA.__new__(ScamperHostSOA)
        soa._c = cscamper_host.scamper_host_rr_soa_use(ptr)
        return soa

    @property
    def mname(self):
        """
        get method to obtain the primary master name server for the zone,
        as encoded in the mname field of the SOA.

        :returns: the name server
        :rtype: string
        """
        mname = cscamper_host.scamper_host_rr_soa_mname_get(self._c)
        if mname == NULL:
            return None
        return mname.decode('UTF-8', 'strict')

    @property
    def rname(self):
        """
        get method to obtain the email address of the administrator
        responsible for the zone, as encoded in the rname field of the
        SOA.

        :returns: the email address
        :rtype: string
        """
        rname = cscamper_host.scamper_host_rr_soa_rname_get(self._c)
        if rname == NULL:
            return None
        return rname.decode('UTF-8', 'strict')

    @property
    def serial(self):
        """
        get method to obtain the serial number for the zone, as encoded
        in the serial field of the SOA.

        :returns: the serial number
        :rtype: int
        """
        return cscamper_host.scamper_host_rr_soa_serial_get(self._c)

    @property
    def refresh(self):
        """
        get method to obtain the time interval before the zone should
        be refreshed from the master, as encoded in the refresh field of
        the SOA.

        :returns: the refresh interval
        :rtype: int
        """
        return cscamper_host.scamper_host_rr_soa_refresh_get(self._c)

    @property
    def retry(self):
        """
        get method to obtain the time interval that should elapse before
        a failed refresh should be retried, as encoded in the retry field
        of the SOA.

        :returns: the retry interval
        :rtype: int
        """
        return cscamper_host.scamper_host_rr_soa_retry_get(self._c)

    @property
    def expire(self):
        """
        get method to obtain the upper limit on the time interval that
        can elapse before the zone is no longer authoritative, as encoded
        in the expire field of the SOA.

        :returns: the expire interval
        :rtype: int
        """
        return cscamper_host.scamper_host_rr_soa_expire_get(self._c)

    @property
    def minimum(self):
        """
        get method to obtain the minimum TTL field that should be
        exported with any resource record from this zone, as encoded
        in the minimum field of the SOA.

        :returns: the minimum TTL
        :rtype: int
        """
        return cscamper_host.scamper_host_rr_soa_minimum_get(self._c)

cdef class ScamperHostTXT:
    """
    The :class:`ScamperHostTXT` object stores fields from the TXT resource
    record.
    """
    cdef cscamper_host.scamper_host_rr_txt_t *_c
    cdef uint16_t _i

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_host.scamper_host_rr_txt_free(self._c)

    @staticmethod
    cdef ScamperHostTXT from_ptr(cscamper_host.scamper_host_rr_txt_t *ptr):
        cdef ScamperHostTXT txt
        if ptr == NULL:
            return None
        txt = ScamperHostTXT.__new__(ScamperHostTXT)
        txt._c = cscamper_host.scamper_host_rr_txt_use(ptr)
        return txt

    def __iter__(self):
        self._i = 0
        return self

    def __next__(self):
        strc = cscamper_host.scamper_host_rr_txt_strc_get(self._c)
        while self._i < strc:
            txt = cscamper_host.scamper_host_rr_txt_str_get(self._c, self._i)
            self._i += 1
            if txt != NULL:
                return txt.decode('UTF-8', 'strict')
        raise StopIteration

    @property
    def strc(self):
        """
        get method to obtain the number of strings in this TXT record.

        :returns: the number of strings
        :rtype: int
        """
        return cscamper_host.scamper_host_rr_txt_strc_get(self._c)

    def str(self, i):
        """
        get method to obtain the number of strings in this TXT record.

        :param int i: The string of interest
        :returns: the string
        :rtype: string
        """
        txt = cscamper_host.scamper_host_rr_txt_str_get(self._c, i)
        if txt == NULL:
            return None
        return txt.decode('UTF-8', 'strict')

cdef class ScamperHostRR:
    """
    The :class:`ScamperHostRR` object stores fields from a DNS resource record.
    """
    cdef cscamper_host.scamper_host_rr_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_host.scamper_host_rr_free(self._c)

    def __str__(self):
        cdef char qclass[128]
        cdef char qtype[128]
        cdef const char *name
        cdef uint16_t class_n, type_n
        cdef uint32_t ttl

        name = cscamper_host.scamper_host_rr_name_get(self._c)
        class_n = cscamper_host.scamper_host_rr_class_get(self._c)
        type_n = cscamper_host.scamper_host_rr_type_get(self._c)
        ttl = cscamper_host.scamper_host_rr_ttl_get(self._c)
        cscamper_host.scamper_host_qclass_tostr(class_n, qclass, sizeof(qclass))
        cscamper_host.scamper_host_qtype_tostr(type_n, qtype, sizeof(qtype))

        sa = cscamper_host.scamper_host_rr_addr_get(self._c)
        rrstr = cscamper_host.scamper_host_rr_str_get(self._c)
        mx = cscamper_host.scamper_host_rr_mx_get(self._c)
        soa = cscamper_host.scamper_host_rr_soa_get(self._c)
        txt = cscamper_host.scamper_host_rr_txt_get(self._c)
        if sa != NULL:
            x = str(ScamperAddr.from_ptr(sa))
        elif rrstr != NULL:
            x = rrstr.decode('UTF-8', 'strict')
        elif mx != NULL:
            mx_pref = cscamper_host.scamper_host_rr_mx_preference_get(mx)
            mx_exch = cscamper_host.scamper_host_rr_mx_exchange_get(mx)
            x = "{} {}".format(mx_pref, mx_exch.decode('UTF-8', 'strict'))
        elif soa != NULL:
            soa_mname = cscamper_host.scamper_host_rr_soa_mname_get(soa)
            soa_rname = cscamper_host.scamper_host_rr_soa_rname_get(soa)
            soa_serial = cscamper_host.scamper_host_rr_soa_serial_get(soa)
            soa_refresh = cscamper_host.scamper_host_rr_soa_refresh_get(soa)
            soa_retry = cscamper_host.scamper_host_rr_soa_retry_get(soa)
            soa_expire = cscamper_host.scamper_host_rr_soa_expire_get(soa)
            soa_minimum = cscamper_host.scamper_host_rr_soa_minimum_get(soa)
            x = "{} {} {} {} {} {} {}".format(soa_mname.decode('UTF-8',
                                                               'strict'),
                                              soa_rname.decode('UTF-8',
                                                               'strict'),
                                              soa_serial, soa_refresh,
                                              soa_retry, soa_expire,
                                              soa_minimum)
        elif txt != NULL:
            txt_strc = cscamper_host.scamper_host_rr_txt_strc_get(txt)
            x = ""
            for i in range(txt_strc):
                txt_str = cscamper_host.scamper_host_rr_txt_str_get(txt, i)
                if txt_str != NULL:
                    if x != "":
                        x = x + " "
                    x = x + "\"" + txt_str.decode('UTF-8', 'strict') + "\""
        else:
            x = "not implemented"

        out = "{} {} {} {} {}".format(name.decode('UTF-8', 'strict'), ttl,
                                      qclass.decode('UTF-8', 'strict'),
                                      qtype.decode('UTF-8', 'strict'), x)

        return out

    @staticmethod
    cdef ScamperHostRR from_ptr(cscamper_host.scamper_host_rr_t *ptr):
        cdef ScamperHostRR rr
        if ptr == NULL:
            return None
        rr = ScamperHostRR.__new__(ScamperHostRR)
        rr._c = cscamper_host.scamper_host_rr_use(ptr)
        return rr

    @property
    def rclass(self):
        """
        get method to obtain the numeric class value of this RR

        :returns: class value
        :rtype: int
        """
        return cscamper_host.scamper_host_rr_class_get(self._c)

    @property
    def rtype(self):
        """
        get method to obtain the numeric type value of this RR

        :returns: type value
        :rtype: int
        """
        return cscamper_host.scamper_host_rr_type_get(self._c)

    @property
    def ttl(self):
        """
        get method to obtain the TTL value of this RR

        :returns: TTL value
        :rtype: int
        """
        return cscamper_host.scamper_host_rr_ttl_get(self._c)

    @property
    def name(self):
        """
        get method to obtain the name queried for this RR

        :returns: name
        :rtype: string
        """
        name = cscamper_host.scamper_host_rr_name_get(self._c)
        if name == NULL:
            return None
        return name.decode('UTF-8', 'strict')

    @property
    def addr(self):
        """
        get method to obtain the address contained in the RR, if the
        record contains an address (A or AAAA)

        :returns: the address value
        :rtype: ScamperAddr
        """
        sa = cscamper_host.scamper_host_rr_addr_get(self._c)
        return ScamperAddr.from_ptr(sa)

    @property
    def ns(self):
        """
        get method to obtain the name server reported in the RR.

        :returns: the NS reported
        :rtype: string
        """
        cls = cscamper_host.scamper_host_rr_class_get(self._c)
        typ = cscamper_host.scamper_host_rr_type_get(self._c)
        if cls != SCAMPER_HOST_CLASS_IN or typ != ScamperHostType.NS:
            return None
        x = cscamper_host.scamper_host_rr_str_get(self._c)
        return x.decode('UTF-8', 'strict')

    @property
    def cname(self):
        """
        get method to obtain the canonical name (cname) reported

        :returns: the cname
        :rtype: string
        """
        cls = cscamper_host.scamper_host_rr_class_get(self._c)
        typ = cscamper_host.scamper_host_rr_type_get(self._c)
        if cls != SCAMPER_HOST_CLASS_IN or typ != ScamperHostType.CNAME:
            return None
        x = cscamper_host.scamper_host_rr_str_get(self._c)
        return x.decode('UTF-8', 'strict')

    @property
    def ptr(self):
        """
        get method to obtain the PTR value in the RR

        :returns: the PTR value
        :rtype: string
        """
        cls = cscamper_host.scamper_host_rr_class_get(self._c)
        typ = cscamper_host.scamper_host_rr_type_get(self._c)
        if cls != SCAMPER_HOST_CLASS_IN or typ != ScamperHostType.PTR:
            return None
        x = cscamper_host.scamper_host_rr_str_get(self._c)
        return x.decode('UTF-8', 'strict')

    @property
    def mx(self):
        """
        get method to obtain an object that contains the MX record.

        :returns: the MX record
        :rtype: ScamperHostMX
        """
        mx = cscamper_host.scamper_host_rr_mx_get(self._c)
        return ScamperHostMX.from_ptr(mx)

    @property
    def soa(self):
        """
        get method to obtain an object that contains the SOA record.

        :returns: the SOA record
        :rtype: ScamperHostSOA
        """
        soa = cscamper_host.scamper_host_rr_soa_get(self._c)
        return ScamperHostSOA.from_ptr(soa)

    @property
    def txt(self):
        """
        get method to obtain an object that contains the TXT record.

        :returns: the TXT record
        :rtype: ScamperHostTXT
        """
        txt = cscamper_host.scamper_host_rr_txt_get(self._c)
        return ScamperHostTXT.from_ptr(txt)

class _ScamperHostRRIterator:
    """
    The :class:`_ScamperHostRRIterator` class provides a convenient
    interface to iterate over a given section in a DNS response.
    """
    def __init__(self, query, section, rrtypes):
        """
        Construct a _ScamperHostRRIterator object.

        :param ScamperHostQuery query: The query to iterate over
        :param int section: which section (0=an, 1=ns, 2=ar) to return RRs
        :returns: an initialized iterator
        :rtype: _ScamperHostRRIterator
        """
        self._query = query
        self._section = section
        self._index = 0
        self._count = 0
        self._rrtypes = None
        if query is not None:
            if section == 0:
                self._count = query.ancount
            elif section == 1:
                self._count = query.nscount
            else:
                self._count = query.arcount
        if rrtypes is not None:
            self._rrtypes = {}
            for rrtype in rrtypes:
                if not isinstance(rrtype, str):
                    raise ValueError("expected str in rrtypes")
                rrtl = rrtype.lower()
                if rrtl == 'a':
                    self._rrtypes[1] = 1
                elif rrtl == 'aaaa':
                    self._rrtypes[28] = 1
                elif rrtl == 'ptr':
                    self._rrtypes[12] = 1
                elif rrtl == 'mx':
                    self._rrtypes[15] = 1
                elif rrtl == 'ns':
                    self._rrtypes[2] = 1
                elif rrtl == 'soa':
                    self._rrtypes[6] = 1
                elif rrtl == 'txt':
                    self._rrtypes[16] = 1
                else:
                    raise ValueError(f"cannot filter {rrtype}")

    def __iter__(self):
        return self

    def __next__(self):
        while self._index < self._count:
            if self._section == 0:
                rr = self._query.an(self._index)
            elif self._section == 1:
                rr = self._query.ns(self._index)
            else:
                rr = self._query.ar(self._index)
            self._index += 1
            if (self._rrtypes is None or
                (rr.rclass == 1 and rr.rtype in self._rrtypes)):
                return rr
        raise StopIteration

cdef class ScamperHostQuery:
    """
    The :class:`ScamperHostQuery` object stores information about a DNS query.
    """
    cdef cscamper_host.scamper_host_query_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_host.scamper_host_query_free(self._c)

    @staticmethod
    cdef ScamperHostQuery from_ptr(cscamper_host.scamper_host_query_t *ptr):
        cdef ScamperHostQuery q
        if ptr == NULL:
            return None
        q = ScamperHostQuery.__new__(ScamperHostQuery)
        q._c = cscamper_host.scamper_host_query_use(ptr)
        return q

    @property
    def tx(self):
        """
        get method that returns the time when the DNS query was made.

        :returns: the transmit time for the query
        :rtype: datetime
        """
        c = cscamper_host.scamper_host_query_tx_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def rx(self):
        """
        get method that returns the time when a DNS response was received.

        :returns: the time when a response was received, or None if no response
        :rtype: datetime
        """
        c = cscamper_host.scamper_host_query_rx_get(self._c)
        if c == NULL or (c.tv_sec == 0 and c.tv_usec == 0):
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def rtt(self):
        """
        get method that returns the the delay between query and response
        for the query

        :returns: the delay between query and response
        :rtype: timedelta
        """
        tx = self.tx
        rx = self.rx
        if tx is None or rx is None:
            return None
        return rx - tx

    @property
    def rcode(self):
        """
        get method that returns the rcode of the response

        :returns: the rcode
        :rtype: int
        """
        return cscamper_host.scamper_host_query_rcode_get(self._c)

    @property
    def flags(self):
        """
        get method that returns the flags from the reply

        :returns: the flags
        :rtype: int
        """
        return cscamper_host.scamper_host_query_flags_get(self._c)

    @property
    def id(self):
        """
        get method that returns the id set in the query

        :returns: the id number
        :rtype: int
        """
        return cscamper_host.scamper_host_query_id_get(self._c)

    @property
    def ancount(self):
        """
        get method that returns the number of RRs in the answer section

        :returns: the number of answer RRs
        :rtype: int
        """
        return cscamper_host.scamper_host_query_ancount_get(self._c)

    def an(self, i):
        """
        an(i)
        get method that returns the specified RR from the answer section

        :returns: the identified RR
        :rtype: int
        """
        c = cscamper_host.scamper_host_query_an_get(self._c, i)
        return ScamperHostRR.from_ptr(c)

    @property
    def nscount(self):
        """
        get method that returns the number of RRs in the NS section

        :returns: the number of NS RRs
        :rtype: int
        """
        return cscamper_host.scamper_host_query_nscount_get(self._c)

    def ns(self, i):
        """
        ns(i)
        get method that returns the specified RR from the NS section

        :returns: the identified RR
        :rtype: int
        """
        c = cscamper_host.scamper_host_query_ns_get(self._c, i)
        return ScamperHostRR.from_ptr(c)

    @property
    def arcount(self):
        """
        get method that returns the number of RRs in the AR section

        :returns: the number of AR RRs
        :rtype: int
        """
        return cscamper_host.scamper_host_query_arcount_get(self._c)

    def ar(self, i):
        """
        ar(i)
        get method that returns the specified RR from the AR section

        :returns: the identified RR
        :rtype: int
        """
        c = cscamper_host.scamper_host_query_ar_get(self._c, i)
        return ScamperHostRR.from_ptr(c)

cdef class ScamperHost:
    """
    :class:`ScamperHost` is used by scamper to store results from a DNS
    measurement.
    """
    cdef cscamper_host.scamper_host_t *_c
    cdef ScamperHostQuery _q
    cdef public ScamperInst _inst

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_host.scamper_host_free(self._c)

    @staticmethod
    cdef ScamperHost from_ptr(cscamper_host.scamper_host_t *ptr):
        cdef ScamperHost host = ScamperHost.__new__(ScamperHost)
        host._c = ptr
        qcount = cscamper_host.scamper_host_qcount_get(ptr)
        for i in range(qcount):
            q = cscamper_host.scamper_host_query_get(ptr, i)
            rx = cscamper_host.scamper_host_query_rx_get(q)
            if rx.tv_sec != 0 or rx.tv_usec != 0:
                host._q = ScamperHostQuery.from_ptr(q)
                break
        return host

    @property
    def inst(self):
        """
        get :class:`ScamperInst` associated with this measurement,
        if the measurement was conducted using a :class:`ScamperCtrl`.

        :returns: the instance
        :rtype: ScamperInst
        """
        return self._inst

    @property
    def list(self):
        """
        get list associated with this measurement.

        :returns: the list
        :rtype: ScamperList
        """
        c = cscamper_host.scamper_host_list_get(self._c)
        return ScamperList.from_ptr(c)

    @property
    def cycle(self):
        """
        get cycle associated with this measurement.

        :returns: the cycle
        :rtype: ScamperCycle
        """
        c = cscamper_host.scamper_host_cycle_get(self._c)
        return ScamperCycle.from_ptr(c, SCAMPER_FILE_OBJ_CYCLE_DEF)

    @property
    def src(self):
        """
        get method to obtain the source address this measurement

        :returns: the source address
        :rtype: ScamperAddr
        """
        c_a = cscamper_host.scamper_host_src_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def dst(self):
        """
        get method to obtain the destination address for a DNS measurement

        :returns: the destination address
        :rtype: ScamperAddr
        """
        c_a = cscamper_host.scamper_host_dst_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def userid(self):
        """
        get method to obtain the userid parameter.

        :returns: the userid
        :rtype: int
        """
        return cscamper_host.scamper_host_userid_get(self._c)

    @property
    def start(self):
        """
        get method to obtain the time this measurement started.

        :returns: the start timestamp
        :rtype: datetime
        """
        c = cscamper_host.scamper_host_start_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def qtype_num(self):
        """
        get method to obtain the qtype for this DNS measurement

        :returns: the qtype number
        :rtype: int
        """
        return cscamper_host.scamper_host_qtype_get(self._c)

    @property
    def qtype(self):
        """
        get method to obtain the qtype for this DNS measurement

        :returns: the qtype string
        :rtype: string
        """
        cdef char buf[128]
        qtype = cscamper_host.scamper_host_qtype_get(self._c)
        cscamper_host.scamper_host_qtype_tostr(qtype, buf, sizeof(buf))
        return buf.decode('UTF-8', 'strict')

    @property
    def qclass(self):
        """
        get method to obtain the qclass for this DNS measurement

        :returns: the qclass string
        :rtype: string
        """
        cdef char buf[128]
        qclass = cscamper_host.scamper_host_qclass_get(self._c)
        cscamper_host.scamper_host_qclass_tostr(qclass, buf, sizeof(buf))
        return buf.decode('UTF-8', 'strict')

    @property
    def qname(self):
        """
        get method to obtain the qname for this DNS measurement

        :returns: the qname
        :rtype: string
        """
        qname = cscamper_host.scamper_host_qname_get(self._c)
        return qname.decode('UTF-8', 'strict')

    @property
    def rcode(self):
        """
        get method to obtain the rcode from the first query with a response

        :returns: the rcode
        :type: int
        """
        if self._q is None:
            return None
        return self._q.rcode

    @property
    def tx(self):
        """
        get method to obtain the transmit time for the first query with
        a response

        :returns: the transmit timestamp
        :rtype: datetime
        """
        if self._q is None:
            return None
        return self._q.tx

    @property
    def rx(self):
        """
        get method to obtain the receive time for the first query with
        a response

        :returns: the receive timestamp
        :rtype: datetime
        """
        if self._q is None:
            return None
        return self._q.rx

    @property
    def rtt(self):
        """
        get method to obtain the delay between query and response for the
        first query with a response

        :returns: the delay between query and response
        :rtype: timedelta
        """
        if self._q is None:
            return None
        return self._q.rtt

    @property
    def ancount(self):
        """
        get method to obtain the number of AN RRs from the first query
        with a response

        :returns: the number of AN RRs
        :rtype: int
        """
        if self._q is None:
            return 0
        return self._q.ancount

    def an(self, i):
        """
        an(i)
        get method to obtain the specified AN RR from the first query
        with a response

        :returns: the number of AN RRs
        :rtype: int
        """
        if self._q is None:
            return None
        return self._q.an(i)

    def ans(self, rrtypes=None):
        """
        get method to obtain a RR Iterator over the AN section of the first
        query with a response

        :returns: an iterator
        :rtype: _ScamperHostRRIterator
        """
        return _ScamperHostRRIterator(self._q, 0, rrtypes)

    @property
    def nscount(self):
        """
        get method to obtain the number of NS RRs from the first query
        with a response

        :returns: the number of NS RRs
        :rtype: int
        """
        if self._q is None:
            return 0
        return self._q.nscount

    def ns(self, i):
        """
        ns(i)
        get method to obtain the specified NS RR from the first query
        with a response

        :returns: the number of NS RRs
        :rtype: int
        """
        if self._q is None:
            return None
        return self._q.ns(i)

    def nss(self, rrtypes=None):
        """
        get method to obtain a RR Iterator over the NS section of the first
        query with a response

        :returns: an iterator
        :rtype: _ScamperHostRRIterator
        """
        return _ScamperHostRRIterator(self._q, 1, rrtypes)

    @property
    def arcount(self):
        """
        get method to obtain the number of AR RRs from the first query
        with a response

        :returns: the number of AR RRs
        :rtype: int
        """
        if self._q is None:
            return 0
        return self._q.arcount

    def ar(self, i):
        """
        ar(i)
        get method to obtain the specified AR RR from the first query
        with a response

        :returns: the number of AR RRs
        :rtype: int
        """
        if self._q is None:
            return None
        return self._q.ar(i)

    def ars(self, rrtypes=None):
        """
        get method to obtain a RR Iterator over the AR section of the first
        query with a response

        :returns: an iterator
        :rtype: _ScamperHostRRIterator
        """
        return _ScamperHostRRIterator(self._q, 2, rrtypes=None)

    def ans_addrs(self):
        """
        get method to obtain all unique addresses returned

        :returns: a list of :class:`ScamperAddr`
        :rtype: a list of :class:`ScamperAddr`
        """
        addrs = {}
        for rec in self.ans():
            if rec.addr is not None:
                addrs[rec.addr] = 1
        return list(addrs.keys())

    def ans_nses(self):
        """
        get method to obtain all unique nameservers returned

        :returns: a list of :str:
        :rtype: a list of :str:
        """
        nses = {}
        for rec in self.ans():
            if rec.ns is not None:
                nses[rec.ns] = 1
        return list(nses.keys())

    def ans_txts(self):
        """
        get method to obtain all txt records returned

        :returns: a list of TXT RRs
        :rtype: a list of :ScamperHostRR:
        """
        txts = []
        for rec in self.ans():
            if rec.txt is not None:
                txts.append(rec)
        return txts

####
#### Scamper HTTP Object
####

cdef class ScamperHttpBuf:
    """
    :class:`ScamperHttpBuf` is used by scamper to store chunks of data
    received during a HTTP measurement.
    """
    cdef cscamper_http.scamper_http_buf_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_http.scamper_http_buf_free(self._c)

    @staticmethod
    cdef ScamperHttpBuf from_ptr(cscamper_http.scamper_http_buf_t *ptr):
        cdef ScamperHttpBuf htb = ScamperHttpBuf.__new__(ScamperHttpBuf)
        htb._c = cscamper_http.scamper_http_buf_use(ptr);
        return htb

    @property
    def timestamp(self):
        """
        get method that returns the time when the chunk was transmitted
        or received.

        :returns: the timestamp for the chunk
        :rtype: datetime
        """
        c = cscamper_http.scamper_http_buf_tv_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    def is_tx(self):
        """
        get method that returns True if the chunk was transmitted.

        :returns: True if the chunk was transmitted
        :rtype: bool
        """
        return cscamper_http.scamper_http_buf_is_tx(self._c)

    def is_rx(self):
        """
        get method that returns True if the chunk was received.

        :returns: True if the chunk was received
        :rtype: bool
        """
        return cscamper_http.scamper_http_buf_is_rx(self._c)

    def is_tls(self):
        """
        get method that returns True if the chunk is a TLS chunk.

        :returns: True if the chunk is a TLS chunk
        :rtype: bool
        """
        return cscamper_http.scamper_http_buf_is_tls(self._c)

    def is_hdr(self):
        """
        get method that returns True if the chunk is an HTTP header chunk.

        :returns: True if the chunk is a HTTP header chunk
        :rtype: bool
        """
        return cscamper_http.scamper_http_buf_is_hdr(self._c)

    def is_data(self):
        """
        get method that returns True if the chunk is a data chunk.

        :returns: True if the chunk is a data chunk
        :rtype: bool
        """
        return cscamper_http.scamper_http_buf_is_data(self._c)

    @property
    def payload(self):
        """
        get method to obtain the payload for this chunk.

        :returns: the payload
        :rtype: bytes
        """
        cdef uint16_t s
        cdef const uint8_t *ptr
        s = cscamper_http.scamper_http_buf_len_get(self._c)
        ptr = cscamper_http.scamper_http_buf_data_get(self._c)
        if s == 0 or ptr == NULL:
            return None
        return ptr[:s]

cdef class ScamperHttp:
    """
    :class:`ScamperHttp` is used by scamper to store results from a HTTP
    measurement.
    """
    cdef cscamper_http.scamper_http_t *_c
    cdef uint32_t _i, _sent
    cdef public ScamperInst _inst

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_http.scamper_http_free(self._c)

    def __iter__(self):
        self._i = 0
        self._sent = cscamper_http.scamper_http_bufc_get(self._c)
        return self

    def __next__(self):
        while self._i < self._sent:
            htb = cscamper_http.scamper_http_buf_get(self._c, self._i)
            self._i += 1
            if htb != NULL: #iterate to the next buf
                return ScamperHttpBuf.from_ptr(htb)
        raise StopIteration

    @staticmethod
    cdef ScamperHttp from_ptr(cscamper_http.scamper_http_t *ptr):
        cdef ScamperHttp http = ScamperHttp.__new__(ScamperHttp)
        http._c = ptr;
        return http

    @property
    def inst(self):
        """
        get :class:`ScamperInst` associated with this measurement,
        if the measurement was conducted using a :class:`ScamperCtrl`.

        :returns: the instance
        :rtype: ScamperInst
        """
        return self._inst

    @property
    def list(self):
        """
        get list associated with this measurement.

        :returns: the list
        :rtype: ScamperList
        """
        c = cscamper_http.scamper_http_list_get(self._c)
        return ScamperList.from_ptr(c)

    @property
    def cycle(self):
        """
        get cycle associated with this measurement.

        :returns: the cycle
        :rtype: ScamperCycle
        """
        c = cscamper_http.scamper_http_cycle_get(self._c)
        return ScamperCycle.from_ptr(c, SCAMPER_FILE_OBJ_CYCLE_DEF)

    @property
    def userid(self):
        """
        get method to obtain the userid parameter.

        :returns: the userid
        :rtype: int
        """
        return cscamper_http.scamper_http_userid_get(self._c)

    @property
    def start(self):
        """
        get method to obtain the time this measurement started.

        :returns: the start timestamp
        :rtype: datetime
        """
        c = cscamper_http.scamper_http_start_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def src(self):
        """
        get method to obtain the source address for this measurement.

        :returns: the source address
        :rtype: ScamperAddr
        """
        c_a = cscamper_http.scamper_http_src_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def dst(self):
        """
        get method to obtain the destination address for this measurement.

        :returns: the destination address
        :rtype: ScamperAddr
        """
        c_a = cscamper_http.scamper_http_dst_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def sport(self):
        """
        get method to obtain the source port the client used.

        :returns: the source port
        :rtype: int
        """
        return cscamper_http.scamper_http_sport_get(self._c)

    @property
    def dport(self):
        """
        get method to obtain the destination port the client reached the
        server on.

        :returns: the destination port
        :rtype: int
        """
        return cscamper_http.scamper_http_dport_get(self._c)

    @property
    def url(self):
        """
        get method to obtain the URL for this measurement.

        :returns: the URL
        :rtype: str
        """
        cdef size_t s
        cdef char *buf
        x = cscamper_http.scamper_http_url_len_get(self._c, &s)
        if x != 0:
            return None
        buf = <char *>PyMem_Malloc(s)
        if not buf:
            raise MemoryError()
        x = cscamper_http.scamper_http_url_get(self._c, buf, s)
        if x == 0:
            url = buf.decode('UTF-8', 'strict')
        else:
            url = None
        PyMem_Free(buf)
        return url

    @property
    def status_code(self):
        """
        get method to obtain the HTTP status code for this measurement.

        :returns: the status code
        :rtype: int
        """
        cdef uint16_t u16
        x = cscamper_http.scamper_http_status_code_get(self._c, &u16)
        if x != 0:
            return None
        return u16

    @property
    def response(self):
        """
        get method to obtain the response for this measurement.

        :returns: the response
        :rtype: bytes
        """
        cdef size_t s
        cdef uint8_t *buf
        x = cscamper_http.scamper_http_rx_data_len_get(self._c, &s)
        if x != 0 or s == 0:
            return None
        buf = <uint8_t *>PyMem_Malloc(s)
        if not buf:
            raise MemoryError()
        x = cscamper_http.scamper_http_rx_data_get(self._c, buf, s)
        if x == 0:
            output = buf[:s]
        else:
            output = None
        PyMem_Free(buf)
        return output

    @property
    def response_hdr(self):
        """
        get method to obtain the response header for this measurement, as
        a single string.

        :returns: the response
        :rtype: str
        """
        cdef size_t s
        cdef char *buf
        x = cscamper_http.scamper_http_rx_hdr_len_get(self._c, &s)
        if x != 0:
            return None
        buf = <char *>PyMem_Malloc(s)
        if not buf:
            raise MemoryError()
        x = cscamper_http.scamper_http_rx_hdr_get(self._c, <uint8_t *>buf, s)
        if x == 0:
            output = buf.decode('UTF-8', 'strict')
        else:
            output = None
        PyMem_Free(buf)
        return output

    @property
    def transmit_hdr(self):
        """
        get method to obtain the transmit header for this measurement, as
        a single string.

        :returns: the response
        :rtype: str
        """
        cdef size_t s
        cdef char *buf
        x = cscamper_http.scamper_http_tx_hdr_len_get(self._c, &s)
        if x != 0:
            return None
        buf = <char *>PyMem_Malloc(s)
        if not buf:
            raise MemoryError()
        x = cscamper_http.scamper_http_tx_hdr_get(self._c, <uint8_t *>buf, s)
        if x == 0:
            output = buf.decode('UTF-8', 'strict')
        else:
            output = None
        PyMem_Free(buf)
        return output

    cdef dict _htfs_todict(self, cscamper_http.scamper_http_hdr_fields_t *htfs):
        x = cscamper_http.scamper_http_hdr_fields_count_get(htfs)
        out = dict()
        if x > 0:
            for i in range(x):
                htf = cscamper_http.scamper_http_hdr_fields_get(htfs, i)
                if htf == NULL:
                    continue
                name = cscamper_http.scamper_http_hdr_field_name_get(htf)
                value = cscamper_http.scamper_http_hdr_field_value_get(htf)
                if name == NULL or value == NULL:
                    continue
                nd = name.decode('UTF-8', 'strict')
                vd = value.decode('UTF-8', 'strict')
                out[nd.lower()] = vd.lower()
        return out

    @property
    def response_hdrs(self):
        """
        get method to obtain the response headers for this measurement,
        stored in a dictionary.  all the response header names and values
        are stored in lowercase form in the dictionary.

        :returns: response header dictionary
        :rtype: dict
        """
        htfs = cscamper_http.scamper_http_rx_hdr_fields_get(self._c)
        if htfs == NULL:
            return None
        out = self._htfs_todict(htfs)
        cscamper_http.scamper_http_hdr_fields_free(htfs)
        return out

    @property
    def transmit_hdrs(self):
        """
        get method to obtain the transmit headers for this measurement,
        stored in a dictionary.  all the transmit header names and values
        are stored in lowercase form in the dictionary.

        :returns: transmit header dictionary
        :rtype: dict
        """
        htfs = cscamper_http.scamper_http_tx_hdr_fields_get(self._c)
        if htfs == NULL:
            return None
        out = self._htfs_todict(htfs)
        cscamper_http.scamper_http_hdr_fields_free(htfs)
        return out

    def response_hdr_byname(self, name):
        """
        get method to obtain the value of a response header, if present
        in the response.  the value is reported in the same case it was
        received.  if the caller will fetch multiple response headers,
        it is more efficient to use the dictionary provided by
        :attr:`response_hdrs`.

        :param string name: the name of the response header to fetch
        :returns: the value for the header, if present.
        :rtype: str
        """
        cdef char *value
        if name is None or not isinstance(name, str):
            return ValueError("name must be a string")
        x = cscamper_http.scamper_http_rx_hdr_name_get(self._c,
                                                       name.encode('UTF-8'),
                                                       &value)
        if x != 0:
            return RuntimeError(f"could not extract {name}")
        if value == NULL:
            return None
        out = value.decode('UTF-8', 'strict')
        free(value)
        return out

    def transmit_hdr_byname(self, name):
        """
        get method to obtain the value of a transmit header entry, if present
        in the request.  the value is reported in the same case it was
        transmitted.  if the caller will fetch multiple transmit headers,
        it is more to efficient use the dictionary provided by
        :attr:`transmit_hdrs`.

        :param string name: the name of the transmit header to fetch
        :returns: the value for the header, if present.
        :rtype: str
        """
        cdef char *value
        if name is None or not isinstance(name, str):
            return ValueError("name must be a string")
        x = cscamper_http.scamper_http_tx_hdr_name_get(self._c,
                                                       name.encode('UTF-8'),
                                                       &value)
        if x != 0:
            return RuntimeError(f"could not extract {name}")
        if value == NULL:
            return None
        out = value.decode('UTF-8', 'strict')
        free(value)
        return out

####
#### Scamper Udpprobe Object
####
class _ScamperUdpprobeReplyIterator:
    def __init__(self, up):
        self._up = up
        self._pi = 0
        self._pc = up.probe_sent
        self._ri = 0

    def __iter__(self):
        return self

    def __next__(self):
        while self._pi < self._pc:
            probe = self._up.probe(self._pi)
            while self._ri < probe.reply_count:
                reply = probe.reply(self._ri)
                self._ri += 1
                return reply
            self._pi += 1
            self._ri = 0
        raise StopIteration

cdef class ScamperUdpprobeReply:
    """
    :class:`ScamperUdpprobeReply` is used by scamper to store responses
    for a :class:`ScamperUdpprobe` measurement.
    """
    cdef cscamper_udpprobe.scamper_udpprobe_reply_t *_c

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_udpprobe.scamper_udpprobe_reply_free(self._c)

    @staticmethod
    cdef ScamperUdpprobeReply from_ptr(cscamper_udpprobe.scamper_udpprobe_reply_t *ptr):
        cdef ScamperUdpprobeReply ur = ScamperUdpprobeReply.__new__(ScamperUdpprobeReply)
        ur._c = cscamper_udpprobe.scamper_udpprobe_reply_use(ptr);
        return ur

    @property
    def rx(self):
        """
        get method that returns the time when the reply was received.

        :returns: the timestamp for the reply
        :rtype: datetime
        """
        c = cscamper_udpprobe.scamper_udpprobe_reply_rx_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def payload(self):
        """
        get method that returns the payload contained in the response.

        :returns: the payload
        :rtype: bytes
        """
        cdef size_t s
        cdef const uint8_t *buf
        s = cscamper_udpprobe.scamper_udpprobe_reply_len_get(self._c)
        buf = cscamper_udpprobe.scamper_udpprobe_reply_data_get(self._c)
        if s == 0 or buf == NULL:
            return None
        return buf[:s]

cdef class ScamperUdpprobeProbe:
    """
    :class:`ScamperUdpprobeProbe` is used by scamper to store information
    about a specific UDP probe.
    """
    cdef cscamper_udpprobe.scamper_udpprobe_probe_t *_c
    cdef uint8_t _i, _probe_sent

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_udpprobe.scamper_udpprobe_probe_free(self._c)

    @staticmethod
    cdef ScamperUdpprobeProbe from_ptr(cscamper_udpprobe.scamper_udpprobe_probe_t *ptr):
        cdef ScamperUdpprobeProbe pr = ScamperUdpprobeProbe.__new__(ScamperUdpprobeProbe)
        pr._c = cscamper_udpprobe.scamper_udpprobe_probe_use(ptr);
        return pr

    def __iter__(self):
        self._i = 0
        self._replyc = cscamper_udpprobe.scamper_udpprobe_probe_replyc_get(self._c)
        return self

    def __next__(self):
        while self._i < self._replyc:
            reply = cscamper_udpprobe.scamper_udpprobe_probe_reply_get(self._c, self._i)
            self._i += 1
            if reply != NULL:
                return ScamperUdpprobeReply.from_ptr(reply)
        raise StopIteration

    @property
    def tx(self):
        """
        get method that returns the time when the probe was transmitted.

        :returns: the timestamp for the probe
        :rtype: datetime
        """
        c = cscamper_udpprobe.scamper_udpprobe_probe_tx_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def sport(self):
        """
        get method to obtain the source port value used by this probe

        :returns: the source port
        :rtype: int
        """
        return cscamper_udpprobe.scamper_udpprobe_probe_sport_get(self._c)

    @property
    def reply_count(self):
        """
        get method that returns the number of replies recorded for this probe

        :returns: the number of replies recorded
        :rtype: int
        """
        return cscamper_udpprobe.scamper_udpprobe_probe_replyc_get(self._c)

    def reply(self, i):
        """
        reply(i)
        get method to obtain a reply for a specific attempt, starting at zero.

        :returns: the nominated reply
        :rtype: ScamperUdpprobeReply
        """
        c = cscamper_udpprobe.scamper_udpprobe_probe_reply_get(self._c, i)
        return ScamperUdpprobeReply.from_ptr(c)

cdef class ScamperUdpprobe:
    """
    :class:`ScamperUdpprobe` is used by scamper to store results from a UDP
    probe measurement.
    """
    cdef cscamper_udpprobe.scamper_udpprobe_t *_c
    cdef public ScamperInst _inst
    cdef uint8_t _i, _probe_sent

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            cscamper_udpprobe.scamper_udpprobe_free(self._c)

    def __iter__(self):
        self._i = 0
        self._probe_sent = cscamper_udpprobe.scamper_udpprobe_probe_sent_get(self._c)
        return self

    def __next__(self):
        while self._i < self._probe_sent:
            probe = cscamper_udpprobe.scamper_udpprobe_probe_get(self._c, self._i)
            self._i += 1
            if probe != NULL:
                return ScamperUdpprobeProbe.from_ptr(probe)
        raise StopIteration

    @staticmethod
    cdef ScamperUdpprobe from_ptr(cscamper_udpprobe.scamper_udpprobe_t *ptr):
        cdef ScamperUdpprobe up = ScamperUdpprobe.__new__(ScamperUdpprobe)
        up._c = ptr;
        return up

    @property
    def inst(self):
        """
        get :class:`ScamperInst` associated with this measurement,
        if the measurement was conducted using a :class:`ScamperCtrl`.

        :returns: the instance
        :rtype: ScamperInst
        """
        return self._inst

    @property
    def list(self):
        """
        get list associated with this measurement.

        :returns: the list
        :rtype: ScamperList
        """
        c = cscamper_udpprobe.scamper_udpprobe_list_get(self._c)
        return ScamperList.from_ptr(c)

    @property
    def cycle(self):
        """
        get cycle associated with this measurement.

        :returns: the cycle
        :rtype: ScamperCycle
        """
        c = cscamper_udpprobe.scamper_udpprobe_cycle_get(self._c)
        return ScamperCycle.from_ptr(c, SCAMPER_FILE_OBJ_CYCLE_DEF)

    @property
    def userid(self):
        """
        get method to obtain the userid parameter.

        :returns: the userid
        :rtype: int
        """
        return cscamper_udpprobe.scamper_udpprobe_userid_get(self._c)

    @property
    def start(self):
        """
        get method to obtain the time this measurement started.

        :returns: the start timestamp
        :rtype: datetime
        """
        c = cscamper_udpprobe.scamper_udpprobe_start_get(self._c)
        if c == NULL:
            return None
        t = time.gmtime(c.tv_sec)
        return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], c.tv_usec,
                                 tzinfo=datetime.timezone.utc)

    @property
    def src(self):
        """
        get method to obtain the source address for this measurement.

        :returns: the source address
        :rtype: ScamperAddr
        """
        c_a = cscamper_udpprobe.scamper_udpprobe_src_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def dst(self):
        """
        get method to obtain the destination address for this measurement.

        :returns: the destination address
        :rtype: ScamperAddr
        """
        c_a = cscamper_udpprobe.scamper_udpprobe_dst_get(self._c)
        return ScamperAddr.from_ptr(c_a)

    @property
    def sport(self):
        """
        get method to obtain the source port value provided to the udpprobe
        measurement.

        :returns: the source port
        :rtype: int
        """
        return cscamper_udpprobe.scamper_udpprobe_sport_get(self._c)

    @property
    def dport(self):
        """
        get method to obtain the destination port the client reached the
        server on.

        :returns: the destination port
        :rtype: int
        """
        return cscamper_udpprobe.scamper_udpprobe_dport_get(self._c)

    @property
    def wait_timeout(self):
        """
        get method to obtain the length of time to wait before declaring
        a probe lost.

        :returns: the timeout value.
        :rtype: timedelta
        """
        c = cscamper_udpprobe.scamper_udpprobe_wait_timeout_get(self._c)
        return datetime.timedelta(seconds=c.tv_sec,
                                  microseconds=c.tv_usec)

    @property
    def payload(self):
        """
        get method that returns the payload contained in the probe.

        :returns: the payload
        :rtype: bytes
        """
        cdef size_t s
        cdef const uint8_t *buf
        s = cscamper_udpprobe.scamper_udpprobe_len_get(self._c)
        buf = cscamper_udpprobe.scamper_udpprobe_data_get(self._c)
        if s == 0 or buf == NULL:
            return None
        return buf[:s]

    @property
    def probe_sent(self):
        return cscamper_udpprobe.scamper_udpprobe_probe_sent_get(self._c)

    def probe(self, i):
        """
        get method that returns a specific probe

        :returns: the probe identified
        :rtype: ScamperUdpprobeProbe
        """
        c = cscamper_udpprobe.scamper_udpprobe_probe_get(self._c, i)
        return ScamperUdpprobeProbe.from_ptr(c)

    def replies(self):
        """
        get an Iterator that contains the replies obtained during the
        measurement.
        """
        return _ScamperUdpprobeReplyIterator(self)

####
#### Scamper File Object
####

cdef class ScamperFile:
    """
    A :class:`ScamperFile` can be used to interact with measurement results
    collected by scamper.  The constructor takes the following parameters,
    the first of which is mandatory; the remainder are optional named
    parameters.

    - filename: a string identifying the name of the file to open.
    - mode: a string ('r' or 'w') identifying whether the file is to be\
    opened read or write.
    - kind: the type of the file to open, if opened for writing. \
    Choices: warts, warts.gz, warts.bz2, warts.xz, json, text.
    - filter_types: a list containing the types of the objects to return \
    when reading. \
    By default, a file opened for reading returns all types of objects.

    The class implements an iterator interface, which a caller can use to
    read objects out of the file.
    """
    cdef cscamper_file.scamper_file_t *_c_sf
    cdef cscamper_file.scamper_file_filter_t *_c_sff
    cdef char _mode

    def __init__(self, filename, mode='r', kind=None, filter_types=None):
        if mode != 'r' and mode != 'w':
            raise ValueError("invalid mode: " + mode)
        if mode == 'r':
            if kind is not None:
                raise ValueError("do not specify kind when opening a file for reading")
            else:
                kind = "warts"
        elif mode == 'w' and kind is None:
            if filename.endswith(".gz"):
                kind = "warts.gz"
            elif filename.endswith(".bz2"):
                kind = "warts.bz2"
            elif filename.endswith(".xz"):
                kind = "warts.xz"
            elif filename.endswith(".json"):
                kind = "json"
            elif filename.endswith(".txt"):
                kind = "text"
            else:
                kind = "warts"
        self._mode = ord(mode)

        if filter_types is not None:
            self.filter_types(*filter_types)

        self._c_sf = cscamper_file.scamper_file_open(filename.encode('UTF-8'),
                                                     ord(mode),
                                                     kind.encode('UTF-8'))
        if self._c_sf == NULL:
            raise RuntimeError("could not open file")

    def __dealloc__(self):
        if self._c_sf != NULL:
            cscamper_file.scamper_file_close(self._c_sf)
        if self._c_sff != NULL:
            cscamper_file.scamper_file_filter_free(self._c_sff)

    def __iter__(self):
        if self._mode != ord('r'):
            raise ValueError("not readable")
        return self

    def __next__(self):
        o = self.read()
        if o is None:
            raise StopIteration
        return o

    @property
    def filetype(self):
        """
        get method to obtain the type of :class:`ScamperFile` (warts or arts)

        :returns: the type
        :rtype: string
        """
        cdef char buf[128]
        cscamper_file.scamper_file_type_tostr(self._c_sf, buf, sizeof(buf))
        return buf.decode('UTF-8', 'strict')

    def close(self):
        """
        close the file
        """
        cscamper_file.scamper_file_close(self._c_sf)
        self._c_sf = NULL

    @property
    def filename(self):
        """
        get method to obtain the filename for the :class:`ScamperFile`

        :returns: the filename
        :rtype: string
        """
        c = cscamper_file.scamper_file_getfilename(self._c_sf)
        if c == NULL:
            return None
        return c.decode('UTF-8', 'strict')

    def filter_types(self, *types):
        """
        filter_types(*types)
        configure the :class:`ScamperFile` to return the specific object types.
        This method will raise a :py:exc:`ValueError` if the type to
        filter is not valid.

        :param class types: the types of Scamper objects to filter.
        """
        cdef uint16_t i
        cdef uint16_t o_type
        cdef uint16_t typea[10]
        cdef uint16_t typec = 0

        if self._mode != ord('r'):
            raise ValueError("cannot add filter to non-readable files")

        for t in types:
            if t is ScamperTrace:
                o_type = SCAMPER_FILE_OBJ_TRACE
            elif t is ScamperPing:
                o_type = SCAMPER_FILE_OBJ_PING
            elif t is ScamperTracelb:
                o_type = SCAMPER_FILE_OBJ_TRACELB
            elif t is ScamperDealias:
                o_type = SCAMPER_FILE_OBJ_DEALIAS
            elif t is ScamperNeighbourdisc:
                o_type = SCAMPER_FILE_OBJ_NEIGHBOURDISC
            elif t is ScamperTbit:
                o_type = SCAMPER_FILE_OBJ_TBIT
            elif t is ScamperSting:
                o_type = SCAMPER_FILE_OBJ_STING
            elif t is ScamperSniff:
                o_type = SCAMPER_FILE_OBJ_SNIFF
            elif t is ScamperHost:
                o_type = SCAMPER_FILE_OBJ_HOST
            elif t is ScamperHttp:
                o_type = SCAMPER_FILE_OBJ_HTTP
            elif t is ScamperUdpprobe:
                o_type = SCAMPER_FILE_OBJ_UDPPROBE
            else:
                raise ValueError("invalid type")

            seen = False
            for i from 0 <= i < 10 by 1:
                if typea[i] == o_type:
                    seen = True
                    break

            if not seen:
                typea[typec] = o_type
                typec += 1

        if typec == 0:
            raise ValueError("nothing to filter")

        c_sff = cscamper_file.scamper_file_filter_alloc(typea, typec)
        if c_sff == NULL:
            raise RuntimeError("could not build filter")
        if self._c_sff != NULL:
            cscamper_file.scamper_file_filter_free(self._c_sff)
        self._c_sff = c_sff

    def read(self):
        """
        get method to read the next object from the :class:`ScamperFile`.
        This method will raise a :py:exc:`RuntimeError` if the file was
        not opened in read mode, or if it reads an object type that this
        module does not support.

        :returns: a scamper object
        :rtype: ScamperList ScamperCycle ScamperTrace ScamperPing \
            ScamperTracelb ScamperDealias ScamperNeighbourdisc ScamperTbit \
            ScamperSting ScamperSniff ScamperHost
        """
        cdef cscamper_list.scamper_list_t *c_list
        cdef cscamper_list.scamper_cycle_t *c_cycle
        cdef uint16_t o_type
        cdef void *o_data
        cdef int rc

        if self._mode != ord('r'):
            raise RuntimeError("file not opened in read mode")

        rc = cscamper_file.scamper_file_read(self._c_sf, self._c_sff, &o_type, &o_data)
        if rc != 0 or o_data == NULL:
            return None

        if o_type == SCAMPER_FILE_OBJ_LIST:
            c_list = <cscamper_list.scamper_list_t *>o_data
            o = ScamperList.from_ptr(c_list)
            if o is not None:
                cscamper_list.scamper_list_free(c_list)
            return o
        elif (o_type == SCAMPER_FILE_OBJ_CYCLE_START or
              o_type == SCAMPER_FILE_OBJ_CYCLE_DEF or
              o_type == SCAMPER_FILE_OBJ_CYCLE_STOP):
            c_cycle = <cscamper_list.scamper_cycle_t *>o_data
            o = ScamperCycle.from_ptr(c_cycle, o_type)
            if o is not None:
                cscamper_list.scamper_cycle_free(c_cycle)
            return o
        elif o_type == SCAMPER_FILE_OBJ_TRACE:
            return ScamperTrace.from_ptr(<cscamper_trace.scamper_trace_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_PING:
            return ScamperPing.from_ptr(<cscamper_ping.scamper_ping_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_TRACELB:
            return ScamperTracelb.from_ptr(<cscamper_tracelb.scamper_tracelb_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_DEALIAS:
            return ScamperDealias.from_ptr(<cscamper_dealias.scamper_dealias_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_NEIGHBOURDISC:
            return ScamperNeighbourdisc.from_ptr(<cscamper_neighbourdisc.scamper_neighbourdisc_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_TBIT:
            return ScamperTbit.from_ptr(<cscamper_tbit.scamper_tbit_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_STING:
            return ScamperSting.from_ptr(<cscamper_sting.scamper_sting_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_SNIFF:
            return ScamperSniff.from_ptr(<cscamper_sniff.scamper_sniff_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_HOST:
            return ScamperHost.from_ptr(<cscamper_host.scamper_host_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_HTTP:
            return ScamperHttp.from_ptr(<cscamper_http.scamper_http_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_UDPPROBE:
            return ScamperUdpprobe.from_ptr(<cscamper_udpprobe.scamper_udpprobe_t *>o_data)

        raise RuntimeError("unexpected object type " + o_type)

    def write(self, obj):
        """
        write(obj)
        write an object to the warts file.  This method will raise a
        :py:exc:`RuntimeError` if the file was not opened in write
        mode, if the object to write is not supported by this module,
        or if it could not write the object to disk.

        :param object obj: a scamper object to write.
        """
        cdef void *o_data
        cdef uint16_t o_type

        if self._mode != ord('w'):
            raise RuntimeError("file not opened in write mode")

        if isinstance(obj, ScamperList):
            o_type = SCAMPER_FILE_OBJ_LIST
            o_data = (<ScamperList>obj)._c
        elif isinstance(obj, ScamperCycle):
            o_type = (<ScamperCycle>obj)._type
            o_data = (<ScamperCycle>obj)._c
        elif isinstance(obj, ScamperAddr):
            o_type = SCAMPER_FILE_OBJ_ADDR
            o_data = (<ScamperAddr>obj)._c
        elif isinstance(obj, ScamperTrace):
            o_type = SCAMPER_FILE_OBJ_TRACE
            o_data = (<ScamperTrace>obj)._c
        elif isinstance(obj, ScamperPing):
            o_type = SCAMPER_FILE_OBJ_PING
            o_data = (<ScamperPing>obj)._c
        elif isinstance(obj, ScamperTracelb):
            o_type = SCAMPER_FILE_OBJ_TRACELB
            o_data = (<ScamperTracelb>obj)._c
        elif isinstance(obj, ScamperDealias):
            o_type = SCAMPER_FILE_OBJ_DEALIAS
            o_data = (<ScamperDealias>obj)._c
        elif isinstance(obj, ScamperNeighbourdisc):
            o_type = SCAMPER_FILE_OBJ_NEIGHBOURDISC
            o_data = (<ScamperNeighbourdisc>obj)._c
        elif isinstance(obj, ScamperTbit):
            o_type = SCAMPER_FILE_OBJ_TBIT
            o_data = (<ScamperTbit>obj)._c
        elif isinstance(obj, ScamperSting):
            o_type = SCAMPER_FILE_OBJ_STING
            o_data = (<ScamperSting>obj)._c
        elif isinstance(obj, ScamperSniff):
            o_type = SCAMPER_FILE_OBJ_SNIFF
            o_data = (<ScamperSniff>obj)._c
        elif isinstance(obj, ScamperHost):
            o_type = SCAMPER_FILE_OBJ_HOST
            o_data = (<ScamperHost>obj)._c
        elif isinstance(obj, ScamperHttp):
            o_type = SCAMPER_FILE_OBJ_HTTP
            o_data = (<ScamperHttp>obj)._c
        elif isinstance(obj, ScamperUdpprobe):
            o_type = SCAMPER_FILE_OBJ_UDPPROBE
            o_data = (<ScamperUdpprobe>obj)._c
        else:
            raise RuntimeError("unhandled object type")

        if (o_type == SCAMPER_FILE_OBJ_LIST or
            o_type == SCAMPER_FILE_OBJ_CYCLE_DEF or
            o_type == SCAMPER_FILE_OBJ_ADDR):
            return

        rc = cscamper_file.scamper_file_write_obj(self._c_sf, o_type, o_data)
        if rc != 0:
            raise RuntimeError("could not write " + str(o_type))

        return

    def is_write(self):
        return self._mode == ord('w')

    def is_read(self):
        return self._mode == ord('r')

class ScamperInstError(Exception):
    def __init__(self, message, inst):
        super().__init__(message)
        self.inst = inst

cdef void _ctrl_cb(clibscamperctrl.scamper_inst_t *c_inst,
                   uint8_t cb_type, clibscamperctrl.scamper_task_t *c_task,
                   const void *data, size_t datalen):

    cdef uint16_t o_type = 0
    cdef void *o_data = NULL
    cdef clibscamperctrl.scamper_ctrl_t *c_ctrl
    cdef cscamper_list.scamper_list_t *c_list
    cdef cscamper_list.scamper_cycle_t *c_cycle
    cdef const char *errstr

    inst = <ScamperInst> clibscamperctrl.scamper_inst_getparam(c_inst)
    c_ctrl = clibscamperctrl.scamper_inst_getctrl(c_inst)
    ctrl = <ScamperCtrl> clibscamperctrl.scamper_ctrl_getparam(c_ctrl)

    if c_task != NULL:
        c_task_param = clibscamperctrl.scamper_task_getparam(c_task)
        if c_task_param != NULL:
            ctrl._tasks.remove(<ScamperTask>c_task_param)
            inst._tasks.remove(<ScamperTask>c_task_param)

    if cb_type == SCAMPER_CTRL_TYPE_DATA:

        # add the passed in data to the file input stream, and see if
        # we got a complete object at the end of it
        cscamper_file.scamper_file_readbuf_add(inst._c_rb, data, datalen)
        cscamper_file.scamper_file_read(inst._c_f, NULL, &o_type, &o_data)
        if o_data == NULL:
            return

        # figure out what type of object we got, and create a wrapping
        # object for it
        if o_type == SCAMPER_FILE_OBJ_LIST:
            c_list = <cscamper_list.scamper_list_t *>o_data
            obj = ScamperList.from_ptr(c_list)
            if obj is not None:
                cscamper_list.scamper_list_free(c_list)
        elif (o_type == SCAMPER_FILE_OBJ_CYCLE_START or
              o_type == SCAMPER_FILE_OBJ_CYCLE_DEF or
              o_type == SCAMPER_FILE_OBJ_CYCLE_STOP):
            c_cycle = <cscamper_list.scamper_cycle_t *>o_data
            obj = ScamperCycle.from_ptr(c_cycle, o_type)
            if obj is not None:
                cscamper_list.scamper_cycle_free(c_cycle)
        elif o_type == SCAMPER_FILE_OBJ_TRACE:
            obj = ScamperTrace.from_ptr(<cscamper_trace.scamper_trace_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_PING:
            obj = ScamperPing.from_ptr(<cscamper_ping.scamper_ping_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_TRACELB:
            obj = ScamperTracelb.from_ptr(<cscamper_tracelb.scamper_tracelb_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_DEALIAS:
            obj = ScamperDealias.from_ptr(<cscamper_dealias.scamper_dealias_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_NEIGHBOURDISC:
            obj = ScamperNeighbourdisc.from_ptr(<cscamper_neighbourdisc.scamper_neighbourdisc_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_TBIT:
            obj = ScamperTbit.from_ptr(<cscamper_tbit.scamper_tbit_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_STING:
            obj = ScamperSting.from_ptr(<cscamper_sting.scamper_sting_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_SNIFF:
            obj = ScamperSniff.from_ptr(<cscamper_sniff.scamper_sniff_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_HOST:
            obj = ScamperHost.from_ptr(<cscamper_host.scamper_host_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_HTTP:
            obj = ScamperHttp.from_ptr(<cscamper_http.scamper_http_t *>o_data)
        elif o_type == SCAMPER_FILE_OBJ_UDPPROBE:
            obj = ScamperUdpprobe.from_ptr(<cscamper_udpprobe.scamper_udpprobe_t *>o_data)
        else:
            obj = None

        # put the object on the queue, or queue an exception
        if obj is None:
            ctrl._exceptions.append(RuntimeError("unexpected object type " +
                                                 o_type))
        else:
            # if we've been passed an output file, write to it.
            if ctrl._outfile is not None:
                try:
                    ctrl._outfile.write(obj)
                except Exception:
                    pass
            if not isinstance(obj, (ScamperList, ScamperCycle)):
                obj._inst = inst
            if ctrl._c_synctask != NULL and ctrl._c_synctask == c_task:
                ctrl._syncdata = obj
            else:
                ctrl._objs.append(obj)

    elif cb_type == SCAMPER_CTRL_TYPE_MORE:
        if ctrl._morecb is not None:
            try:
                ctrl._morecb(ctrl, inst, ctrl._param)
            except Exception as e:
                ctrl._exceptions.append(e)

    elif cb_type == SCAMPER_CTRL_TYPE_ERR:
        errstr = <const char *>data
        excstr = f"got err from {inst.name}"
        if errstr != NULL and errstr[0] != ord('\0'):
            excstr += ": " + errstr.decode('UTF-8', 'strict')
        ctrl._exceptions.append(ScamperInstError(excstr, inst))

    elif cb_type == SCAMPER_CTRL_TYPE_FATAL:
        excstr = f"got fatal from {inst.name}"
        errstr = clibscamperctrl.scamper_ctrl_strerror(c_ctrl)
        if errstr != NULL and errstr[0] != ord('\0'):
            excstr += ": " + errstr.decode('UTF-8', 'strict')
        ctrl._exceptions.append(ScamperInstError(excstr, inst))

    elif cb_type == SCAMPER_CTRL_TYPE_EOF:
        # got an eof on an instance.  remove the references to the tasks
        # managed by inst from both the inst and ctrl objects.
        while len(inst._tasks) > 0:
            task = inst._tasks.pop(0)
            ctrl._tasks.remove(task)

        # remove the instance from the set of instances managed by ctrl
        # and call the eofcb if one provided by the user.
        ctrl._insts.remove(inst)
        if ctrl._eofcb is not None:
            try:
                ctrl._eofcb(ctrl, inst, ctrl._param)
            except Exception as e:
                ctrl._exceptions.append(e)

    return

cdef class ScamperCtrl:
    """
    :class:`ScamperCtrl` is used to interact with a collection (one or more)
    :class:`ScamperInst` objects.
    The :class:`ScamperCtrl` constructor takes the following named
    parameters, all of which are optional:

    - meta: whether the caller wants meta objects \
    (:class:`ScamperList`, :class:`ScamperCycle`) or not.  default is false.
    - morecb: a callback that is called when an instance signals that it \
    wants more work.  The callback takes three parameters: \
    :class:`ScamperCtrl`, :class:`ScamperInst`, and a parameter that the \
    callback can use.
    - eofcb: a callback that is called when an instance signals that it \
    has finished.  The callback takes the same three parameters as morecb.
    - param: a parameter that is passed to morecb and eofcb.
    - outfile: a :class:`ScamperFile` that should record all measurement \
    results.  This can save the caller from doing that itself.
    - unix: the path to a unix domain socket representing a local instance, \
    which will then become a :class:`ScamperInst`.
    - remote: the path to a unix domain socket representing a remote \
    instance, which will then become a :class:`ScamperInst`.
    - remote_dir: the path to a directory containing unix domain sockets \
    each representing a remote instance, which will each then become a \
    :class:`ScamperInst`.
    """
    cdef clibscamperctrl.scamper_ctrl_t *_c
    cdef clibscamperctrl.scamper_task_t *_c_synctask
    cdef public object _morecb
    cdef public object _eofcb
    cdef public object _syncdata
    cdef public object _outfile
    cdef public object _param
    cdef bint _meta

    # initialize these lists in __init__, otherwise there's a chance
    # that a second ScamperCtrl object will initially refer to the
    # lists in the first ScamperCtrl object
    cdef object _objs # = []
    cdef object _exceptions # = []
    cdef object _insts # = []
    cdef object _tasks # = []

    def __init__(self, meta=False, morecb=None, eofcb=None, param=None,
                 unix=None, remote=None, remote_dir=None, outfile=None):
        if outfile is not None:
            if not isinstance(outfile, ScamperFile):
                raise ValueError("outfile not ScamperFile")
            if not outfile.is_write():
                raise RuntimeError("outfile not opened in write mode")

        self._c = clibscamperctrl.scamper_ctrl_alloc(_ctrl_cb)
        clibscamperctrl.scamper_ctrl_setparam(self._c, <PyObject *>self)
        self._meta = meta
        self._morecb = morecb
        self._eofcb = eofcb
        self._outfile = outfile
        self._param = param
        self._objs = []
        self._exceptions = []
        self._insts = []
        self._tasks = []

        if unix is not None:
            self.add_unix(unix)
        if remote is not None:
            self.add_remote(remote)
        if remote_dir is not None:
            self.add_remote_dir(remote_dir)

    def __dealloc__(self):
        # cython does not seem to empty lists on dealloc, so explicitly empty
        while len(self._insts) > 0:
            self._insts.pop(0)
        while len(self._objs) > 0:
            self._objs.pop(0)
        while len(self._exceptions) > 0:
            self._exceptions.pop(0)
        while len(self._tasks) > 0:
            self._tasks.pop(0)

        # free the control structure
        if self._c != NULL:
            clibscamperctrl.scamper_ctrl_free(self._c)

    def add_unix(self, path):
        """
        add_unix(path)
        add a :class:`ScamperInst` connected to a specified unix domain
        socket on the local system.
        This method will raise a :py:exc:`RuntimeError` if it could not
        connect to the local scamper instance at the local unix domain socket.

        :param string path: the unix domain socket
        :returns: the scamper instance
        :rtype: ScamperInst
        """
        c = clibscamperctrl.scamper_inst_unix(self._c, NULL,
                                              path.encode('UTF-8'))
        if c == NULL:
            err = clibscamperctrl.scamper_ctrl_strerror(self._c)
            if err != NULL:
                raise RuntimeError(err.decode('UTF-8', 'strict'))
            else:
                raise RuntimeError("could not connect to " + path)
        inst = ScamperInst.from_ptr(c)
        self._insts.append(inst)
        return inst

    def add_inet(self, port, addr=None):
        """
        add_inet(port, addr=None)
        add a :class:`ScamperInst` connected to a specified port on the local
        system, if the addr parameter is not set.  This method will
        raise a :py:exc:`RuntimeError` if it could not connect to the
        scamper instance at the given port.

        :param int port: the port to connect to
        :param string addr: the address to connect to, if not loopback
        :returns: the scamper instance
        :rtype: ScamperInst
        """
        if addr is None:
            c = clibscamperctrl.scamper_inst_inet(self._c, NULL, NULL, port)
        else:
            a = addr.encode('UTF-8')
            c = clibscamperctrl.scamper_inst_inet(self._c, NULL, a, port)
        if c == NULL:
            err = clibscamperctrl.scamper_ctrl_strerror(self._c)
            if err != NULL:
                raise RuntimeError(err.decode('UTF-8', 'strict'))
            else:
                msg = (a + ":" if a is not None else "") + str(port)
                raise RuntimeError("could not connect to " + msg)
        inst = ScamperInst.from_ptr(c)
        self._insts.append(inst)
        return inst

    def add_remote(self, path):
        """
        add_remote(path)
        add a :class:`ScamperInst` connected to a specified remote system
        available on the specified unix domain socket.  This method will
        raise a :py:exc:`RuntimeError` if it could not connect to the
        remote scamper instance at the local unix domain socket.

        :param string path: the unix domain socket
        :returns: the scamper instance
        :rtype: ScamperInst
        """
        c = clibscamperctrl.scamper_inst_remote(self._c, path.encode('UTF-8'))
        if c == NULL:
            err = clibscamperctrl.scamper_ctrl_strerror(self._c)
            if err != NULL:
                raise RuntimeError(err.decode('UTF-8', 'strict'))
            else:
                raise RuntimeError("could not connect to " + path)
        inst = ScamperInst.from_ptr(c)
        self._insts.append(inst)
        return inst

    def add_remote_dir(self, path):
        """
        add_remote_dir(path)
        add a :class:`ScamperInst` connected to each remote system available
        on the unix domain sockets.
        """
        for filename in os.listdir(path):
            pf = path + "/" + filename
            o = os.stat(pf)
            if not stat.S_ISSOCK(o.st_mode):
                continue
            c = clibscamperctrl.scamper_inst_remote(self._c, pf.encode('UTF-8'))
            if c == NULL:
                continue
            inst = ScamperInst.from_ptr(c)
            self._insts.append(inst)

    def exceptions(self):
        """
        exceptions()
        a generator that returns queued exceptions reporting errors
        from a :class:`ScamperInst`.
        """
        while len(self._exceptions) > 0:
            yield self._exceptions.pop(0)

    def responses(self, timeout=None, until=None):
        """
        responses(timeout=None, until=None)
        a generator that returns the objects for all issued measurements.
        this method will not return until all issued measurements have
        completed, or the timeout provided is reached.

        :param timedelta timeout: the maximum length of time to wait before
            returning
        :param datetime until: wait no longer than this timestamp before
            returning
        """
        cdef timeval tv
        cdef timeval *tv_ptr = NULL

        # process the timeout/until parameters, if provided.
        # if a timeout parameter is supplied, then calculate when the
        # method needs to complete by.
        if timeout is not None and until is not None:
            raise ValueError("cannot provide both timeout and until parameters")
        if timeout is not None:
            if not isinstance(timeout, datetime.timedelta):
                raise TypeError("timeout is not a timedelta")
            u = datetime.datetime.now() + timeout
            tv_ptr = &tv
        elif until is not None:
            if not isinstance(until, datetime.datetime):
                raise TypeError("until is not a datetime")
            u = until
            tv_ptr = &tv
        else:
            u = None

        while 1:
            # process queued data as follows:
            # - return all objects in the queue
            # - exit when there are no outstanding tasks left
            while len(self._objs) > 0:
                o = self._objs.pop(0)
                if self._meta or not isinstance(o, (ScamperList, ScamperCycle)):
                    yield o
            if len(self._tasks) == 0:
                break

            # handle any signals (e.g. KeyboardInterrupt)
            PyErr_CheckSignals()

            # set a timeout based on when the responses generator is
            # expected to be finished by.
            if u is not None:
                now = datetime.datetime.now()
                if u < now:
                    break
                diff = u - now
                tv.tv_sec = diff.seconds
                tv.tv_usec = diff.microseconds

            clibscamperctrl.scamper_ctrl_wait(self._c, tv_ptr)

    def poll(self, timeout=None, until=None):
        """
        poll(timeout=None, until=None)
        wait for a scamper object to become available from one of the
        :class:`ScamperInst` under management.  This method can raise
        exceptions collected by the :class:`ScamperCtrl` object.  These
        will be :py:exc:`RuntimeError` exceptions if scamper encountered
        a problem, as well as any of the exceptions that any user-provided
        callback function raises.

        :param timedelta timeout: the maximum length of time to wait before
            returning
        :param datetime until: wait no longer than this timestamp before
            returning
        :returns: a scamper object, or None if none are available.
        :rtype: a scamper object.
        """
        cdef timeval tv
        cdef timeval *tv_ptr = NULL

        if len(self._exceptions) > 0:
            raise self._exceptions.pop(0)
        while len(self._objs) > 0:
            o = self._objs.pop(0)
            if self._meta or not isinstance(o, (ScamperList, ScamperCycle)):
                return o

        if timeout is not None and until is not None:
            raise ValueError("cannot provide both timeout and until parameters")

        if timeout is not None:
            if not isinstance(timeout, datetime.timedelta):
                raise TypeError("timeout is not a timedelta")
            u = datetime.datetime.now() + timeout
            tv_ptr = &tv
        elif until is not None:
            if not isinstance(until, datetime.datetime):
                raise TypeError("until is not a datetime")
            u = until
            tv_ptr = &tv
        else:
            u = None

        while 1:
            if len(self._exceptions) > 0:
                raise self._exceptions.pop(0)
            while len(self._objs) > 0:
                o = self._objs.pop(0)
                if self._meta or not isinstance(o, (ScamperList, ScamperCycle)):
                    return o

            # handle any signals (e.g. KeyboardInterrupt)
            PyErr_CheckSignals()

            if self.is_done():
                return None

            # set a timeout based on when the wait is expected to return
            if u is not None:
                now = datetime.datetime.now()
                if u < now:
                    break
                diff = u - now
                tv.tv_sec = diff.seconds
                tv.tv_usec = diff.microseconds

            clibscamperctrl.scamper_ctrl_wait(self._c, tv_ptr)

        return None

    def done(self):
        """
        signal done on all instances.
        """
        for i in self._insts:
            i.done()

    def instances(self):
        """
        get method that returns a list of :class:`ScamperInst` managed by
        this :class:`ScamperCtrl` object.
        """
        return self._insts

    @property
    def taskc(self):
        """
        get method that returns the total number of tasks outstanding
        for this :class:`ScamperCtrl` object.
        """
        return len(self._tasks)

    @property
    def instc(self):
        """
        get method that returns the number of :class:`ScamperInst` managed by
        this :class:`ScamperCtrl` object.
        """
        return len(self._insts)

    def _getinst(self, inst):
        if inst is not None:
            if not isinstance(inst, ScamperInst):
                raise TypeError("inst not ScamperInst type")
        elif len(self._insts) == 0:
            raise RuntimeError("no connected ScamperInst")
        elif len(self._insts) != 1:
            raise RuntimeError("specify a ScamperInst")
        else:
            inst = self._insts[0]
        return inst

    cdef _task(self, clibscamperctrl.scamper_task_t *task,
               clibscamperctrl.scamper_inst_t *inst,
               bint sync):
        if sync:
            self._c_synctask = task
            self._syncdata = None
            while self._syncdata is None:
                # handle any signals (e.g. KeyboardInterrupt)
                PyErr_CheckSignals()
                if len(self._exceptions) > 0:
                    raise self._exceptions.pop(0)
                clibscamperctrl.scamper_ctrl_wait(self._c, NULL)
            o = self._syncdata
            self._c_synctask = NULL
            self._syncdata = None
            return o
        else:
            t = ScamperTask.from_ptr(task, inst)
            self._tasks.append(t)
            i = <ScamperInst> clibscamperctrl.scamper_inst_getparam(inst)
            i._tasks.append(t)
            return t

    def _do(self, cmd, inst=None, sync=False):
        """
        do(cmd, inst=None, sync=False)
        sends a manually-constructed command using scamper syntax to the scamper
        instance.  you should use one of the do_trace/do_ping/do_dns functions
        instead.

        :param string cmd: the command to send.
        :param ScamperInst inst: the instance to use.
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :returns: a task object representing the measurement
        :rtype: ScamperTask
        """
        inst = self._getinst(inst)
        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    # the optional parameters are ordered roughly according to the order
    # these appear in the underlying trace command
    def do_trace(self, dst, confidence=None, dport=None,
                 icmp_sum=None, firsthop=None, gaplimit=None, loops=None,
                 hoplimit=None, pmtud=None, squeries=None, ptr=None,
                 payload=None, method=None, attempts=None, all_attempts=None,
                 rtr=None, sport=None, src=None, tos=None,
                 wait_timeout=None, wait_probe=None,
                 userid=None, inst=None, sync=False):
        """
        do_trace(dst, confidence=None, dport=None,\
                 icmp_sum=None, firsthop=None, gaplimit=None, loops=None,\
                 hoplimit=None, pmtud=None, squeries=None, ptr=None,\
                 payload=None, method=None, attempts=None, all_attempts=None,\
                 rtr=None, sport=None, src=None, tos=None,\
                 wait_timeout=None, wait_probe=None,\
                 userid=None, inst=None, sync=False)
        conduct a traceroute guided by the assembled parameters.
        Only the dst parameter is required; scamper will use built-in
        defaults for the other optional parameters if they are not
        provided.  If any parameters conflict with other parameters
        (e.g., specifying a sport or dport while also specifying icmp-echo
        method) then this method will raise a :py:exc:`ValueError` exception.
        If this method could not queue the measurement, it will raise a
        :py:exc:`RuntimeError` exception.

        :param string dst: The destination IP address to probe
        :param ScamperInst inst: The specific instance to issue command over
        :param int attempts: The number of probes to send per hop
        :param bool all_attempts: Send all allotted attempts per hop
        :param int confidence: Confidence level before assuming all
            the interfaces have been observed that will reply at that hop
        :param int dport: The TCP/UDP destination port to use in probes
        :param int firsthop: The TTL to start probing with.
        :param int gaplimit: How many consecutive unresponsive hops before
            stopping traceroute
        :param int hoplimit: The maximum TTL to use before stopping traceroute
        :param int icmp_sum: The checksum to use in the ICMP header for
            icmp-paris traceroute
        :param int loops: The number of loops allowed before stopping
        :param string method: The method to use when sending probes
            Choices: icmp-paris, udp-paris, tcp, tck-ack, udp, icmp
        :param bytes payload: The payload to include in probes
        :param bool pmtud: Conduct Path MTU discovery for this traceroute
        :param bool ptr: Look up names for addresses in this traceroute
        :param string rtr: The first-hop router to send packets through
        :param int sport: The TCP/UDP source port to use in probes
        :param int squeries: The number of consecutive hops to probe before
            stopping to wait for a response
        :param string src: The source IP address to use in probes
        :param int tos: The byte to use in the field formally known as IP TOS
        :param int userid: The userid value to tag with this measurement
        :param timedelta wait_probe: The minimum length of time between probes
        :param timedelta wait_timeout: The length of time to wait for a response
             for a probe
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :returns: a task object representing the traceroute
        :rtype: ScamperTask
        """

        cmd = "trace"
        inst = self._getinst(inst)

        if method is not None:
            m = method.lower()
        else:
            m = None

        if sport is not None or dport is not None:
            if m is None:
                raise ValueError("specify method when specifying the source or destination port")
            elif not any(m.startswith(s) for s in ["tcp", "udp"]):
                raise ValueError("cannot specify source or destination ports with " + method)

        if icmp_sum is not None:
            if m is None:
                m = "icmp-paris"
            elif m != "icmp-paris":
                raise ValueError("cannot specify ICMP parameters with " + method)

        if confidence is not None:
            cmd = cmd + " -C " + str(confidence)
        if dport is not None:
            cmd = cmd + " -d " + str(dport)
        if firsthop is not None:
            cmd = cmd + " -f " + str(firsthop)
        if gaplimit is not None:
            cmd = cmd + " -g " + str(gaplimit)
        if loops is not None:
            cmd = cmd = " -l " + str(loops)
        if hoplimit is not None:
            cmd = cmd + " -m " + str(hoplimit)
        if pmtud is not None and pmtud is True:
            cmd = cmd + " -M"
        if squeries is not None:
            cmd = cmd + " -N " + str(squeries)
        if ptr is not None and ptr is True:
            cmd = cmd + " -O ptr"
        if payload is not None:
            cmd = cmd + " -p " + binascii.hexlify(payload).decode('ascii')
        if method is not None:
            cmd = cmd + " -P " + method
        if attempts is not None:
            cmd = cmd + " -q " + str(attempts)
        if all_attempts is not None and all_attempts is True:
            cmd = cmd + " -Q"
        if rtr is not None:
            cmd = cmd + " -r " + str(rtr)
        if sport is not None:
            cmd = cmd + " -s " + str(sport)
        if src is not None:
            cmd = cmd + " -S " + str(src)
        if tos is not None:
            cmd = cmd + " -t " + str(tos)
        if userid is not None:
            cmd = cmd + " -U " + str(userid)
        if wait_timeout is not None:
            if not isinstance(wait_timeout, datetime.timedelta):
                wait_timeout = datetime.timedelta(seconds=wait_timeout)
            cmd += f" -w {wait_timeout.total_seconds()}s"
        if wait_probe is not None:
            if not isinstance(wait_probe, datetime.timedelta):
                wait_probe = datetime.timedelta(seconds=wait_probe)
            cmd += f" -W {wait_probe.total_seconds()}s"
        cmd = cmd + " " + str(dst)

        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    def do_tracelb(self, dst, confidence=None, dport=None,
                   firsthop=None, gaplimit=None, method=None,
                   attempts=None, ptr=None, rtr=None, sport=None, tos=None,
                   wait_timeout=None, wait_probe=None,
                   userid=None, inst=None, sync=False):
        """
        do_tracelb(dst, confidence=None, dport=None, firsthop=None,\
                   gaplimit=None, method=None, attempts=None,\
                   ptr=None, rtr=None, sport=None, tos=None,\
                   wait_timeout=None, wait_probe=None,\
                   userid=None, inst=None, sync=False)
        conduct an MDA traceroute guided by the assembled parameters.
        Only the dst parameter is required; scamper will use built-in
        defaults for the other optional parameters if they are not
        provided.  If any parameters conflict with other parameters
        (e.g., specifying a sport or dport while also specifying icmp-echo
        method) then this method will raise a :py:exc:`ValueError` exception.
        If this method could not queue the measurement, it will raise a
        :py:exc:`RuntimeError` exception.

        :param string dst: The destination IP address to probe
        :param ScamperInst inst: The specific instance to issue command over
        :param int attempts: The number of probes to send per hop
        :param int confidence: Confidence level before assuming all
            the interfaces have been observed that will reply at that hop
        :param int dport: The TCP/UDP destination port to use in probes
        :param int gaplimit: How many consecutive unresponsive hops before
            stopping traceroute
        :param string method: The method to use when sending probes
            Choices: udp-dport, icmp-echo, udp-sport, tcp-sport, tcp-ack-sport
        :param bool ptr: Look up names for addresses in this traceroute
        :param string rtr: The first-hop router to send packets through
        :param int sport: The TCP/UDP source port to use in probes
        :param int tos: The byte to use in the field formally known as IP TOS
        :param int userid: The userid value to tag with this measurement
        :param timedelta wait_probe: The minimum length of time between probes
        :param timedelta wait_timeout: The length of time to wait for a response
             for a probe
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :returns: a task object representing the MDA traceroute
        :rtype: ScamperTask
        """

        cmd = "tracelb"
        inst = self._getinst(inst)

        if method is not None:
            m = method.lower()
        else:
            m = None

        if sport is not None or dport is not None:
            if m is None:
                raise ValueError("specify method when specifying the source or destination port")
            elif not any(m.startswith(s) for s in ["tcp", "udp"]):
                raise ValueError("cannot specify source or destination ports with " + method)

        if confidence is not None:
            cmd = cmd + " -c " + str(confidence)
        if dport is not None:
            cmd = cmd + " -d " + str(dport)
        if firsthop is not None:
            cmd = cmd + " -f " + str(firsthop)
        if gaplimit is not None:
            cmd = cmd + " -g " + str(gaplimit)
        if method is not None:
            cmd = cmd + " -P " + method
        if attempts is not None:
            cmd = cmd + " -q " + str(attempts)
        if ptr is not None and ptr is True:
            cmd = cmd + " -O ptr"
        if rtr is not None:
            cmd = cmd + " -r " + str(rtr)
        if sport is not None:
            cmd = cmd + " -s " + str(sport)
        if tos is not None:
            cmd = cmd + " -t " + str(tos)
        if userid is not None:
            cmd = cmd + " -U " + str(userid)
        if wait_timeout is not None:
            if not isinstance(wait_timeout, datetime.timedelta):
                wait_timeout = datetime.timedelta(seconds=wait_timeout)
            cmd += f" -w {wait_timeout.total_seconds()}s"
        if wait_probe is not None:
            if not isinstance(wait_probe, datetime.timedelta):
                wait_probe = datetime.timedelta(seconds=wait_probe)
            cmd += f" -W {wait_probe.total_seconds()}s"
        cmd = cmd + " " + str(dst)

        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    # the optional parameters are ordered roughly according to the order
    # these appear in the underlying ping command
    def do_ping(self, dst, tcp_ack=None, tcp_seq=None, attempts=None,
                icmp_id=None, icmp_seq=None, icmp_sum=None, dport=None,
                sport=None, wait_probe=None, ttl=None, mtu=None,
                stop_count=None, method=None, payload=None, rtr=None,
                recordroute=None, size=None, src=None, wait_timeout=None,
                tos=None, userid=None, inst=None, sync=False):
        """
        do_ping(dst, tcp_ack=None, tcp_seq=None, attempts=None,\
                icmp_id=None, icmp_seq=None, icmp_sum=None, dport=None,\
                sport=None, wait_probe=None, ttl=None, mtu=None,\
                stop_count=None, method=None, payload=None, rtr=None,\
                recordroute=None, size=None, src=None, wait_timeout=None,\
                tos=None, userid=None, inst=None, sync=False)
        conduct a ping guided by the assembled parameters.
        Only the dst parameter is required; scamper will use built-in
        defaults for the other optional parameters if they are not
        provided.  If any parameters conflict with other parameters
        (e.g., specifying a sport or dport while also specifying icmp-echo
        method) then this method will raise a :py:exc:`ValueError` exception.
        If this method could not queue the measurement, it will raise a
        :py:exc:`RuntimeError` exception.

        :param string dst: The destination IP address to probe
        :param ScamperInst inst: The specific instance to issue command over
        :param int attempts: The number of probes to send
        :param int dport: The TCP/UDP destination port to use in probes
        :param int icmp_id: The ID number to include in the ICMP header
        :param int icmp_seq: The sequence number to include in the ICMP header
        :param int icmp_sum: The checksum to use in the ICMP header
        :param string method: The method to use when sending probes.
            Choices: icmp-echo, icmp-time, udp, udp-port, tcp-syn,
            tcp-syn-sport, tcp-synack, tcp-ack, tcp-ack-sport, tcp-rst
        :param int mtu: The pseudo MTU to use for this ping; responses larger
            than this value will cause ping to send an ICMP packet-too-big to
            the destination.
        :param bytes payload: the payload to include in probes.
        :param bool recordroute: Include the IP record-route option in probes
        :param int stop_count: Stop pinging after receiving this many replies
        :param int rtr: The first-hop router to send packets through
        :param int size: The size of packets to send.
        :param int sport: The TCP/UDP source port to use in probes.
        :param string src: The source IP address to use in probes.
        :param int tcp_ack: The TCP acknowledgement value to use in probes,
            for tcp-ack, tcp-ack-sport, and tcp-synack methods.
        :param int tcp_seq: The TCP sequence value to use in probes,
            for tcp-syn, tcp-syn-sport, and tcp-rst methods.
        :param int tos: The byte to use in the field formally known as IP TOS
        :param int userid: The userid value to tag with the traceroute
        :param timedelta wait_probe: The minimum length of time between probes
        :param timedelta wait_timeout: The length of time to wait for response
            for a probe
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :returns: a task object representing the ping
        :rtype: ScamperTask
        """

        cmd = "ping"
        inst = self._getinst(inst)

        if dst is None:
            raise ValueError("dst cannot be none")

        if method is not None:
            m = method.lower()
        else:
            m = None

        # if user specifies tcp ack/syn then ensure method is appropriate tcp
        if tcp_ack is not None or tcp_seq is not None:
            if m is None:
                raise ValueError("specify method when specifying a TCP sequence or acknowledgement value")
            elif tcp_ack is not None and tcp_seq is not None:
                raise ValueError("can only specify either TCP sequence or acknowledgement value")
            elif icmp_sum is not None:
                raise ValueError("cannot specify ICMP checksum with TCP parameters")
            elif tcp_ack is not None and not m.startswith("tcp-ack"):
                raise ValueError("cannot specify tcp_ack with " + method)
            elif (tcp_seq is not None and
                  not any(m.startswith(s) for s in ["tcp-syn", "tcp-rst"])):
                raise ValueError("cannot specify tcp_seq with " + method)

        # if user specifies ICMP csum/id/seq then ensure method is icmp
        if icmp_sum is not None or icmp_id is not None or icmp_seq is not None:
            if m is None:
                m = "icmp-echo"
            elif not m.startswith("icmp"):
                raise ValueError("cannot specify ICMP parameters with " + method)

        # if user specifies sport/dport then ensure method is tcp or udp
        if sport is not None or dport is not None:
            if m is None:
                raise ValueError("specify method when specifying the source or destination port")
            elif not any(m.startswith(s) for s in ["tcp", "udp"]):
                raise ValueError("cannot specify source or destination ports with " + method)

        if tcp_ack is not None:
            cmd = cmd + " -A " + str(tcp_ack)
        if tcp_seq is not None:
            cmd = cmd + " -A " + str(tcp_seq)
        if payload is not None:
            cmd = cmd + " -B " + binascii.hexlify(payload).decode('ascii')
        if attempts is not None:
            cmd = cmd + " -c " + str(attempts)
        if icmp_sum is not None:
            cmd = cmd + " -C " + str(icmp_sum)
        if dport is not None:
            cmd = cmd + " -d " + str(dport)
        if icmp_seq is not None:
            cmd = cmd + " -d " + str(icmp_seq)
        if sport is not None:
            cmd = cmd + " -F " + str(sport)
        if icmp_id is not None:
            cmd = cmd + " -F " + str(icmp_id)
        if wait_probe is not None:
            if not isinstance(wait_probe, datetime.timedelta):
                wait_probe = datetime.timedelta(seconds=wait_probe)
            cmd += f" -i {wait_probe.total_seconds()}s"
        if ttl is not None:
            cmd = cmd + " -m " + str(ttl)
        if mtu is not None:
            cmd = cmd + " -M " + str(mtu)
        if stop_count is not None:
            cmd = cmd + " -o " + str(stop_count)
        if method is not None:
            cmd = cmd + " -P " + method
        if rtr is not None:
            cmd = cmd + " -r " + str(rtr)
        if recordroute is not None and recordroute:
            cmd = cmd + " -R "
        if size is not None:
            cmd = cmd + " -s " + str(size)
        if src is not None:
            cmd = cmd + " -S " + str(src)
        if userid is not None:
            cmd = cmd + " -U " + str(userid)
        if wait_timeout is not None:
            if not isinstance(wait_timeout, datetime.timedelta):
                wait_timeout = datetime.timedelta(seconds=wait_timeout)
            cmd += f" -W {wait_timeout.total_seconds()}s"
        if tos is not None:
            cmd = cmd + " -z " + str(tos)
        cmd = cmd + " " + str(dst)

        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    def do_dns(self, qname, server=None, qclass=None, qtype=None,
               attempts=None, rd=None, wait_timeout=None, tcp=None,
               userid=None, inst=None, sync=False):
        """
        do_dns(qname, server=None, qclass=None, qtype=None,
               attempts=None, rd=None, wait_timeout=None, tcp=None,
               userid=None, inst=None, sync=False)
        conduct a DNS measurement guided by the assembled parameters.
        Only the qname is required; scamper will use built-in defaults
        for the other optional parameters if they are not provided.
        If any parameters are invalid (e.g. a negative number of attempts)
        then this method will raise a :py:exc:`ValueError` exception.
        If this method could not queue the measurement, it will raise a
        :py:exc:`RuntimeError` exception.

        :param string qname: The name to query
        :param ScamperInst inst: The specific instance to issue command over
        :param string server: The DNS server to use
        :param string qclass: The query class to use
        :param string qtype: The query type to use
        :param int attempts: The number of queries to make before giving up
        :param timedelta wait_timeout: The length of time to wait for a response
        :param bool tcp: Use TCP instead of UDP for queries
        :param int userid: The userid value to tag with the DNS measurement
        :param bool rd: The recursion desired value to use
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :returns: a task object representing the DNS measurement
        :rtype: ScamperTask or the completed measurement if sync=True
        """

        cmd = "host"
        inst = self._getinst(inst)

        if attempts is not None and attempts < 1:
            raise ValueError("attempts < 1")

        if server is not None:
            cmd = cmd + " -s " + str(server)
        if qclass is not None:
            cmd = cmd + " -c " + qclass
        if qtype is not None:
            cmd = cmd + " -t " + qtype
        if attempts is not None:
            cmd = cmd + " -R " + str(attempts)
        if wait_timeout is not None:
            if not isinstance(wait_timeout, datetime.timedelta):
                wait_timeout = datetime.timedelta(seconds=wait_timeout)
            cmd += f" -W {wait_timeout.total_seconds()}s"
        if userid is not None:
            cmd = cmd + " -U " + str(userid)
        if rd is not None and not rd:
            cmd = cmd + " -r"
        if tcp is not None and tcp:
            cmd = cmd + " -T"
        cmd = cmd + " " + str(qname)

        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    def do_ally(self, dst1, dst2, fudge=None, icmp_sum=None, dport=None,
                sport=None, method=None, attempts=None, wait_probe=None,
                wait_timeout=None, userid=None, inst=None, sync=False):
        """
        do_ally(dst1, dst2, fudge=None, icmp_sum=None, dport=None,\
                sport=None, method=None, attempts=None, wait_probe=None,\
                wait_timeout=None, userid=None, inst=None, sync=False)
        conduct an Ally-style alias resolution measurement guided by the
        assembled parameters.  This measurement requires two destination
        addresses to probe.  The other parameters are optional, and scamper
        will use its built-in defaults if they are not provided.  If any
        parameters conflict with other parameters (e.g., specifying a sport
        or dport while also specifying icmp-echo method) then this method
        will raise a :py:exc:`ValueError` exception.  If this method could
        not queue the measurement, it will raise a :py:exc:`RuntimeError`
        exception.

        :param string dst1: The first address to test if it is an alias of
            the second address
        :param string dst2: The second address to test if it is an alias of
            the first address
        :param ScamperInst inst: The specific instance to issue command over
        :param int attempts: The number of probes to use in this measurement
        :param int dport: The TCP/UDP destination port to use in probes
        :param int fudge: The maximum difference between IPID values to
            still consider as possibly from the same counter
        :param int icmp_sum: The ICMP checksum to use in probes
        :param string method: The method to use when sending probes.
            Choices: udp, udp-dport, tcp-ack, tcp-ack-sport, tcp-syn-sport,
            and icmp-echo.
        :param int sport: The TCP/UDP source port to use in probes
        :param int userid: The userid value to tag with this measurement
        :param timedelta wait_probe: The minimum length of time between probes
        :param timedelta wait_timeout: The length of time to wait for a response
            for a probe
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :returns: a task object representing the alias resolution
        :rtype: ScamperTask
        """

        cmd = "dealias -m ally"
        inst = self._getinst(inst)

        if method is not None:
            m = method.lower()
        else:
            m = None

        # if user specifies ICMP csum then ensure method is icmp
        if icmp_sum is not None:
            if m is None:
                m = "icmp-echo"
            elif not m.startswith("icmp"):
                raise ValueError("do not specify icmp_sum with " + method)
            if sport is not None or dport is not None:
                raise ValueError("cannot specify source or destination port with " + method)

        # if user specifies sport/dport then ensure method is tcp or udp
        if sport is not None or dport is not None:
            if m is None:
                raise ValueError("specify method when specifying the source or destination port")
            elif not any(m.startswith(s) for s in ["tcp", "udp"]):
                raise ValueError("cannot specify source or destination ports with " + method)

        # if user specifies a method, then construct a probedef
        if m is not None:
            cmd = cmd + " -p '-P " + m
            if sport is not None:
                cmd = cmd + " -F " + str(sport)
            if dport is not None:
                cmd = cmd + " -d " + str(dport)
            if icmp_sum is not None:
                cmd = cmd + " -c " + str(icmp_sum)
            cmd = cmd + "'"

        # other parameters to the dealias method
        if fudge is not None:
            if fudge == 0:
                cmd = cmd + " -O inseq"
            else:
                cmd = cmd + " -f " + str(fudge)
        if userid is not None:
            cmd = cmd + " -U " + str(userid)
        if wait_probe is not None:
            if not isinstance(wait_probe, datetime.timedelta):
                wait_probe = datetime.timedelta(seconds=wait_probe)
            cmd += f" -W {wait_probe.total_seconds()}s"
        if wait_timeout is not None:
            if not isinstance(wait_timeout, datetime.timedelta):
                wait_timeout = datetime.timedelta(seconds=wait_timeout)
            cmd += f" -w {wait_timeout.total_seconds()}s"
        cmd = cmd + " " + str(dst1) + " " + str(dst2)

        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    def do_mercator(self, dst, userid=None, inst=None, sync=False):
        """
        do_mercator(dst, userid=None, inst=None, sync=False)
        conduct a Mercator-style alias resolution measurement to the
        specified destination.  If this method could not queue the
        measurement, it will raise a :py:exc:`RuntimeError` exception.

        :param string dst: the destination to probe
        :param ScamperInst inst: The specific instance to issue command over
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :returns: a task object representing the mercator alias resolution
        :rtype: ScamperTask
        """

        cmd = "dealias -m mercator"
        inst = self._getinst(inst)

        if userid is not None:
            cmd = cmd + " -U " + str(userid)
        cmd = cmd + " " + str(dst)

        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    def do_midarest(self, rounds=None, wait_probe=None, wait_round=None,
                    wait_timeout=None, probedefs=None, addrs=None,
                    userid=None, inst=None, sync=False):
        """
        do_midarest(rounds=None, wait_probe=None, wait_round=None,\
                    wait_timeout=None, probedefs=None, addrs=None,\
                    userid=None, inst=None, sync=False)
        conduct MIDAR-style estimation-stage probing of a set of IP
        addresses.  If this method could not queue the
        measurement, it will raise a :py:exc:`RuntimeError` exception.

        :param ScamperInst inst: The specific instance to issue command over
        :param int rounds: The number of rounds to use in this measurement
        :param int userid: The userid value to tag with this measurement
        :param timedelta wait_probe: The minimum length of time between probes
        :param timedelta wait_round: The minimum length of time between rounds
        :param timedelta wait_timeout: The length of time to wait for a response
            for a probe
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :param list probedefs: The list of probe types to use
        :param list addrs: The list of addresses to probe
        :returns: a task object representing the midarest alias resolution
        :rtype: ScamperTask
        """
        cmd = "dealias -m midarest"
        inst = self._getinst(inst)

        if probedefs is None:
            raise ValueError("missing probedefs")
        if addrs is None:
            raise ValueError("missing addrs")

        if rounds is not None:
            if not isinstance(rounds, int):
                raise ValueError("rounds not an integer")
            cmd += f" -q {rounds}"
        if userid is not None:
            if not isinstance(userid, int):
                raise ValueError("userid not an integer")
            cmd += f" -U {userid}"
        if wait_probe is not None:
            if not isinstance(wait_probe, datetime.timedelta):
                wait_probe = datetime.timedelta(seconds=wait_probe)
            ms = int(wait_probe.seconds * 1000) + int(wait_probe.microseconds / 1000)
            if ms <= 0:
                raise ValueError("wait_probe must be at least 1ms")
            cmd += f" -W {ms}"
        if wait_timeout is not None:
            if not isinstance(wait_timeout, datetime.timedelta):
                wait_timeout = datetime.timedelta(seconds=wait_timeout)
            s = int(wait_timeout.seconds)
            if s <= 0:
                raise ValueError("wait_timeout must be at least 1s")
            cmd += f" -w {s}"
        if wait_round is not None:
            if not isinstance(wait_round, datetime.timedelta):
                wait_round = datetime.timedelta(seconds=wait_round)
            ms = int(wait_round.seconds * 1000) + int(wait_round.microseconds / 1000)
            if ms <= 0:
                raise ValueError("wait_round must be at least 1ms")
            cmd += f" -r {ms}"

        for pd in probedefs:
            if not isinstance(pd, ScamperDealiasProbedef):
                raise ValueError("expected probedef in probedefs")
            cmd += f" -p '{pd}'"
        for addr in addrs:
            if not isinstance(addr, str) and not isinstance(addr, ScamperAddr):
                raise ValueError("expected str in addrs")
            cmd += f" {addr}"

        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    def do_midardisc(self, probedefs=None, schedule=None,
                     startat=None, wait_timeout=None,
                     userid=None, inst=None, sync=False):
        """
        do_midardisc(probedefs=None, schedule=None,\
                     startat=None, wait_timeout=None,\
                     userid=None, inst=None, sync=False)
        conduct MIDAR-style discovery-stage probing of a set of IP
        addresses.  If this method could not queue the
        measurement, it will raise a :py:exc:`RuntimeError` exception.

        :param ScamperInst inst: The specific instance to issue command over
        :param int userid: The userid value to tag with this measurement
        :param datetime startat: The time to start the measurement at
        :param timedelta wait_timeout: The length of time to wait for a
            response to a probe
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :param list probedefs: The list of probe types and IPs to probe
        :returns: a task object representing the midardisc alias resolution
        :rtype: ScamperTask
        """
        cmd = "dealias -m midardisc"
        inst = self._getinst(inst)

        if probedefs is None:
            raise ValueError("missing probedefs")
        if schedule is None:
            raise ValueError("missing schedule")

        if userid is not None:
            if not isinstance(userid, int):
                raise ValueError("userid not an integer")
            cmd += f" -U {userid}"
        if wait_timeout is not None:
            if not isinstance(wait_timeout, datetime.timedelta):
                wait_timeout = datetime.timedelta(seconds=wait_timeout)
            s = int(wait_timeout.seconds)
            if s <= 0:
                raise ValueError("wait_timeout must be at least 1s")
            cmd += f" -w {s}"
        if startat is not None:
            if not isinstance(startat, datetime.datetime):
                raise ValueError("startat not a datetime")
            cmd += f" -@ {startat.timestamp()}"

        for pd in probedefs:
            if not isinstance(pd, ScamperDealiasProbedef):
                raise ValueError("expected probedef in probedefs")
            if pd.dst is None:
                raise ValueError("missing IP address in probedef")
            cmd += f" -p '{pd}'"

        for s in schedule:
            if not isinstance(s, ScamperDealiasMidardiscRound):
                raise ValueError("expected round in schedule")
            cmd += f" -S {s}"

        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    def do_radargun(self, addrs=None, rounds=None, probedefs=None,
                    wait_probe=None, wait_round=None, wait_timeout=None,
                    userid=None, inst=None, sync=False):
        """
        do_radargun(addrs=None, rounds=None, probedefs=None,\
                    wait_probe=None, wait_round=None, wait_timeout=None,\
                    userid=None, inst=None, sync=False):
        conduct Radargun-style probing of a set of IP addresses.
        If this method could not queue the measurement, it will raise a
        :py:exc:`RuntimeError` exception.

        :param list addrs: The addresses to probe.  This parameter is
        :param int rounds: The number of rounds for this measurement.
        :param list probedefs: The list of probe types to use.
            This parameter is mandatory.
            If a list of addresses is provided, then the probedefs must
            not also contain IP addresses.
            If a list of addresses is not provided, then the probedefs must
            contain IP addresses.
        :param timedelta wait_probe: The minimum delay between two probes.
        :param timedelta wait_round: The length of time between starting
            consecutive rounds.
        :param timedelta wait_timeout: The length of time to wait for a
            response to a probe.
        :param int userid: The userid value to tag with this measurement
        :param ScamperInst inst: The specific instance to issue command over
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :returns: a task object representing the radargun alias resolution
        :rtype: ScamperTask
        """
        cmd = "dealias -m radargun"
        inst = self._getinst(inst)

        if probedefs is None:
            raise ValueError("missing probedefs")

        if rounds is not None:
            if not isinstance(rounds, int):
                raise ValueError("rounds not an integer")
            cmd += f" -q {rounds}"

        if userid is not None:
            if not isinstance(userid, int):
                raise ValueError("userid not an integer")
            cmd += f" -U {userid}"

        if wait_probe is not None:
            if not isinstance(wait_probe, datetime.timedelta):
                wait_probe = datetime.timedelta(seconds=wait_probe)
            if wait_probe <= datetime.timedelta(seconds=0):
                raise ValueError("wait_probe must be greater than zero")
            cmd += f" -W {wait_probe.total_seconds()}s"

        if wait_round is not None:
            if not isinstance(wait_round, datetime.timedelta):
                wait_round = datetime.timedelta(seconds=wait_round)
            if wait_round <= datetime.timedelta(seconds=0):
                raise ValueError("wait_round must be greater than zero")
            cmd += f" -r {wait_round.total_seconds()}s"

        if wait_timeout is not None:
            if not isinstance(wait_timeout, datetime.timedelta):
                wait_timeout = datetime.timedelta(seconds=wait_timeout)
            if not wait_timeout >= datetime.timedelta(seconds=1):
                raise ValueError("wait_timeout must be at least 1s")
            cmd += f" -w {wait_timeout.total_seconds()}s"

        for pd in probedefs:
            if not isinstance(pd, ScamperDealiasProbedef):
                raise ValueError("expected probedef in probedefs")
            if addrs is None and pd.dst is None:
                raise ValueError("missing IP address in probedef")
            elif addrs is not None and pd.dst is not None:
                raise ValueError("unexpected IP address in probedef")
            cmd += f" -p '{pd}'"

        if addrs is not None:
            for a in addrs:
                cmd += f" {a}"

        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    def do_prefixscan(self, near, far, prefixlen, fudge=None,
                      icmp_sum=None, dport=None, sport=None, method=None,
                      attempts=None, wait_probe=None, wait_timeout=None,
                      userid=None, inst=None, sync=False):
        """
        do_prefixscan(near, far, prefixlen, fudge=None,\
                      icmp_sum=None, dport=None, sport=None, method=None,\
                      attempts=None, wait_probe=None, wait_timeout=None,\
                      userid=None, inst=None, sync=False)
        find an alias on near that is within a subnet containing far.
        This measurement requires two addresses defining a link to probe,
        and the size of the prefix to search.
        The other parameters are optional, and scamper will use its
        built-in defaults if they are not provided.  If any
        parameters conflict with other parameters (e.g., specifying a sport
        or dport while also specifying icmp-echo method) then this method
        will raise a :py:exc:`ValueError` exception.  If this method could
        not queue the measurement, it will raise a :py:exc:`RuntimeError`
        exception.

        :param string near: the near hop in a traceroute
        :param string far: the far hop in a traceroute, consecutive to near
        :param int prefixlen: the size of the subnet to search
        :param ScamperInst inst: The specific instance to issue command over
        :param int attempts: The number of probes to use in this measurement
        :param int dport: The TCP/UDP destination port to use in probes
        :param int fudge: The maximum difference between IPID values to
            still consider as possibly from the same counter
        :param int icmp_sum: The ICMP checksum to use in probes
        :param string method: The method to use when sending probes.
            Choices: udp, udp-dport, tcp-ack, tcp-ack-sport, tcp-syn-sport,
            and icmp-echo.
        :param int sport: The TCP/UDP source port to use in probes
        :param int userid: The userid value to tag with this measurement
        :param timedelta wait_probe: The minimum length of time between probes
        :param timedelta wait_timeout: The length of time to wait for a response
            for a probe
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :returns: a task object representing the prefixscan alias resolution
        :rtype: ScamperTask
        """

        cmd = "dealias -m prefixscan"
        inst = self._getinst(inst)

        if method is not None:
            m = method.lower()
        else:
            m = None

        # if user specifies ICMP csum then ensure method is icmp
        if icmp_sum is not None:
            if m is None:
                m = "icmp-echo"
            elif not m.startswith("icmp"):
                raise ValueError("do not specify icmp_sum with " + method)
            if sport is not None or dport is not None:
                raise ValueError("cannot specify source or destination port with " + method)

        # if user specifies sport/dport then ensure method is tcp or udp
        if sport is not None or dport is not None:
            if m is None:
                raise ValueError("specify method when specifying the source or destination port")
            elif not any(m.startswith(s) for s in ["tcp", "udp"]):
                raise ValueError("cannot specify source or destination ports with " + method)

        # if user specifies fudge, validate it
        if fudge is not None and (fudge < 0 or fudge > 65535):
            raise ValueError("fudge value must be between 0-65535")

        # set probe method to udp by default
        if m is None:
            m = "udp"

        # if user specifies a method, then construct a probedef
        if m is not None:
            cmd = cmd + " -p '-P " + m
            if sport is not None:
                cmd = cmd + " -F " + str(sport)
            if dport is not None:
                cmd = cmd + " -d " + str(dport)
            if icmp_sum is not None:
                cmd = cmd + " -c " + str(icmp_sum)
            cmd = cmd + "'"

        # other parameters to the dealias method
        if fudge is not None:
            if fudge == 0:
                cmd = cmd + " -O inseq"
            else:
                cmd = cmd + " -f " + str(fudge)
        if userid is not None:
            cmd = cmd + " -U " + str(userid)
        if wait_probe is not None:
            if not isinstance(wait_probe, datetime.timedelta):
                wait_probe = datetime.timedelta(seconds=wait_probe)
            cmd += f" -W {wait_probe.total_seconds()}s"
        if wait_timeout is not None:
            if not isinstance(wait_timeout, datetime.timedelta):
                wait_timeout = datetime.timedelta(seconds=wait_timeout)
            cmd += f" -w {wait_timeout.total_seconds()}s"

        cmd = cmd + " " + str(near) + " " + str(far) + "/" + str(prefixlen)

        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    def do_sniff(self, src, icmp_id, limit_pkt_count=None, limit_time=None,
                 userid=None, inst=None, sync=False):
        """
        do_sniff(src, icmp_id, limit_pkt_count=None, limit_time=None,\
                 userid=None, inst=None, sync=False)
        capture packets matching a specific ICMP ID value on an interface
        identified by a source IP address.

        :param string src: The source address of the interface to listen on
        :param int icmp_id: The ICMP ID value to match
        :param ScamperInst inst: The specific instance to issue command over
        :param int limit_pkt_count: The maximum number of packets to capture
        :param timedelta limit_time: The maximum length of time to listen
        :param int userid: The userid value to tag with this measurement
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :returns: a task object representing the sniff capture
        :rtype: ScamperTask
        """

        cmd = "sniff -S " + str(src)
        inst = self._getinst(inst)

        if icmp_id < 0 or icmp_id > 65535:
            raise ValueError("invalid ICMP ID")
        if limit_pkt_count is not None and limit_pkt_count < 1:
            raise ValueError("invalid limit_pkt_count")
        if limit_time is not None and limit_time < 1:
            raise ValueError("invalid limit_time")

        if limit_pkt_count is not None:
            cmd = cmd + " -c " + str(limit_pkt_count)
        if limit_time is not None:
            if not isinstance(limit_time, datetime.timedelta):
                limit_time = datetime.timedelta(seconds=limit_time)
            cmd += f" -G {limit_time.total_seconds()}s"
        if userid is not None:
            cmd = cmd + " -U " + str(userid)

        cmd = cmd + " icmp[icmpid] == " + str(icmp_id)

        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    def do_http(self, dst, url, headers=None, insecure=False, limit_time=None,
                userid=None, inst=None, sync=False):
        """
        do_http(dst, url, headers=None, insecure=False, limit_time=None,\
                userid=None, inst=None, sync=False)
        conduct a HTTP request of the URL with the specified
        destination.  If this method could not queue the measurement,
        it will raise a :py:exc:`RuntimeError` exception.

        :param string dst: the destination IP address to connect to
        :param string url: the URL to use for this HTTP request
        :param dict headers: a dictionary of headers to include in the request
        :param bool insecure: do not do TLS validation on certificate
        :param timedelta limit_time: the maximum time for this measurement to run
        :param int userid: the userid value to tag with this measurement
        :param ScamperInst inst: The specific instance to issue command over
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :returns: a task object representing the HTTP request
        :rtype: ScamperTask
        """

        cmd = "http"
        inst = self._getinst(inst)

        if dst is None:
            raise ValueError("invalid dst")
        if url is None:
            raise ValueError("invalid url")

        if insecure is True:
            cmd = cmd + " -O insecure"

        if limit_time is not None:
            if not isinstance(limit_time, datetime.timedelta):
                limit_time = datetime.timedelta(seconds=limit_time)
            cmd = cmd + f" -m {limit_time.total_seconds()}s"

        if headers is not None:
            if not isinstance(headers, dict):
                raise ValueError("headers not dictionary")
            for fname in headers:
                if not isinstance(fname, str) or not fname.isascii():
                    raise ValueError("header field-name is not ascii")
                fbody = headers[fname]
                if not isinstance(fbody, str) or not fbody.isascii():
                    raise ValueError("header field-body is not ascii")
                cmd = cmd + f" -H '{fname}: {fbody}'"

        cmd = cmd + " -u '" + str(url) + "' " + str(dst)
        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    def do_udpprobe(self, dst, dport, payload, attempts=None,
                    stop_count=None, inst=None, userid=None, sync=False):
        """
        do_udpprobe(dst, dport, payload, attempts=None, stop_count=None,\
                    inst=None, userid=None, sync=False)
        conduct a UDP probe specified destination, port, and payload.
        If this method could not queue the measurement,
        it will raise a :py:exc:`RuntimeError` exception.

        :param string dst: the destination address to send the probe to
        :param int dport: the destination port to send the probe to
        :param bytes payload: the payload to include in the probe
        :param int attempts: the number of probes to send
        :param int stop_count: stop after receiving replies to this many probes
        :param int userid: the userid value to tag with this measurement
        :param ScamperInst inst: The specific instance to issue command over
        :param bool sync: operate the measurement synchronously
            (the method returns when the measurement completes).
        :returns: an object representing the UDP probe task.
        :rtype: ScamperTask
        """

        cmd = "udpprobe"
        inst = self._getinst(inst)

        if dst is None or dport is None or payload is None:
            raise ValueError("must specify destination address, port, and payload")
        if dport < 1 or dport > 65535:
            raise ValueError(f"invalid destination port {dport}")

        cmd = cmd + f" -d {dport}"
        cmd = cmd + " -p " + binascii.hexlify(payload).decode('ascii')
        if attempts is not None:
            cmd = cmd + " -c " + str(attempts)
        if stop_count is not None:
            cmd = cmd + " -o " + str(stop_count)
        if userid is not None:
            cmd = cmd + " -U " + userid
        cmd = cmd + f" {dst}"

        c = clibscamperctrl.scamper_inst_do((<ScamperInst>inst)._c,
                                            cmd.encode('UTF-8'), NULL)
        if c == NULL:
            raise RuntimeError("could not schedule command")
        return self._task(c, (<ScamperInst>inst)._c, sync)

    def is_done(self):
        """
        get method to determine if all of the :class:`ScamperInst` have
        signalled that they are now finished

        :returns: True if all done
        :rtype: bool
        """
        if len(self._objs) > 0:
            return False
        return clibscamperctrl.scamper_ctrl_isdone(self._c)

cdef class ScamperInst:
    """
    A :class:`ScamperInst` represents a connection to a single scamper
    instance, for which we can issue measurement requests.
    This class implements functions for sorting and hashing.
    """
    cdef clibscamperctrl.scamper_inst_t *_c
    cdef cscamper_file.scamper_file_t *_c_f
    cdef cscamper_file.scamper_file_readbuf_t *_c_rb
    cdef object _tasks # = []

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        while len(self._tasks) > 0:
            self._tasks.pop(0)
        if self._c_f != NULL:
            cscamper_file.scamper_file_close(self._c_f)
        if self._c_rb != NULL:
            cscamper_file.scamper_file_readbuf_free(self._c_rb)
        if self._c != NULL:
            clibscamperctrl.scamper_inst_free(self._c)

    def __eq__(self, other):
        if not isinstance(other, ScamperInst):
            return NotImplemented
        return self._c == (<ScamperInst>other)._c

    def __ne__(self, other):
        if not isinstance(other, ScamperInst):
            return NotImplemented
        return self._c != (<ScamperInst>other)._c

    def __lt__(self, other):
        if not isinstance(other, ScamperInst):
            return NotImplemented
        return self._c < (<ScamperInst>other)._c

    def __le__(self, other):
        if not isinstance(other, ScamperInst):
            return NotImplemented
        return self._c <= (<ScamperInst>other)._c

    def __gt__(self, other):
        if not isinstance(other, ScamperInst):
            return NotImplemented
        return self._c > (<ScamperInst>other)._c

    def __ge__(self, other):
        if not isinstance(other, ScamperInst):
            return NotImplemented
        return self._c >= (<ScamperInst>other)._c

    def __hash__(self):
        return hash((<Py_ssize_t>self._c))

    def __str__(self):
        c_name = clibscamperctrl.scamper_inst_getname(self._c)
        if c_name == NULL:
            return None
        return c_name.decode('UTF-8', 'strict')

    @staticmethod
    cdef ScamperInst from_ptr(clibscamperctrl.scamper_inst_t *ptr):
        cdef ScamperInst inst = ScamperInst.__new__(ScamperInst)
        inst._c = ptr
        inst._c_f = cscamper_file.scamper_file_opennull(ord('r'), "warts")
        inst._c_rb = cscamper_file.scamper_file_readbuf_alloc()
        inst._tasks = []
        cscamper_file.scamper_file_setreadfunc(inst._c_f, inst._c_rb,
                                               cscamper_file.scamper_file_readbuf_read)
        clibscamperctrl.scamper_inst_setparam(ptr, <PyObject *>inst)
        return inst

    @property
    def name(self):
        """
        return a friendly string that identifies the instance in some way
        """
        c_name = clibscamperctrl.scamper_inst_getname(self._c)
        if c_name == NULL:
            return None
        name = c_name.decode('UTF-8', 'strict')
        # if the name looks like /path/to/foobar-192.0.2.1:31337 then
        # return foobar
        match = re.search("(?:.+\/)?(.+)-", name)
        if match:
            return match.group(1)
        return name

    @property
    def taskc(self):
        """
        get method that returns the total number of tasks outstanding
        for this :class:`ScamperInst` object.
        """
        return len(self._tasks)

    def done(self):
        """
        signal that there are no further measurements to come on this
        ScamperInst
        """
        clibscamperctrl.scamper_inst_done(self._c)

cdef class ScamperTask:
    """
    A :class:`ScamperTask` object represents a scheduled measurement.
    This class implements functions for sorting and hashing.
    """
    cdef clibscamperctrl.scamper_task_t *_c
    cdef clibscamperctrl.scamper_inst_t *_c_i

    def __init__(self):
        raise TypeError("This class cannot be instantiated directly.")

    def __dealloc__(self):
        if self._c != NULL:
            clibscamperctrl.scamper_task_free(self._c)

    def __eq__(self, other):
        if not isinstance(other, ScamperTask):
            return NotImplemented
        return self._c == (<ScamperTask>other)._c

    def __ne__(self, other):
        if not isinstance(other, ScamperTask):
            return NotImplemented
        return self._c != (<ScamperTask>other)._c

    def __lt__(self, other):
        if not isinstance(other, ScamperTask):
            return NotImplemented
        return self._c < (<ScamperTask>other)._c

    def __le__(self, other):
        if not isinstance(other, ScamperTask):
            return NotImplemented
        return self._c <= (<ScamperTask>other)._c

    def __gt__(self, other):
        if not isinstance(other, ScamperTask):
            return NotImplemented
        return self._c > (<ScamperTask>other)._c

    def __ge__(self, other):
        if not isinstance(other, ScamperTask):
            return NotImplemented
        return self._c >= (<ScamperTask>other)._c

    def __hash__(self):
        return hash((<Py_ssize_t>self._c))

    @staticmethod
    cdef ScamperTask from_ptr(clibscamperctrl.scamper_task_t *ptr,
                              clibscamperctrl.scamper_inst_t *inst):
        cdef ScamperTask task = ScamperTask.__new__(ScamperTask)
        clibscamperctrl.scamper_task_use(ptr)
        clibscamperctrl.scamper_task_setparam(ptr, <PyObject *>task)
        task._c = ptr
        task._c_i = inst
        return task

    def halt(self):
        """
        halt a measurement underway
        """
        clibscamperctrl.scamper_inst_halt(self._c_i, self._c)
