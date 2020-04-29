# DLT and LINKTYPE allocation

DLT\_ types live in pcap/dlt.h. They can be requested by the community on a
First-Come First-Served basis [i.e. https://tools.ietf.org/html/rfc8126#section-4.4 ]
(Although libpcap is not at this time an IETF specification, there have been
some as yet-incomplete efforts to do this).

The Tcpdump Group prefers to link to an open specification on the new DLT*
type, but they are available for closed, proprietary projects as well.
In that case, a stable email address suffices so that someone who finds
an unknown DLT* type can investigate.
We prefer to give out unambiguous numbers, and we try to do it as quickly
as possible, but DLT_USERx is available while you wait.

Note that DLT* types are, in theory, private to the capture mechanism and can
in some cases be operating system specific, and so a second set of values,
LINKTYPE* is allocated for actually writing to pcap files. As much as
possible going forward, the DLT* and LINKTYPE* value are identical, however,
this was not always the case. See pcap-common.cpp.

The LINKTYPE\_ values are not exported, but are in pcap-common.cpp only.

## DEVELOPER NOTES

When allocating a new DLT\_ value, a corresponding value needs to be
added to pcap-common.cpp.
It is not necessary to copy the comments from dlt.h to pcap-common.cpp.
