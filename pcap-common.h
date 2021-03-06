/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * pcap-common.h - common code for pcap and pcapng files
 */

/*
 * We use the "receiver-makes-right" approach to byte order,
 * because time is at a premium when we are writing the file.
 * In other words, the pcap_file_header and pcap_pkthdr,
 * records are written in host byte order.
 * Note that the bytes of packet data are written out in the order in
 * which they were received, so multi-byte fields in packets are not
 * written in host byte order, they're written in whatever order the
 * sending machine put them in.
 *
 * ntoh[ls] aren't sufficient because we might need to swap on a big-endian
 * machine (if the file was written in little-end order).
 */

#ifndef pcap_common_h
#define pcap_common_h

#include <climits>
namespace pcap {

template <typename T> static inline constexpr T swap_endian(T u) {
  static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");

  T ret = 0;

  for (size_t k = 0; k < sizeof(T); k++) {
    ret <<= CHAR_BIT;
    ret += u & uint8_t(-1);
    u >>= CHAR_BIT;
  }

  return ret;
}

static inline constexpr uint32_t SWAPLONG(uint32_t y) {
  return swap_endian(uint32_t(y));
}

static inline constexpr uint16_t SWAPSHORT(uint16_t y) {
  return swap_endian(uint16_t(y));
}

extern int dlt_to_linktype(int dlt);

extern int linktype_to_dlt(int linktype);

extern void swap_pseudo_headers(int linktype, struct pcap_pkthdr *hdr,
                                u_char *data);

extern u_int max_snaplen_for_dlt(int dlt);

} // namespace pcap
#endif