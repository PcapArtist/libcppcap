#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

void fuzz_openFile(const char *name) {
  // do nothing
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  pcap::pcap_t *pkts;
  struct bpf_program bpf;
  char *filter;

  // we need at least 1 byte for linktype
  if (Size < 1) {
    return 0;
  }

  // initialize structure snaplen = 65535
  pkts = pcap::pcap_open_dead(Data[Size - 1], 0xFFFF);
  if (pkts == nullptr) {
    printf("pcap_open_dead failed\n");
    return 0;
  }
  filter = static_cast<char *>(malloc(Size));
  memcpy(filter, Data, Size);
  // nullptr terminate string
  filter[Size - 1] = 0;

  if (pcap_compile(pkts, &bpf, filter, 1, pcap::PCAP_NETMASK_UNKNOWN) != 0) {
    pcap_close(pkts);
  } else {
    pcap_setfilter(pkts, &bpf);
    pcap_close(pkts);
    pcap::pcap_freecode(&bpf);
  }
  free(filter);

  return 0;
}
