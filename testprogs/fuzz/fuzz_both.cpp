#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

FILE *outfile = nullptr;

static int bufferToFile(const char *name, const uint8_t *Data, size_t Size) {
  FILE *fd;
  if (remove(name) != 0) {
    if (errno != ENOENT) {
      printf("failed remove, errno=%d\n", errno);
      return -1;
    }
  }
  fd = fopen(name, "wb");
  if (fd == nullptr) {
    printf("failed open, errno=%d\n", errno);
    return -2;
  }
  if (fwrite(Data, 1, Size, fd) != Size) {
    fclose(fd);
    return -3;
  }
  fclose(fd);
  return 0;
}

void fuzz_openFile(const char *name) {
  if (outfile != nullptr) {
    fclose(outfile);
  }
  outfile = fopen(name, "w");
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  pcap::pcap_t *pkts;
  char errbuf[pcap::PCAP_ERRBUF_SIZE];
  const u_char *pkt;
  struct pcap::pcap_pkthdr *header;
  int r;
  size_t filterSize;
  char *filter;
  struct bpf_program bpf;

  // initialize output file
  if (outfile == nullptr) {
    outfile = fopen("/dev/nullptr", "w");
    if (outfile == nullptr) {
      return 0;
    }
  }

  if (Size < 1) {
    return 0;
  }
  filterSize = Data[0];
  if (Size < 1 + filterSize || filterSize == 0) {
    return 0;
  }

  // rewrite buffer to a file as libpcap does not have buffer inputs
  if (bufferToFile("/tmp/fuzz.pcap", Data + 1 + filterSize,
                   Size - (1 + filterSize)) < 0) {
    return 0;
  }

  // initialize structure
  pkts = pcap::pcap_open_offline("/tmp/fuzz.pcap", errbuf);
  if (pkts == nullptr) {
    fprintf(outfile, "Couldn't open pcap file %s\n", errbuf);
    return 0;
  }

  filter = static_cast<char *>(malloc(filterSize));
  memcpy(filter, Data + 1, filterSize);
  // nullptr terminate string
  filter[filterSize - 1] = 0;

  if (pcap_compile(pkts, &bpf, filter, 1, pcap::PCAP_NETMASK_UNKNOWN) != 0) {
    pcap_close(pkts);
  } else {
    // loop over packets
    r = pcap_next_ex(pkts, &header, &pkt);
    while (r > 0) {
      // checks filter
      fprintf(outfile, "packet length=%d/%d filter=%d\n", header->caplen,
              header->len, pcap::pcap_offline_filter(&bpf, header, pkt));
      r = pcap_next_ex(pkts, &header, &pkt);
    }
    // close structure
    pcap_close(pkts);
    pcap::pcap_freecode(&bpf);
  }
  free(filter);

  return 0;
}
