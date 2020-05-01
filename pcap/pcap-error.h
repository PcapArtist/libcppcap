
#ifndef pcap_error_h
#define pcap_error_h
#include <string>

namespace pcap {

static constexpr std::string::size_type PCAP_ERRBUF_SIZE = 256;

struct PcapError {
  std::string string = std::string(PCAP_ERRBUF_SIZE, '\0');
};

} // namespace pcap

#endif