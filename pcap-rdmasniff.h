pcap_t *rdmasniff_create(const char *device, char *ebuf, int *is_ours);
int rdmasniff_findalldevs(Interfaces *devlistp, char *err_str);
