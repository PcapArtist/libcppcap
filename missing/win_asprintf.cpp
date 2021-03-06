#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "portability.h"

int pcap_vasprintf(char **strp, const char *format, va_list args) {
  int len;
  size_t str_size;
  char *str;
  int ret;

  len = _vscprintf(format, args);
  if (len == -1) {
    *strp = nullptr;
    return (-1);
  }
  str_size = len + 1;
  str = malloc(str_size);
  if (str == nullptr) {
    *strp = nullptr;
    return (-1);
  }
  ret = vsnprintf(str, str_size, format, args);
  if (ret == -1) {
    free(str);
    *strp = nullptr;
    return (-1);
  }
  *strp = str;
  /*
   * vsnprintf() shouldn't truncate the string, as we have
   * allocated a buffer large enough to hold the string, so its
   * return value should be the number of characters printed.
   */
  return (ret);
}

int pcap_asprintf(char **strp, const char *format, ...) {
  va_list args;
  int ret;

  va_start(args, format);
  ret = pcap_vasprintf(strp, format, args);
  va_end(args);
  return (ret);
}
