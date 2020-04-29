#ifndef conversion_utils_h
#define conversion_utils_h
#include <new>

template <class TYPE> TYPE *c_malloc(size_t size) {
  void *buffer = malloc(size);
  return new (buffer) TYPE{};
}

#endif