#ifndef conversion_utils_h
#define conversion_utils_h
#include <new>

template <class TYPE> TYPE *c_malloc(size_t size = sizeof(TYPE)) {
  void *buffer = malloc(size);
  return new (buffer) TYPE{};
}

template <class TYPE> TYPE *c_realloc(TYPE *old_buffer, size_t new_size) {
  void *buffer = realloc(old_buffer, new_size * sizeof(TYPE));
  return new (buffer) TYPE[new_size];
}

#endif