#ifndef UTIL_H
#define UTIL_H
#include <stddef.h>
char *strchrnul_(const char *s, int c);
char *concat_char(char *base, size_t base_max_len, char add);
char *concat(char *base, size_t base_max_len, const char *add, size_t add_len);
#endif
