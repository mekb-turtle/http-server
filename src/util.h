#ifndef UTIL_H
#define UTIL_H
#include <stddef.h>
#ifdef __GNUC__
#define WARN_UNUSED __attribute__((warn_unused_result))
#else
#define WARN_UNUSED
#endif
extern char *WARN_UNUSED strchrnul_(const char *s, int c);
extern char *WARN_UNUSED concat_n(char *base, size_t base_max_len, const char *add, size_t add_len);
extern char *WARN_UNUSED concat(char *base, size_t base_max_len, const char *add);
extern char *WARN_UNUSED concat_char(char *base, size_t base_max_len, char add);
extern char *WARN_UNUSED concat_expand_n(char **base, const char *add, size_t add_len);
extern char *WARN_UNUSED concat_expand(char **base, const char *add);
extern char *WARN_UNUSED concat_expand_char(char **base, char add);
extern char *WARN_UNUSED escape_html(char **base, const char *input);
#endif
