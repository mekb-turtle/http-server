#ifndef UTIL_H
#define UTIL_H
#include <stddef.h>
#include "attribute.h"
extern char *strchrnul_(const char *s, int c);

// TODO: this is a mess, clean it up
extern char *WARN_UNUSED concat_n(char *base, size_t base_max_len, const char *add, size_t add_len);
extern char *WARN_UNUSED concat(char *base, size_t base_max_len, const char *add);
extern char *WARN_UNUSED concat_char(char *base, size_t base_max_len, char add);

extern char *WARN_UNUSED concat_expand_n(char **base, const char *add, size_t add_len);
extern char *WARN_UNUSED concat_expand(char **base, const char *add);
extern char *WARN_UNUSED concat_expand_char(char **base, char add);

extern char *WARN_UNUSED concat_expand_escape_func_n(
        char **base, const char *add, size_t input_len,
        void (*pre_line)(void *), void *pre_line_arg,
        void (*post_line)(void *), void *post_line_arg);
extern char *WARN_UNUSED concat_expand_escape_func(
        char **base, const char *add,
        void (*pre_line)(void *), void *pre_line_arg,
        void (*post_line)(void *), void *post_line_arg);
extern char *WARN_UNUSED concat_expand_escape_func_char(
        char **base, char add,
        void (*pre_line)(void *), void *pre_line_arg,
        void (*post_line)(void *), void *post_line_arg);

extern char *WARN_UNUSED concat_expand_escape_n(char **base, const char *add, size_t input_len);
extern char *WARN_UNUSED concat_expand_escape(char **base, const char *add);
extern char *WARN_UNUSED concat_expand_escape_char(char **base, char add);

#ifdef _WIN32
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif
extern char *WARN_UNUSED join_filepath_n(char *base, size_t base_max_len, const char *add, size_t add_len);
extern char *WARN_UNUSED join_url_path_n(char *base, size_t base_max_len, const char *add, size_t add_len);
extern char *WARN_UNUSED join_filepath(char *base, size_t base_max_len, const char *add);
extern char *WARN_UNUSED join_url_path(char *base, size_t base_max_len, const char *add);
#endif
