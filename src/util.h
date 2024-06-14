#ifndef UTIL_H
#define UTIL_H
#include <stddef.h>
#include <stdbool.h>
#include "macro.h"
extern char *strchrnul_(const char *s, int c);

// TODO: this is a mess, clean it up
extern char *WARN_UNUSED concat_n(char *base, size_t base_max_len, const char *add, size_t add_len);
extern char *WARN_UNUSED concat(char *base, size_t base_max_len, const char *add);
extern char *WARN_UNUSED concat_char(char *base, size_t base_max_len, char add);

extern char *WARN_UNUSED concat_expand_n(char **base, const char *add, size_t add_len);
extern char *WARN_UNUSED concat_expand(char **base, const char *add);
extern char *WARN_UNUSED concat_expand_char(char **base, char add);

typedef bool (*line_func)(void *, char **base, bool);

extern char *WARN_UNUSED concat_expand_escape_func_n(
        char **base, const char *add, size_t input_len,
        line_func pre_line, void *pre_line_arg,
        line_func post_line, void *post_line_arg,
        bool append_br);
extern char *WARN_UNUSED concat_expand_escape_func(
        char **base, const char *add,
        line_func pre_line, void *pre_line_arg,
        line_func post_line, void *post_line_arg,
        bool append_br);
extern char *WARN_UNUSED concat_expand_escape_func_char(
        char **base, char add,
        line_func pre_line, void *pre_line_arg,
        line_func post_line, void *post_line_arg,
        bool append_br);

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
