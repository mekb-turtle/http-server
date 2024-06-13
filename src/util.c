#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
// for systems w/o GNU extensions
char *strchrnul_(const char *s, int c) {
	for (; *s && *s != c; s++)
		;
	return (char *) s;
}

// concat functions with overflow protection, strncat doesn't tell us if the string was too long
char *WARN_UNUSED concat_n(char *base, size_t base_max_len, const char *add, size_t add_len) {
	size_t base_len = strlen(base);
	if (base_len + add_len + 1 >= base_max_len) // string too long
		return NULL;

	memcpy(base + base_len, add, add_len);
	base[base_len + add_len] = '\0';
	return base;
}

char *WARN_UNUSED concat(char *base, size_t base_max_len, const char *add) {
	return concat_n(base, base_max_len, add, strlen(add));
}

char *WARN_UNUSED concat_char(char *base, size_t base_max_len, char add) {
	return concat_n(base, base_max_len, &add, 1);
}

// concat functions with automatic memory allocation
char *WARN_UNUSED concat_expand_n(char **base, const char *add, size_t add_len) {
	size_t base_len = 0;
	if (!*base) {
		*base = malloc(add_len + 1);
		if (!*base) {
			eprintf("Failed to allocate memory\n");
			return NULL;
		}
		(*base)[0] = '\0';
	} else {
		base_len = strlen(*base);
		char *new_base = realloc(*base, base_len + add_len + 1);
		if (!new_base) {
			eprintf("Failed to allocate memory\n");
			free(*base);
			*base = NULL;
			return NULL;
		}
		*base = new_base;
	}
	memcpy(*base + base_len, add, add_len);
	(*base)[base_len + add_len] = '\0';
	return *base;
}

char *WARN_UNUSED concat_expand(char **base, const char *add) {
	return concat_expand_n(base, add, strlen(add));
}

char *WARN_UNUSED concat_expand_char(char **base, char add) {
	return concat_expand_n(base, &add, 1);
}

char *WARN_UNUSED concat_expand_escape_func_n(
        char **base, const char *add, size_t input_len,
        void (*pre_line)(void *), void *pre_line_arg,
        void (*post_line)(void *), void *post_line_arg) {
	size_t bulk_i = 0;
	char hex[16];
	bool new_line = true;
	for (size_t i = 0;; ++i) {
		if (new_line) {
			// start of the line
			if (pre_line) pre_line(pre_line_arg);
			new_line = false;
		}
		char *escaped = NULL;
		if (i < input_len) {
			switch (add[i]) {
				case '&':
				case '<':
				case '>':
				case '"':
				case '\'':
				case '\\':
				case ';':
				case '\t': // tab
					// escape characters as hexadecimal HTML entities
					snprintf(hex, 16, "&#x%02x;", add[i]);
					escaped = hex;
					break;
			}
			if (!escaped) {
				if ((add[i] < 0 || add[i] >= '\x20') // x<0 is done because of signed char
				    && add[i] != '\x7f')             // printable characters, those are done in bulk below
					continue;
				else if ((add[i] == '\r' &&                           // carriage return,
				          (i + 1 >= input_len || add[i + 1] != '\n')) // but not followed by line feed
				         || add[i] == '\n') {                         // or a line feed
					escaped = "<br/>";
					new_line = true;
				}
			}
		}
		// append bulk data before the escaped character
		if (bulk_i < i) {
			if (!concat_expand_n(base, add + bulk_i, i - bulk_i)) return NULL;
		}
		if (i == input_len || new_line) {
			// end of the line
			if (post_line) post_line(post_line_arg);
		}
		if (i >= input_len) break; // end of string
		bulk_i = i + 1;            // set the start position of the next bulk data
		if (escaped)
			if (!concat_expand(base, escaped)) return NULL; // append escaped character
	}
	return *base;
}

char *WARN_UNUSED concat_expand_escape_func(
        char **base, const char *add,
        void (*pre_line)(void *), void *pre_line_arg,
        void (*post_line)(void *), void *post_line_arg) {
	return concat_expand_escape_func_n(base, add, strlen(add), pre_line, pre_line_arg, post_line, post_line_arg);
}

char *WARN_UNUSED concat_expand_escape_func_char(
        char **base, char add,
        void (*pre_line)(void *), void *pre_line_arg,
        void (*post_line)(void *), void *post_line_arg) {
	return concat_expand_escape_func_n(base, &add, 1, pre_line, pre_line_arg, post_line, post_line_arg);
}

char *WARN_UNUSED concat_expand_escape_n(char **base, const char *add, size_t input_len) {
	return concat_expand_escape_func_n(base, add, input_len, NULL, NULL, NULL, NULL);
}

char *WARN_UNUSED concat_expand_escape(char **base, const char *add) {
	return concat_expand_escape_n(base, add, strlen(add));
}

char *WARN_UNUSED concat_expand_escape_char(char **base, char add) {
	return concat_expand_escape_n(base, &add, 1);
}

static char *WARN_UNUSED internal_join_filepath_n(char *base, size_t base_max_len, const char *add, size_t add_len, char path_separator) {
	size_t base_len = strlen(base);
	if (base_len == 0 || base[base_len - 1] != path_separator)
		if (!concat_char(base, base_max_len, path_separator)) return NULL;
	if (!concat_n(base, base_max_len, add, add_len)) return NULL;
	return base;
}

char *WARN_UNUSED join_filepath_n(char *base, size_t base_max_len, const char *add, size_t add_len) {
	return internal_join_filepath_n(base, base_max_len, add, add_len, PATH_SEPARATOR);
}

char *WARN_UNUSED join_url_path_n(char *base, size_t base_max_len, const char *add, size_t add_len) {
	return internal_join_filepath_n(base, base_max_len, add, add_len, '/');
}

char *WARN_UNUSED join_filepath(char *base, size_t base_max_len, const char *add) {
	return join_filepath_n(base, base_max_len, add, strlen(add));
}

char *WARN_UNUSED join_url_path(char *base, size_t base_max_len, const char *add) {
	return join_url_path_n(base, base_max_len, add, strlen(add));
}
