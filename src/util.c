#include "util.h"
#include <stdlib.h>
#include <string.h>
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

char *WARN_UNUSED concat_expand_n(char **base, const char *add, size_t add_len) {
	size_t base_len = 0;
	if (!*base) {
		*base = malloc(add_len + 1);
		if (!*base) return NULL;
		(*base)[0] = '\0';
	} else {
		base_len = strlen(*base);
		*base = realloc(*base, base_len + add_len + 1);
		if (!*base) {
			free(*base);
			return NULL;
		}
	}
	memcpy(*base + base_len, add, add_len);
	(*base)[base_len + add_len] = '\0';
	return *base;
}

char *WARN_UNUSED escape_html_n(char **base, const char *input, size_t input_len) {
	size_t bulk_i = 0;
	for (size_t i = 0;; i++) {
		char *escaped = NULL;
		if (i < input_len) {
			switch (input[i]) {
				case '&':
					escaped = "&amp;";
					break;
				case '<':
					escaped = "&lt;";
					break;
				case '>':
					escaped = "&gt;";
					break;
				case '"':
					escaped = "&quot;";
					break;
				case '\'':
					escaped = "&#39;";
					break;
				case '\\':
					escaped = "&#92;";
					break;
				case ';':
					escaped = "&#59;";
					break;
			}
			if (!escaped) continue;
		}
		// append bulk data before the escaped character
		if (bulk_i < i) {
			if (!concat_expand_n(base, input + bulk_i, i - bulk_i)) return NULL;
			bulk_i = i + 1;
		}
		if (i == input_len) break;                      // end of string
		if (!concat_expand(base, escaped)) return NULL; // append escaped character
	}
	return *base;
}

char *WARN_UNUSED concat(char *base, size_t base_max_len, const char *add) {
	return concat_n(base, base_max_len, add, strlen(add));
}

char *WARN_UNUSED concat_char(char *base, size_t base_max_len, char add) {
	return concat_n(base, base_max_len, &add, 1);
}

char *WARN_UNUSED concat_expand(char **base, const char *add) {
	return concat_expand_n(base, add, strlen(add));
}

char *WARN_UNUSED concat_expand_char(char **base, char add) {
	return concat_expand_n(base, &add, 1);
}

char *WARN_UNUSED escape_html(char **base, const char *input) {
	return escape_html_n(base, input, strlen(input));
}

char *WARN_UNUSED escape_html_char(char **base, char input) {
	return escape_html_n(base, &input, 1);
}
