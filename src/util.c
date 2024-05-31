#include "util.h"
#include <string.h>
// for systems w/o GNU extensions
char *strchrnul_(const char *s, int c) {
	for (; *s && *s != c; s++);
	return (char *) s;
}

// concat functions with overflow protection, strncat doesn't tell us if the string was too long
char *concat_char(char *base, size_t base_max_len, char add) {
	size_t base_len = strlen(base);
	if (base_len + 2 >= base_max_len) // string too long
		return NULL;

	base[base_len] = add;
	base[base_len + 1] = '\0';
	return base;
}

char *concat(char *base, size_t base_max_len, const char *add, size_t add_len) {
	size_t base_len = strlen(base);
	if (base_len + add_len + 1 >= base_max_len) // string too long
		return NULL;

	memcpy(base + base_len, add, add_len);
	base[base_len + add_len] = '\0';
	return base;
}

