#include "util.h"
char *strchrnul_(const char *s, int c) { // GNU extension
	for (; *s && *s != c; s++);
	return (char *) s;
}
