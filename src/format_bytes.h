#ifndef FORMAT_BYTES_H
#define FORMAT_BYTES_H
#include <stddef.h>
enum format_bytes_mode { binary_i,
	                     binary,
	                     metric };
extern char *format_bytes(size_t byte, enum format_bytes_mode mode);
#endif
