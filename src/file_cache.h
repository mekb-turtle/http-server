#ifndef FILE_CACHE_H
#define FILE_CACHE_H
#include <stddef.h>
#include <stdbool.h>
struct file_cache_item {
	void *data;
	size_t size;
	bool is_binary;
	char *mime_type;
};
enum cache_result {
	cache_file_not_found = 0,
	cache_fatal_error = -1,
	cache_not_a_file = -2,
	cache_miss = 1,
	cache_hit = 2,
};
#include "serve.h"
enum cache_result get_file_cached(
        struct file_detail *file,
		bool fetch_new);
#endif
