#include "file_cache.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "attribute.h"
#include "hashmap.h"
#include "magic.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

// for hashmap functions
static bool strcmp_compare(void *key1, void *key2) {
	return strcmp(key1, key2) == 0;
}
static size_t fnv_1a_hash_n(const void *data, size_t len) {
	// FNV-1a hash function
	uint32_t hash = 0x811c9dc5;
	for (size_t i = 0; i < len; i++) {
		hash ^= ((char *) data)[i];
		hash *= 0x01000193;
	}
	return hash;
}
static size_t fnv_1a_hash(void *data) {
	return fnv_1a_hash_n(data, strlen(data));
}
static void free_value(void *value_) {
	struct file_cache_item *value = (struct file_cache_item *) value_;
	if (value->data) free(value->data);
	if (value->mime_type) free(value->mime_type); // mime_type is strdup'd
	free(value);
}

static struct hashmap *cache_map = NULL;

void free_file_cache(void) {
	hashmap_free(cache_map);
	cache_map = NULL;
}

bool initialize_cache_map() {
	if (cache_map) return true;
	// initialize the cache map
	static struct hashmap cache_map_;
	cache_map_ = hashmap_create(0x400, fnv_1a_hash, strcmp_compare, free, free_value);
	if (!cache_map_.buckets) {
		eprintf("Failed to create cache hashmap\n");
		return false;
	}
	cache_map = &cache_map_;
	return true;
}

enum cache_result get_file_cached(
        struct file_detail *file,
        bool fetch_new) {
	if (!file) return cache_fatal_error;
	if (!file->filepath) return cache_fatal_error;
	if (file->cache) goto cache_hit;

	if (!initialize_cache_map()) return cache_fatal_error;
	if (!initialize_magic()) return cache_fatal_error;

	struct hashmap_entry *entry = hashmap_get(cache_map, file->filepath);
	if (entry) {
		// TODO: make cache expire after a certain time
		file->cache = (struct file_cache_item *) entry->value;
	cache_hit:
		return cache_hit;
	}
	if (!fetch_new) return cache_miss;      // return miss if we don't want to fetch new data
	if (!file->fp) return cache_not_a_file; // can't read a file if it isn't open

	// create a new cache entry

	// copy the filepath to avoid dangling pointers
	char *filepath = strdup(file->filepath);
	if (!filepath) {
	malloc_error:
		eprintf("Failed to allocate memory\n");
		return cache_fatal_error;
	}

	struct file_cache_item *cache_item = malloc(sizeof(struct file_cache_item));
	if (!cache_item) {
		free(filepath);
		goto malloc_error;
	}

	memset(cache_item, 0, sizeof(struct file_cache_item)); // zero out the struct

	cache_item->size = file->stat.st_size;
	cache_item->data = malloc(cache_item->size);
	if (!cache_item->data) {
		free(filepath);
		free_value(cache_item);
		goto malloc_error;
	}

	size_t read = fread(cache_item->data, 1, file->stat.st_size, file->fp);
	if (read != file->stat.st_size || ferror(file->fp)) {
	read_error:
		eprintf("Error reading file: %s\n", file->filepath);
		if (read != file->stat.st_size)
			eprintf("Expected: %zu bytes, Read: %zu bytes\n", file->stat.st_size, read);
		else
			eprintf("File has more data than expected\n");
		eprintf("Error: %s, EOF: %s\n",
		        ferror(file->fp) ? "yes" : "no", feof(file->fp) ? "yes" : "no");
		free(filepath);
		free_value(cache_item);
		return cache_fatal_error;
	}

	// check the file is at EOF
	if (fgetc(file->fp) != EOF) goto read_error;

	// determine the MIME type using libmagic
	cache_item->mime_type = NULL;
	cache_item->mime_encoding = NULL;
	cache_item->mime = magic_buffer(magic_cookie, cache_item->data, cache_item->size);
	cache_item->is_binary = true; // assume binary unless encoding is specified

	if (cache_item->mime) {
		// find the MIME type
		char *mime_type = strdup(cache_item->mime);
		if (!mime_type) {
			free(filepath);
			free_value(cache_item);
			goto malloc_error;
		}
		char *semicolon = strchr(mime_type, ';');
		if (semicolon) *semicolon = '\0'; // trim the semicolon and everything after it
		cache_item->mime_type = mime_type;

		// parse the MIME type
		const char *encoding;
		if ((encoding = strchr(cache_item->mime, ';'))) {
			if ((encoding = strchr(encoding, '='))) { // magic always returns "x/x; charset=x" for MAGIC_MIME
				++encoding;
				if (*encoding != '\0') {
					if (strcmp(encoding, "binary") == 0) {
						// "binary" is not a valid encoding for HTTP responses
						cache_item->mime_encoding = NULL; // set encoding to NULL
						cache_item->mime = mime_type;     // trim encoding as it's invalid
					} else {
						cache_item->mime_encoding = encoding;
						cache_item->is_binary = false;
					}
				}
			}
		}
	}

	if (!hashmap_set(cache_map, filepath, cache_item)) {
		eprintf("Failed to set cache item\n");
		free(filepath);
		free_value(cache_item);
		return cache_fatal_error;
	}

	// TODO: read file into memory
	file->cache = cache_item;
	return cache_miss;
}
