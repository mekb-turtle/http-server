#include "file_cache.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "macro.h"
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
	if (value->mime) free(value->mime);
	if (value->mime_type) free(value->mime_type);
	if (value->mime_encoding) free(value->mime_encoding);
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

#define ALLOC_ERROR "Failed to allocate memory\n"
static bool detect_mime(struct file_cache_item *file, struct file_cache_item *entry);

enum cache_result get_file_cached(
        struct file_detail *file_detail,
        bool fetch_new) {
	if (!file_detail) return cache_fatal_error;
	if (!file_detail->filepath) return cache_fatal_error;
	if (file_detail->cache) goto cache_hit;

	if (!initialize_cache_map()) return cache_fatal_error;
	if (!initialize_magic()) return cache_fatal_error;

	struct hashmap_entry *entry = hashmap_get(cache_map, file_detail->filepath);
	if (entry) {
		// TODO: make cache expire after a certain time
		file_detail->cache = (struct file_cache_item *) entry->value;
	cache_hit:
		return cache_hit;
	}
	if (!fetch_new) return cache_miss;             // return miss if we don't want to fetch new data
	if (!file_detail->fp) return cache_not_a_file; // can't read a file if it isn't open

	// create a new cache entry

	// copy the filepath to avoid dangling pointers
	char *filepath = strdup(file_detail->filepath);
	if (!filepath) {
		eprintf(ALLOC_ERROR);
		return cache_fatal_error;
	}

	struct file_cache_item *file = malloc(sizeof(struct file_cache_item));
	if (!file) {
		free(filepath);
		eprintf(ALLOC_ERROR);
		return cache_fatal_error;
	}

	memset(file, 0, sizeof(struct file_cache_item)); // zero out the struct

	file->mime_type = NULL;
	file->mime_encoding = NULL;
	file->mime = NULL;
	file->is_binary = true; // assume binary unless encoding is specified
	file->is_utf8 = false;

	file->size = file_detail->stat.st_size;
	file->data = malloc(file->size);
	if (!file->data) {
		free(filepath);
		free_value(file);
		eprintf(ALLOC_ERROR);
		return cache_fatal_error;
	}

	size_t read = fread(file->data, 1, file_detail->stat.st_size, file_detail->fp);
	if (read != file_detail->stat.st_size || ferror(file_detail->fp)) {
	read_error:
		eprintf("Error reading file: %s\n", file_detail->filepath);
		if (read != file_detail->stat.st_size)
			eprintf("Expected: %zu bytes, Read: %zu bytes\n", file_detail->stat.st_size, read);
		else
			eprintf("File has more data than expected\n");
		eprintf("Error: %s, EOF: %s\n",
		        ferror(file_detail->fp) ? "yes" : "no", feof(file_detail->fp) ? "yes" : "no");
		free(filepath);
		free_value(file);
		return cache_fatal_error;
	}

	// check the file is at EOF
	if (fgetc(file_detail->fp) != EOF) goto read_error;

	if (!detect_mime(file, file)) {
		free(filepath);
		free_value(file);
		return cache_fatal_error;
	}

	entry = hashmap_set(cache_map, filepath, file);
	if (!entry) {
		eprintf("Failed to set cache item\n");
		free(filepath);
		free_value(file);
		return cache_fatal_error;
	}

	// TODO: read file into memory
	file_detail->cache = entry->value;
	return cache_miss;
}

static bool detect_mime(struct file_cache_item *file, struct file_cache_item *entry) {
	// determine the MIME type using libmagic
	const char *mime = magic_buffer(magic_cookie, file->data, file->size);
	if (!mime) {
		eprintf("Failed to determine MIME type\n");
		return false;
	}

	// find the MIME type by itself without the encoding
	ASSERT(entry->mime_type = strdup(mime));

	char *semicolon = strchr(entry->mime_type, ';');
	if (semicolon) *semicolon = '\0'; // trim the semicolon and everything after it

	// find the encoding by itself
	const char *encoding;
	ASSERTL(encoding = strchr(mime, ';'), mime);
	ASSERTL(encoding = strchr(encoding + 1, '='), mime); // magic always returns "x/x; charset=x" for MAGIC_MIME
	++encoding;
	ASSERTL(*encoding != '\0', mime);
	if (strcmp(encoding, "binary") == 0) {
		entry->is_binary = true;
		entry->is_utf8 = false;
		entry->mime_encoding = NULL;
	} else {
		ASSERT(entry->mime_encoding = strdup(encoding)); // create another copy
		entry->is_binary = false;
		// check if the encoding is UTF-8 or US-ASCII
		if (strcmp(entry->mime_encoding, "utf-8") == 0)
			entry->is_utf8 = true;
		else if (strcmp(entry->mime_encoding, "us-ascii") == 0)
			entry->is_utf8 = true;
	}

	// reconstruct the MIME type with the encoding
	if (entry->mime_encoding) {
		size_t len = strlen(entry->mime_type) + strlen(entry->mime_encoding) + 32;
		entry->mime = malloc(len);
		ASSERT(entry->mime);
		ASSERTL(snprintf(entry->mime, len, "%s; charset=%s", entry->mime_type, entry->mime_encoding) >= 0, mime);
	} else {
		entry->mime = strdup(entry->mime_type);
		ASSERT(entry->mime);
	}
	return true;
error:
	eprintf(ALLOC_ERROR);
	return false;
mime:
	eprintf("Failed to determine MIME type\n");
	return false;
}
