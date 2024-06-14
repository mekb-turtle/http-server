#include "magic.h"
#include <stddef.h>
#include <stdio.h>
#include "macro.h"

magic_t magic_cookie = NULL;

bool initialize_magic() {
	if (magic_cookie) return true;
	magic_cookie = magic_open(MAGIC_MIME);
	if (!magic_cookie) {
		eprintf("Failed to create magic cookie\n");
		return false;
	}
	if (magic_load(magic_cookie, NULL) != 0) {
		eprintf("Failed to load magic database\n");
		magic_close(magic_cookie);
		magic_cookie = NULL;
		return false;
	}
	return true;
}

void close_magic() {
	if (magic_cookie) {
		magic_close(magic_cookie);
		magic_cookie = NULL;
	}
}
