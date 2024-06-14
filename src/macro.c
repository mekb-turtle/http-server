#include "macro.h"
extern bool _assert_internal(bool val, const char *expr) {
	if (val) return false;
	eprintf("Assertion failed: %s\n", expr);
	return true;
}
