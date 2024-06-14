#ifndef WARN_UNUSED
#ifdef __GNUC__
#define WARN_UNUSED __attribute__((warn_unused_result))
#else
#define WARN_UNUSED
#endif
#endif

#ifndef eprintf
#include <stdio.h>
#define eprintf(...) fprintf(stderr, __VA_ARGS__)
#endif

#include <stdbool.h>
extern bool _assert_internal(bool val, const char *expr);

#ifndef ASSERT
// ASSERT macro for error handling
// I personally think this is cleaner
// than writing if (!...) goto ... every time,
// but if this is stupid, please let me know
#define ASSERTL(expr, label) \
	if (_assert_internal(!!(expr), #expr)) goto label // internal function so it's portable
#define ASSERT(expr) ASSERTL(expr, error)

// string concatenation macros with error handling
// saves writing ASSERT(concat...(...)) over and over
#define append_n(str, len) \
	ASSERT(concat_expand_n(base, str, len))
#define append(str) \
	ASSERT(concat_expand(base, str))
#define append_char(str) \
	ASSERT(concat_expand_char(base, str))
#define append_escape_n(str, len) \
	ASSERT(concat_expand_escape_n(base, str, len))
#define append_escape(str) \
	ASSERT(concat_expand_escape(base, str))
#define append_escape_char(str) \
	ASSERT(concat_expand_escape_char(base, str))
#endif
