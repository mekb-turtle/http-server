#ifndef WARN_UNUSED
#ifdef __GNUC__
#define WARN_UNUSED __attribute__((warn_unused_result))
#else
#define WARN_UNUSED
#endif
#endif
#ifndef eprintf
#define eprintf(...) fprintf(stderr, __VA_ARGS__)
#endif
#ifndef ASSERT
// ASSERT macro for error handling
// I personally think this is cleaner, but if this is stupid, please let me know
#define ASSERT(expr) \
	if (!expr) goto error
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
