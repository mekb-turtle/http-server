#include "format_bytes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

char *format_bytes(size_t byte, enum format_bytes_mode mode) {
	const int scale = 2;

	size_t scale_exp = 1;
	for (int i = 0; i < scale; ++i) scale_exp *= 10;

	char *suffix = "";
	int base = 0;
	switch (mode) {
		case metric:
			base = 1000;
			break;
		case binary_i:
			suffix = "i";
		case binary:
			base = 1024;
			break;
		default:
			return NULL;
	}

	size_t power = 1;
	int exp_index = 0;
	size_t mantissa = byte;
	while (mantissa >= base) {
		++exp_index;      // increase exponent
		mantissa /= base; // divide by base
		power *= base;    // multiply power by the base so we can count the remainder
	}

	size_t remainder = byte - mantissa * power;
	float fraction_part = (remainder * scale_exp) / (float) power / (float) scale_exp;
	if (remainder == 0) fraction_part = 0; // prevent floating point weirdness

	char *frac_str, *str;
	if (!(frac_str = malloc(64))) return NULL;

	// fraction part in a separate string so we can trim off until the decimal point
	if (snprintf(frac_str, 64, "%.*g", scale, fraction_part) < 0) {
		free(frac_str);
		return NULL;
	}

	if (!(str = malloc(64))) {
		free(frac_str);
		return NULL;
	}

	char *frac_str_dp = strchrnul_(frac_str, '.'); // find the decimal point, or "" if none found
	if (strchr(frac_str, 'e')) {
		// use "" if float uses scientific notation
		frac_str_dp = frac_str + strlen(frac_str);
	}
	if (strlen(frac_str_dp) >= scale + 1) {
		// trim string if it's too long
		frac_str_dp[scale + 1] = '\0';
	}

	const char *suffixes = " kMGTPEZY";

	if (snprintf(str, 64, "%zu%s %c%s", mantissa, frac_str_dp, suffixes[exp_index], suffix) < 0)
		goto snprintf_error;

	if (byte == 0) {
		if (snprintf(str, 64, "0") < 0) // don't bother printing "bytes" for 0
			goto snprintf_error;
	} else if (exp_index == 0) { // append "bytes" instead
		char *trim = strchr(str, ' ');
		if (trim) {
			if (snprintf(trim, 64 - (trim - str), " byte%s", byte == 1 ? "" : "s") < 0)
				goto snprintf_error;
		}
	}

	free(frac_str);

	return str;

snprintf_error:
	free(frac_str);
	free(str);
	return NULL;
}
