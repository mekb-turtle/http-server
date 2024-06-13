#include "serve_file.h"
#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "format_bytes.h"

// later in the code
static bool pre_line(void *, char **base, bool end);
static bool post_line(void *, char **base, bool end);

#define append(str) \
	if (!concat_expand(&output->text, str)) goto server_error
#define append_escape(str) \
	if (!concat_expand_escape(&output->text, str)) goto server_error
enum serve_result serve_file(server_config cls, struct input_data *input, struct output_data *output) {
	if (!input->file.fp) return serve_not_found;
	enum cache_result result = get_file_cached(&input->file, true);
	switch (result) {
		case cache_fatal_error:
			return serve_error;
		case cache_file_not_found:
		case cache_not_a_file:
			return serve_not_found;
		default:
			break;
	}

	struct file_cache_item *file_data = input->file.cache;
	char size_str[32];
	snprintf(size_str, 32, "%li", file_data->size);
	char *size_format = format_bytes(file_data->size, binary_i);

	switch (output->response_type) {
		case OUT_NONE:
		case OUT_TEXT:
			output->response_type = OUT_NONE;
			output->data = file_data->data;
			output->size = file_data->size;
			output->content_type = file_data->mime;
			break;
		case OUT_HTML:
			output->data_memory = MHD_RESPMEM_MUST_FREE;
			if (!construct_html_head(cls, input, output)) goto server_error;
			append(TITLE_START);
			append_escape(input->url);
			append(TITLE_END);
			if (!construct_html_body(cls, input, output, NULL, "Back")) goto server_error;
			append_escape(input->url);
			if (!construct_html_main(cls, input, output)) goto server_error;
			append("<p>");
			if (has_parent_url(cls, input)) {
				append("<a href=\"");
				append_escape(input->url_parent);
				append("\">Back</a> - ");
			}
			append("<a href=\"");
			append_escape(input->url);
			append_escape("?output=raw");
			append("\">Raw</a> - ");
			append("<a href=\"");
			append_escape(input->url);
			append_escape("?download=true");
			append("\">Download</a> - ");
			append("<span class=\"file-size\" title=\"");
			append_escape(size_str);
			append(" bytes\">");
			append_escape(size_format);
			append("</span>");
			if (file_data->mime_type) {
				append(" - <span class=\"file-content-type\" title=\"Content Type\">");
				append_escape(file_data->mime_type);
				append("</span>");
			}
			if (file_data->mime_encoding) {
				append(" - <span class=\"file-content-encoding\" title=\"Content Encoding\">");
				append_escape(file_data->mime_encoding);
				append("</span>");
			}
			append(" - <span class=\"file-binary\">");
			if (file_data->is_binary) {
				append("Binary");
			} else {
				append("Text");
			}
			append("</span></p>");
			if (file_data->is_utf8) {
				// TODO: convert non-UTF-8 text files to UTF-8 to display
				append("<div class=\"text-file\">"
				       "<table class=\"text-file\">"
				       "<tbody>");
				int line_number = 0;
				if (!concat_expand_escape_func_n(&output->text, file_data->data, file_data->size,
				                                 pre_line, &line_number, post_line, &line_number, false)) goto server_error;
				append("</tbody>"
				       "</table>"
				       "</div>");
			}
			if (!construct_html_end(cls, input, output)) goto server_error;
			break;
		case OUT_JSON:;
			cjson_add_file_details(output->json_root, input->file, input->url, NULL);
			break;
	}
	free(size_format);
	if (!append_text_footer(cls, output)) goto server_error;
	if (output->response_type == OUT_HTML) output->size = strlen(output->text);
	return serve_ok;
server_error:
	if (output->data && output->data != file_data->data) free(output->data); // free the data if it was allocated
	free(size_format);
	return serve_error;
}

#undef append
#undef append_escape
#define append(str) \
	if (!concat_expand(base, str)) return false
#define append_escape(str) \
	if (!concat_expand_escape(base, str)) return false

static bool pre_line(void *line, char **base, bool end) {
	append("<tr class=\"text-file line\">");
	append("<td class=\"text-file line-number\">");
	int *line_number = (int *) line;
	char line_number_str[32];
	snprintf(line_number_str, 32, "%i", ++*line_number);
	append(line_number_str);
	append("</td>");
	append("<td class=\"text-file line-content\">");
	return true;
}

static bool post_line(void *, char **base, bool end) {
	append("</td></tr>");
	return true;
}
