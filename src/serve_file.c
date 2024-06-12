#include "serve_file.h"
#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "format_bytes.h"

#define append(str, label) \
	if (!concat_expand(&output->text, str)) goto label
#define append_escape(str, label) \
	if (!concat_expand_escape(&output->text, str)) goto label
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

	bool has_back = !input->is_root_url && cls->list_directories;

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
			if (!construct_html_head(&output->text)) goto server_error;
			append(TITLE_START, server_error);
			append_escape(input->url, server_error);
			append(TITLE_END, server_error);
			if (!construct_html_body(&output->text, NULL)) goto server_error;
			if (has_back) {
				append("<a title=\"Back\" href=\"", server_error);
				append_escape(input->url_parent, server_error);
				append("\">&laquo;</a> ", server_error);
			}
			append_escape(input->url, server_error);
			if (!construct_html_main(&output->text)) goto server_error;
			append("<p>", server_error);
			if (has_back) {
				append("<a href=\"", server_error);
				append_escape(input->url_parent, server_error);
				append("\">Back</a> - ", server_error);
			}
			append("<a href=\"", server_error);
			append_escape(input->url, server_error);
			append_escape("?output=raw", server_error);
			append("\">Raw</a> - ", server_error);
			append("<a href=\"", server_error);
			append_escape(input->url, server_error);
			append_escape("?download=true", server_error);
			append("\">Download</a> - ", server_error);
			append("<span class=\"file-size\" title=\"", server_error);
			append_escape(size_str, server_error);
			append(" bytes\">", server_error);
			append_escape(size_format, server_error);
			append("</span>", server_error);
			if (file_data->mime_type) {
				append(" - <span class=\"file-content-type\" title=\"Content Type\">", server_error);
				append_escape(file_data->mime_type, server_error);
				append("</span>", server_error);
			}
			if (file_data->mime_encoding) {
				append(" - <span class=\"file-content-encoding\" title=\"Content Encoding\">", server_error);
				append_escape(file_data->mime_encoding, server_error);
				append("</span>", server_error);
			}
			append(" - <span class=\"file-binary\">", server_error);
			if (file_data->is_binary) {
				append("Binary", server_error);
			} else {
				append("Text", server_error);
			}
			append("</span></p>", server_error);
			if (file_data->is_utf8) {
				// TODO: convert non-UTF-8 text files to UTF-8 to display
				append("<hr/>", server_error);
				append("<div class=\"wrap\">", server_error);
				append("<pre class=\"file-text-data\">", server_error);
				if (!concat_expand_escape_n(&output->text, file_data->data, file_data->size)) goto server_error;
				append("</pre>", server_error);
				append("</div>", server_error);
			}
			if (!construct_html_end(&output->text, cls)) goto server_error;
			break;
		case OUT_JSON:;
			cjson_add_file_details(output->json_root, input->file, input->url, NULL);
			break;
	}
	free(size_format);
	if (!append_footer(cls, output)) goto server_error;
	if (output->response_type == OUT_HTML) output->size = strlen(output->text);
	return serve_ok;
server_error:
	if (output->data && output->data != file_data->data) free(output->data); // free the data if it was allocated
	free(size_format);
	return serve_error;
}
