#include "serve_file.h"
#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "format_bytes.h"

#define append(str, label) \
	if (!concat_expand(&output->text, str)) goto label
#define append_escape(str, label) \
	if (!concat_expand_escape(&output->text, str)) goto label
enum serve_result serve_file(const struct server_config *cls, struct input_data *input, struct output_data *output) {
	if (!input->file.fp) return serve_not_found;
	struct file_cache_item file;
	enum cache_result result = get_file_cached(input->filepath, &input->file, &file);
	switch (result) {
		case cache_fatal_error:
			return serve_error;
		case cache_file_not_found:
			return serve_not_found;
		default:
	}

	char *size_format = format_bytes(file.size, binary_i);
	// currently segfaults with text and JSON, TODO: fix
	switch (output->response_type) {
		case OUT_NONE:
		case OUT_TEXT:
			output->response_type = OUT_NONE;
			output->data = file.data;
			output->size = file.size;
			output->content_type = file.mime_type; // TODO: set charset parameter
			break;
		case OUT_HTML:
			output->data_memory = MHD_RESPMEM_MUST_FREE;
			if (!construct_html_head(&output->text)) goto server_error;
			append(TITLE_START, server_error);
			append_escape(input->url, server_error);
			append(TITLE_END, server_error);
			if (!construct_html_body(&output->text, NULL)) goto server_error;
			append("<a title=\"Back\" href=\"", server_error);
			append_escape(input->url_parent, server_error);
			append("\">&laquo;</a> ", server_error);
			append_escape(input->url, server_error);
			if (!construct_html_main(&output->text)) goto server_error;
			append("<p><a href=\"", server_error);
			append_escape(input->url_parent, server_error);
			append("\">Back</a> - <a href=\"", server_error);
			append_escape(input->url, server_error);
			append_escape("?output=raw", server_error);
			append("\">Raw</a> - <a href=\"", server_error);
			append_escape(input->url, server_error);
			append_escape("?download=true", server_error);
			append("\">Download</a></p>", server_error);
			if (!construct_html_end(&output->text)) goto server_error;
			output->size = strlen(output->text);
			break;
		case OUT_JSON:;
			cjson_add_file_details(output->json_root, input->file, input->url, NULL, &file);
			break;
	}
	free(size_format);
	return serve_ok;
server_error:
	if (output->data && output->data != file.data) free(output->data); // free the data if it was allocated
	free(size_format);
	return serve_error;
}
