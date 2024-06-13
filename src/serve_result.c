#include "serve_result.h"
#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "status_code.h"

#define append(str) \
	if (!concat_expand(&output->text, str)) goto server_error
#define append_escape(str) \
	if (!concat_expand_escape(&output->text, str)) goto server_error
enum serve_result serve_result(server_config cls, struct input_data *input, struct output_data *output) {
	if (!output->data) { // if there is no data to respond with
		output->size = 0;

		output->content_type = NULL;

		if (output->status != MHD_HTTP_NO_CONTENT) {
			char *status_name = status_codes[output->status];

			char status_num_str[32];
			snprintf(status_num_str, 32, "%i", output->status);

			bool is_error = http_status_is_error(output->status);

			output->data_memory = MHD_RESPMEM_MUST_FREE; // free the data after responding

			// write out status code
			switch (output->response_type) {
				case OUT_NONE:
				case OUT_TEXT:
					output->response_type = OUT_TEXT;
					append(status_num_str);
					append(" - ");
					append(status_name);
					append("\n");
					break;
				case OUT_HTML:
					if (!construct_html_head(cls, input, output)) goto server_error;
					append(TITLE_START);
					append_escape("Index of ");
					append_escape(input->url);
					append(TITLE_END);
					if (!construct_html_body(cls, input, output, is_error ? "error" : "ok", "Back")) goto server_error;
					append_escape(status_num_str);
					append_escape(" - ");
					append_escape(status_name);
					if (!construct_html_main(cls, input, output)) goto server_error;
					append("<p>");
					if (has_parent_url(cls, input)) {
						append("<a href=\"");
						append_escape(input->url_parent);
						append("\">Back</a> - ");
					}
					append("<a class=\"main-page\" href=\"/\">Main Page</a></p>\n");
					if (!construct_html_end(cls, input, output)) goto server_error;
					break;
				case OUT_JSON:;
					// set status code in JSON
					cJSON *status_obj = cJSON_CreateObject();
					cJSON_AddNumberToObject(status_obj, "number", output->status);
					cJSON_AddStringToObject(status_obj, "message", status_name);
					cJSON_AddBoolToObject(status_obj, "ok", !is_error);
					cJSON_AddItemToObject(output->json_root, "status", status_obj);

					// encode JSON data and respond with it
					output->data = cJSON_Print(output->json_root);
					if (!output->data) goto server_error;
					append("\n");
					break;
			}

			if (!append_text_footer(cls, output)) goto server_error;

			if (output->data) output->size = strlen(output->data);
		}
	}
	return serve_ok;

server_error:
	if (output->data) free(output->data); // free the data if it was allocated
	output->size = 0;
	output->content_type = NULL;
	output->response_type = OUT_NONE;
	return serve_not_found;
}
