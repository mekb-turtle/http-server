#include "serve_result.h"
#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "status_code.h"

#define append(str, label) \
	if (!concat_expand(&output->text, str)) goto label
#define append_escape(str, label) \
	if (!concat_expand_escape(&output->text, str)) goto label
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
					append(status_num_str, server_error);
					append(" - ", server_error);
					append(status_name, server_error);
					append("\n", server_error);
					break;
				case OUT_HTML:
					if (!construct_html_head(&output->text)) goto server_error;
					append(TITLE_START, server_error);
					append_escape("Index of ", server_error);
					append_escape(input->url, server_error);
					append(TITLE_END, server_error);
					if (!construct_html_body(&output->text, is_error ? "error" : "ok")) goto server_error;
					append_escape(status_num_str, server_error);
					append_escape(" - ", server_error);
					append_escape(status_name, server_error);
					if (!construct_html_main(&output->text)) goto server_error;
					append("<p><a class=\"main-page\" href=\"/\">Main Page</a></p>\n", server_error);
					if (!construct_html_end(&output->text, cls)) goto server_error;
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
					append("\n", server_error);
					break;
			}

			if (!append_footer(cls, output)) goto server_error;

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
