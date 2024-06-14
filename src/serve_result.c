#include "serve_result.h"
#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "status_code.h"
#include "macro.h"

enum serve_result serve_result(server_config cls, struct input_data *input, struct output_data *output) {
	char **base = &output->text;
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
			switch (output->response_type.type) {
				case OUT_NONE:
				case OUT_TEXT:
					output->response_type.type = OUT_TEXT;
					append(status_num_str);
					append(" - ");
					append(status_name);
					append("\n");
					break;
				case OUT_HTML:
					ASSERT(construct_html_head(cls, input, output));
					append(TITLE_START);
					append_escape("Index of ");
					append_escape(input->url);
					append(TITLE_END);
					ASSERT(construct_html_body(cls, input, output, is_error ? "error" : "ok", "Back"));
					append_escape(status_num_str);
					append_escape(" - ");
					append_escape(status_name);
					ASSERT(construct_html_main(cls, input, output));
					append("<p>");
					if (has_parent_url(cls, input)) {
						append("<a href=\"");
						append_escape(input->url_parent);
						append("\">Back</a> - ");
					}
					append("<a class=\"main-page\" href=\"/\">Main Page</a></p>\n");
					ASSERT(construct_html_end(cls, input, output));
					break;
				case OUT_JSON:;
					// set status code in JSON
					cJSON *status_obj = cJSON_CreateObject();
					ASSERT(status_obj);
					ASSERT(cJSON_AddNumberToObject(status_obj, "number", output->status));
					ASSERT(cJSON_AddStringToObject(status_obj, "message", status_name));
					ASSERT(cJSON_AddBoolToObject(status_obj, "ok", !is_error));
					ASSERT(cJSON_AddItemToObject(output->json_root, "status", status_obj));
					break;
			}

			ASSERT(append_text_footer(cls, output));

			if (output->response_type.type == OUT_JSON) {
				// encode JSON data and respond with it
				output->data = cJSON_Print(output->json_root);
				ASSERT(output->data);
				append("\n");
			}

			if (output->data) output->size = strlen(output->data);
		}
	}
	return serve_ok;

error:
	if (output->data) free(output->data); // free the data if it was allocated
	output->size = 0;
	output->content_type = NULL;
	output->response_type.type = OUT_NONE;
	output->response_type.explicit = true;
	return serve_not_found;
}
