#ifndef SERVE_RESULT_H
#define SERVE_RESULT_H
#include "serve.h"
// serve status code page or json data
extern enum serve_result serve_result(server_config cls, struct input_data *input, struct output_data *output);
#endif
