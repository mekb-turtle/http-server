#ifndef STATUS_CODE_H
#define STATUS_CODE_H
#include <stdbool.h>
extern char *status_codes[];
extern bool http_status_is_info(unsigned int status_code);
extern bool http_status_is_success(unsigned int status_code);
extern bool http_status_is_redirect(unsigned int status_code);
extern bool http_status_is_client_error(unsigned int status_code);
extern bool http_status_is_server_error(unsigned int status_code);
extern bool http_status_is_error(unsigned int status_code);
extern bool http_status_is_ok(unsigned int status_code);
#endif
