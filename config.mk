TARGET = http-server
VERSION = 1.0.0

EXTRA_SRC_FILES =
EXTRA_BINARY_FILES =
LDLIBS += -lmicrohttpd -lcjson -lcjson_utils
CFLAGS += -Wall
