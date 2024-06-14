TARGET = http-server
VERSION = 1.1.0
URL = https://github.com/mekb-turtle/http-server

EXTRA_SRC_FILES =
EXTRA_BINARY_FILES =
LDLIBS += -lmicrohttpd -lcjson -lcjson_utils -lmagic
CFLAGS += -Wall
