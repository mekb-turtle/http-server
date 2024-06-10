# http-server

### [Work in progress]

Simple HTTP server that serves files from a directory. It is written in C using the libmicrohttpd library.

#### Compiling:

1. Install dependencies
    - libmicrohttpd (arch: `libmicrohttpd`, debian: `libmicrohttpd-dev`)
    - cJSON (arch: `cjson`, debian: `libcjson-dev`)
    - libmagic (arch: `file`, debian: `libmagic-dev`)
    - ```sudo pacman -S libmicrohttpd cjson file```
    - ```sudo apt install libmicrohttpd-dev libcjson-dev libmagic-dev```
2. Run `make`
3. Binary will be created in `build/*/bin/`

The server supports directory listing and file preview.

#### Working on:

- [x] Read files from disk to serve
  - [x] File caching
- [x] Directory listing
- [ ] File preview
  - [ ] Text
    - [ ] Syntax highlighting
  - [ ] Images
  - [ ] Audio
  - [ ] Video

#### Planned features:

- [ ] Code cleanup
- [ ] Documentation
- [ ] Finer control over the server
  - [ ] Cache control
  - [ ] Custom index page
  - [ ] Custom error pages
  - [ ] Set specific MIME types which are served as raw data (without file preview)
- [ ] Signal to drop cache
