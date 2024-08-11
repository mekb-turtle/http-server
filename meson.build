project('http-server', 'c',
  version: '0.1',
  license: 'MPL-2.0',
  default_options: ['warning_level=3'])

# define source files
src = files('src'/'file_cache.c', 'src'/'format_bytes.c', 'src'/'macro.c', 'src'/'magic.c', 'src'/'main.c', 'src'/'serve.c', 'src'/'serve_directory.c', 'src'/'serve_file.c', 'src'/'serve_result.c', 'src'/'status_code.c', 'src'/'util.c')

# define project metadata
url = 'https://github.com/mekb-turtle/http-server'
name = meson.project_name()
version = meson.project_version()

add_project_arguments(
  f'-DPROJECT_NAME="@name@"',
  f'-DPROJECT_VERSION="@version@"',
  f'-DPROJECT_URL="@url@"',
  language: 'c')

subproject('hashmap')

xxd = find_program('xxd')
src += custom_target(input: 'src' / 'site.css', command: [xxd, '-i', '@INPUT@', '@OUTPUT@'], output: '@PLAINNAME@.c', install: false, build_by_default: true)

exe = executable('http-server', sources: src, install: true, dependencies: [
  dependency('libmicrohttpd'),
  dependency('libcjson'),
  dependency('libmagic'),
  dependency('hashmap')
])

