cmake_minimum_required(VERSION 3.15)

# 1. Nombre del proyecto sin espacios ni caracteres especiales (o entre comillas)
project(Lab07_MAC_functions C)

find_package(OpenSSL REQUIRED)

# 2. La forma más limpia es añadir todos los archivos fuente directamente aquí
add_executable(main
  src/main.c
  src/cmac/cmac.c
  src/kmac/kmac.c
  src/hmac/hmac.c
)

# 3. Directorios de cabeceras (rutas relativas al CMakeLists.txt)
target_include_directories(main PRIVATE
  src/cmac
  src/kmac
  src/hmac
  src/
  include
)

# 4. Enlazar la librería de criptografía de OpenSSL
target_link_libraries(main PRIVATE
  OpenSSL::Crypto
)
