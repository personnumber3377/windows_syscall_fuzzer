clang \
    --target=x86_64-w64-windows-gnu \
    -x c \
    -fsyntax-only \
    -I. \
    -Iheaders \
    parse_winddi.c
