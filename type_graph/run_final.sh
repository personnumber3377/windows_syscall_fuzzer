clang \
    --target=x86_64-w64-windows-gnu \
    -x c \
    -std=gnu11 \
    -fsyntax-only \
    -Xclang -ast-dump=json \
    -I. \
    -Iheaders \
    parse_winddi.c \
    > ast.json
