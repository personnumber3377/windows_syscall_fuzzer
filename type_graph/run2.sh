clang \
    -x c \
    -Xclang -ast-dump=json \
    headers/winddi.h \
    -Iheaders \
    > ast.json
