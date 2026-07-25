#!/bin/sh

python3 generate_type_graph.py headers/winddi.h \
    -I ./headers/ \
    --pretty \
    -o type_graph.json

