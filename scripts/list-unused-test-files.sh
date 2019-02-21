#!/bin/sh

ls tests/data_files | \
    while read f; do
        grep -R -F "$f" tests >/dev/null || echo "$f"
    done
