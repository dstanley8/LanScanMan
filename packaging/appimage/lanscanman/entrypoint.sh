#! /bin/bash
# -s: ignore the user's ~/.local site-packages so the bundled libraries win
{{ python-executable }} -s -m lanscanman "$@"
