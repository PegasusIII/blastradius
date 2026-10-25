#!/bin/sh
# Build fixture images (needs network once). Usage: tests/build_images.sh
set -eu
cd "$(dirname "$0")/containers"
RT=${RT:-podman}
for d in debian12 ubuntu2404 rocky9 alpine320; do
  $RT build -q -t "br-$d" -f "$d.Containerfile" . >/dev/null && echo "built br-$d"
  $RT build -q -t "br-$d-real" -f "$d-real.Containerfile" . >/dev/null && echo "built br-$d-real"
done
