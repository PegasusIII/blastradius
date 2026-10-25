#!/bin/sh
# Inside a *-real image: run the checker as non-root with the REAL bundled definitions.
. /etc/os-release; echo "== real-world smoke: $PRETTY_NAME"
su -s /bin/sh bruser -c "TMPDIR=/tmp /br/bin/blastradius --no-color"; echo "exit=$?"
