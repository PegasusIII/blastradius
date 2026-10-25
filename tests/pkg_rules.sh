#!/bin/sh
# Runs INSIDE a *-real image as root (network: none): distro package rules (PKGFIX).
# Uses the real installed PHP packages with FAKE test definitions signed by a throwaway key.
set -u
BR=/br/bin/blastradius; F=/pkgfix; mkdir -p $F; cd $F || exit 1; chmod 755 $F
PASS=0; FAILN=0
ok()  { PASS=$((PASS+1)); echo "PASS $1 $2"; }
bad() { FAILN=$((FAILN+1)); echo "FAIL $1 $2"; sed 's/^/     | /' $F/out | head -30; }
check(){ id=$1; desc=$2; shift 2; if "$@"; then ok "$id" "$desc"; else bad "$id" "$desc"; fi; }
. /etc/os-release
echo "== pkg rules: $PRETTY_NAME"
openssl genpkey -algorithm ed25519 -out k 2>/dev/null; openssl pkey -in k -pubout -out pub.pem
# locate the PHP CLI binary and its owning package/version via the package DB
P=$(for b in /usr/bin/php8.* /usr/bin/php83 /usr/bin/php; do [ -x "$b" ] && readlink -f "$b" && break; done)
if command -v dpkg-query >/dev/null; then PM=dpkg; PK=$(dpkg-query -S "$P" | cut -d: -f1); PV=$(dpkg-query -W -f='${Version}' "$PK"); SRC=$(dpkg-query -W -f='${source:Package}' "$PK"); HI="99:0"
elif command -v rpm >/dev/null; then PM=rpm; PK=$(rpm -qf --qf '%{NAME}' "$P"); PV=$(rpm -qf --qf '%{VERSION}-%{RELEASE}' "$P"); SRC=php; HI="99:0-0"
else PM=apk; O=$(apk info --who-owns "$P" | sed 's/.* is owned by //'); PK=$(echo "$O" | sed 's/-[0-9][^-]*-r[0-9]*$//'); PV=${O#"$PK"-}; SRC=$PK; HI="999.0-r0"; fi
UP=$("$P" -v | head -n1 | sed 's/^PHP \([0-9]*\.[0-9]*\.[0-9]*\).*/\1/'); BRN=$(echo "$UP" | cut -d. -f1-2)
case "$ID" in ubuntu) REL=$VERSION_ID ;; alpine) REL=$(echo "$VERSION_ID" | cut -d. -f1-2) ;; *) REL=${VERSION_ID%%.*} ;; esac
echo "     php=$P upstream=$UP package=$PK $PV (prefix rule: $SRC) os=$ID $REL"
mk() { # $1 file ; PKGFIX lines on stdin
  { printf 'META\tversion\t9.9.9\nMETA\tpublished_at\t2099-01-01\n'
    printf 'INC\tTEST-PKG-1\truntime_cve\t1\t2099-01-01\tTest pkg rule\n'
    printf 'VB\tTEST-PKG-1\tphp\t%s\t999.0.0\n' "$BRN"; cat; } > "$1"
  openssl pkeyutl -sign -rawin -inkey k -in "$1" -out "$1.sig"; chmod 644 "$1" "$1.sig"; }
run() { su -s /bin/sh bruser -c "TMPDIR=/tmp $BR --trust-key $F/pub.pem --definitions $F/$1 --no-color" > $F/out 2>&1; echo $? > $F/rc; }
printf 'PKGFIX\tTEST-PKG-1\t%s\t%s\t%s\t%s\t%s\tTEST-ADV-EQ\n' "$ID" "$REL" "$SRC" "$BRN" "$PV" | mk eq.tsv
run eq.tsv
check PK-1 "installed == distro fix -> NOT AFFECTED (upstream rule says affected; distro row wins)" sh -c "php_line() { grep '^php:.*$P ' $F/out; }; php_line | grep -q 'NOT AFFECTED TEST-PKG-1' && php_line | grep -q 'TEST-ADV-EQ'"
printf 'PKGFIX\tTEST-PKG-1\t%s\t%s\t%s\t%s\t%s\tTEST-ADV-HI\n' "$ID" "$REL" "$SRC" "$BRN" "$HI" | mk hi.tsv
run hi.tsv
check PK-2 "installed < distro fix -> AFFECTED, PATCH FIRST, advisory cited" sh -c "grep '^php:.*$P ' $F/out | grep -q 'AFFECTED TEST-PKG-1.*< distro fix.*TEST-ADV-HI' && [ \$(cat $F/rc) = 20 ]"
printf 'PKGFIX\tTEST-PKG-1\t%s\t%s\t%s\t%s\t%s\tTEST-ADV-OTHER\n' "$ID" "0.0" "$SRC" "$BRN" "$PV" | mk none.tsv
run none.tsv
case "$ID" in
  ubuntu|rocky|rhel|almalinux|centos|ol)
    check PK-3 "backport distro, no tracker row for this release -> UNKNOWN needs verification (never guessed)" sh -c "grep -q 'needs verification: $ID $REL backports fixes' $F/out && grep -q 'VERDICT: UNKNOWN' $F/out" ;;
  *)
    check PK-3 "non-backport distro, no tracker row -> falls back to upstream compare (AFFECTED vs 999.0.0)" sh -c "grep '^php:.*$P ' $F/out | grep -q 'AFFECTED TEST-PKG-1.*fixed=999.0.0'" ;;
esac
# version comparator edge cases on this distro's native ordering
mkdir -p /usr/local/bin; cp "$P" /usr/local/bin/php; chmod 755 /usr/local/bin/php
printf 'PKGFIX\tTEST-PKG-1\t%s\t%s\t%s\t%s\t%s\tX\n' "$ID" "$REL" "$SRC" "$BRN" "$PV" | mk eq2.tsv
run eq2.tsv
check PK-4 "unpackaged copy (source build) -> upstream compare, not package rule" sh -c "grep '/usr/local/bin/php ' $F/out | grep -q 'AFFECTED TEST-PKG-1.*fixed=999.0.0'"
rm -f /usr/local/bin/php
echo "== RESULT pkg $ID: $PASS passed, $FAILN failed"
