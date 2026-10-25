#!/bin/sh
# Runs INSIDE a throwaway fixture container as root (network: none).
# Builds fixtures (test CA, fake PHP, configs), then runs the checker as a
# non-root user and asserts on output. Prints "PASS/FAIL <id> <desc>" lines.
set -u
BR=/br/bin/blastradius
F=/fixtures; mkdir -p $F; cd $F || exit 1
PASS=0; FAILN=0
ok()   { PASS=$((PASS+1)); echo "PASS $1 $2"; }
bad()  { FAILN=$((FAILN+1)); echo "FAIL $1 $2"; [ -n "${3:-}" ] && sed 's/^/     | /' "$3" | head -40; }
run()  { # run checker as non-root; $@ args; writes $F/out, $F/rc
  su -s /bin/sh bruser -c "TMPDIR=/tmp $BR --trust-key $F/test-pub.pem --definitions $F/defs.tsv --no-color $*" > $F/out 2>$F/err; echo $? > $F/rc; }
rc()   { cat $F/rc; }
has()  { grep -qF -- "$1" $F/out; }
check(){ id=$1; desc=$2; shift 2; if "$@"; then ok "$id" "$desc"; else bad "$id" "$desc" $F/out; fi; }
. /etc/os-release
echo "== distro: $PRETTY_NAME"
PM=unknown; command -v dpkg-query >/dev/null && PM=dpkg; [ $PM = unknown ] && command -v rpm >/dev/null && PM=rpm; [ $PM = unknown ] && command -v apk >/dev/null && PM=apk
chmod 755 $F

# ---------- test PKI (self-generated; no real advisory data) ----------
mk_ca() { openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1.key" -out "$1.pem" -days 30 -subj "/CN=$2" -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1; }
mk_sub() { # name CN issuer ca(true/false)
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2" >/dev/null 2>&1
  if [ "$4" = ca ]; then printf 'basicConstraints=critical,CA:TRUE\n' > ext; else printf 'basicConstraints=CA:FALSE\n' > ext; fi
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial -out "$1.pem" -days 20 -extfile ext >/dev/null 2>&1; }
mk_ca badroot "BR Test Distrusted Root"
mk_sub badint "BR Test Distrusted Intermediate" badroot ca
mk_sub badleaf "bad.example.test" badint leaf
mk_sub badleaf2 "bad2.example.test" badroot leaf
mk_ca goodroot "BR Test Good Root"
mk_sub goodleaf "good.example.test" goodroot leaf
mk_ca otherroot "BR Test Unknown Root"
mk_sub orphan "orphan.example.test" otherroot leaf
fpof() { openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g'; }
BADROOT_FP=$(fpof badroot.pem)

# ---------- test definitions (fake ids/versions) ----------
mkdefs() { # $1 out ; extra lines from stdin
  { printf 'META\tversion\t9.9.%s\n' "${2:-0}"; printf 'META\tpublished_at\t2099-01-01\n'
    printf 'INC\tTEST-RT-1\truntime_cve\t1\t2099-01-01\tTest runtime CVE\n'
    printf 'VB\tTEST-RT-1\tphp\t9.1\t9.1.20\n'
    printf 'VB\tTEST-RT-1\tphp\t9.2\t9.2.5\n'
    printf 'REM\tTEST-RT-1\tdpkg\tsudo apt-get install --only-upgrade test-php\n'
    printf 'REM\tTEST-RT-1\trpm\tsudo dnf upgrade test-php\n'
    printf 'REM\tTEST-RT-1\tapk\tsudo apk upgrade test-php\n'
    printf 'INC\tTEST-CA-1\tca_distrust\t1\t2099-01-01\tTest CA distrust\n'
    printf 'FP\tTEST-CA-1\t%s\tos_ca,certifi,java,leaf_chain\tBR Test Distrusted Root\n' "$BADROOT_FP"
    printf 'ICN\tTEST-CA-1\tBR Test Distrusted Root\n'
    printf 'PKGMIN\tTEST-CA-1\t%s\tca-certificates\t99999999\n' "$PM"
    printf 'REM\tTEST-CA-1\tdpkg\tsudo apt-get install --only-upgrade test-ca-certificates\n'
    printf 'REM\tTEST-CA-1\trpm\tsudo dnf upgrade test-ca-certificates\n'
    printf 'REM\tTEST-CA-1\tapk\tsudo apk upgrade test-ca-certificates\n'
    printf 'REM\tTEST-CA-1\tleaf\tReissue from a trusted CA\n'
    cat; } > "$1"
  openssl pkeyutl -sign -rawin -inkey test-sign.key -in "$1" -out "$1.sig"; }
openssl genpkey -algorithm ed25519 -out test-sign.key 2>/dev/null; openssl pkey -in test-sign.key -pubout -out test-pub.pem
mkdefs defs.tsv </dev/null
chmod 644 $F/*.pem $F/defs.tsv* ; chmod 600 $F/*.key

# ---------- AT-1.1 baseline + read-only ----------
snap() { find / -xdev \( -path /proc -o -path /sys -o -path /tmp -o -path /fixtures -o -path /dev -o -path /run \) -prune -o -newer /tmp/marker -print 2>/dev/null | sort; }
touch /tmp/marker; sleep 1
snap > /tmp/before   # control: anything already "newer" without running the checker
run
snap > /tmp/after
# su(1)'s PAM session updates lastlog/wtmp on some distros; that is the test harness, not the checker
CH=$(grep -vxF -f /tmp/before /tmp/after | grep -v -x -e /var/log -e /var/log/lastlog -e /var/log/wtmp -e /var/log/btmp | tr '\n' ' ')
if [ "$ID" = rocky ]; then  # Rocky ships a java cacerts file but no keytool -> UNKNOWN is the correct verdict
  check AT-1.1 "clean host: VERDICT UNKNOWN (only: keytool not found), exit 30, no file changed" sh -c "[ $(rc) = 30 ] && grep -q 'VERDICT: UNKNOWN' $F/out && [ \$(grep -c '^[a-z_]*: *UNKNOWN (' $F/out) = 1 ] && grep -q 'keytool not found' $F/out && [ -z '$CH' ]"
else
  check AT-1.1 "clean host: VERDICT OK, exit 0, no file changed outside TMPDIR" sh -c "[ $(rc) = 0 ] && grep -q 'VERDICT: OK' $F/out && [ -z '$CH' ]"
fi
[ -n "$CH" ] && echo "     changed: $CH"
check AT-1.2 "completes with --network none (no outbound calls needed)" sh -c "[ $(rc) != 2 ]"
check AT-3.4 "Go/rustls advisory note printed" has "compiled-in roots"
check AT-4.4 "reports package manager $PM" has "pkg=$PM"
check AT-8.1 "header shows --definitions version/published_at" has "definitions: v9.9.0 published 2099-01-01"
check AT-1.x "no temp dirs left behind" sh -c "! ls /tmp/blastradius.* >/dev/null 2>&1"

# ---------- AT-8.4 bundled defs ----------
su -s /bin/sh bruser -c "$BR --no-color" > out.b 2>&1; RCB=$?
check AT-8.4 "no --definitions: uses bundled defs and prints version (signature OK)" sh -c "grep -q 'definitions: v0.2.0 published 2026-10-26 (bundled), signature OK' out.b && [ $RCB != 2 ]"
echo "     real bundled defs on clean $ID image -> $(grep VERDICT out.b) (exit $RCB)"

# ---------- AT-8.2 / 8.3 ----------
cp defs.tsv tamper.tsv; cp defs.tsv.sig tamper.tsv.sig; sed -i 's/9.1.20/9.1.21/' tamper.tsv; chmod 644 tamper.tsv*
su -s /bin/sh bruser -c "$BR --trust-key $F/test-pub.pem --definitions $F/tamper.tsv" > out 2>&1; R=$?
check AT-8.2 "one changed byte -> exit 2 'definitions signature invalid'" sh -c "[ $R = 2 ] && grep -q 'definitions signature invalid' $F/out && ! grep -q VERDICT $F/out"
printf 'FP\tTEST-CA-1\tNOTHEX\tos_ca\tbroken\n' | mkdefs broken.tsv; chmod 644 broken.tsv*
su -s /bin/sh bruser -c "$BR --trust-key $F/test-pub.pem --definitions $F/broken.tsv" > out 2>&1; R=$?
check AT-8.3 "schema-invalid defs -> exit 2 naming field" sh -c "[ $R = 2 ] && grep -q 'FP.sha256' $F/out"
cp defs.tsv nosig.tsv; chmod 644 nosig.tsv
su -s /bin/sh bruser -c "$BR --trust-key $F/test-pub.pem --definitions $F/nosig.tsv" > out 2>&1; R=$?
check AT-8.x "missing .sig -> exit 2" sh -c "[ $R = 2 ]"
su -s /bin/sh bruser -c "$BR --definitions $F/defs.tsv" > out 2>&1; R=$?
check AT-8.y "defs signed by a key other than the embedded one -> exit 2" sh -c "[ $R = 2 ] && grep -q 'signature invalid' $F/out"

# ---------- US-2 PHP (fake binaries printing version banners) ----------
fakephp() { mkdir -p "$(dirname "$1")"; printf '#!/bin/sh\necho "%s"\necho "Copyright (c) The PHP Group"\n' "$2" > "$1"; chmod 755 "$1"; }
fakephp /usr/local/bin/php "PHP 9.1.10-1~deb12u1 (cli) (built: Jan 1 2099) (NTS)"
fakephp /usr/local/sbin/php-fpm9.2 "PHP 9.2.5 (fpm-fcgi) (built: Jan 1 2099)"
fakephp /opt/php77/bin/php "PHP 7.7.1 (cli) (built: Jan 1 2099)"
run
check AT-2.1 "below fixed: path, version, SAPI cli, AFFECTED" grep -q "php: *AFFECTED TEST-RT-1  /usr/local/bin/php  \[version=9.1.10 sapi=cli fixed=9.1.20\]" $F/out
check AT-2.5 "distro suffix 9.1.10-1~deb12u1 compared on upstream part" has "version=9.1.10 "
check AT-2.2 "exactly at fixed version -> NOT AFFECTED" grep -q "NOT AFFECTED TEST-RT-1  /usr/local/sbin/php-fpm9.2  \[version=9.2.5 sapi=fpm" $F/out
check AT-2.3 "cli and fpm listed separately" sh -c "[ \$(grep -c '^php:' $F/out) -ge 3 ]"
check AT-2.4 "uncovered branch -> UNKNOWN (branch not covered)" has "branch not covered by definition"
check AT-7.2a "PATCH FIRST -> exit 20" sh -c "[ $(rc) = 20 ] && grep -q 'VERDICT: PATCH FIRST' $F/out"
case $PM in dpkg) EXP="sudo apt-get install --only-upgrade test-php";; rpm) EXP="sudo dnf upgrade test-php";; apk) EXP="sudo apk upgrade test-php";; esac
check AT-6.4 "actions show remediation.$PM word for word" has "     $EXP"
# AT-6.5 determinism
run; grep -v '^generated:' out > o1; run; grep -v '^generated:' out > o2
check AT-6.5 "same facts twice -> byte-identical apart from timestamp" sh -c "[ \"\$(sha256sum < o1)\" = \"\$(sha256sum < o2)\" ]"

# ---------- US-3 certifi ----------
mkdir -p /home/bruser/venvA/lib/python3.11/site-packages/certifi /home/bruser/venvB/lib/python3.11/site-packages/certifi
cat goodroot.pem badroot.pem > /home/bruser/venvA/lib/python3.11/site-packages/certifi/cacert.pem
cat goodroot.pem > /home/bruser/venvB/lib/python3.11/site-packages/certifi/cacert.pem
mkdir -p /srv/locked/lib/certifi; cp goodroot.pem /srv/locked/lib/certifi/cacert.pem; chmod 600 /srv/locked/lib/certifi/cacert.pem
chown -R bruser /home/bruser
# ---------- US-4 os bundle (fixture container only: append test root) ----------
B=""; for b in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt; do [ -e $b ] && { B=$(readlink -f $b); break; }; done
cp "$B" /tmp/bundle.orig; cat badroot.pem >> "$B"
run
check AT-3.1 "only venvA certifi AFFECTED, full path" sh -c "grep -q 'certifi: AFFECTED TEST-CA-1  /home/bruser/venvA/lib/python3.11/site-packages/certifi/cacert.pem' $F/out && grep -q 'certifi: NOT AFFECTED TEST-CA-1  /home/bruser/venvB' $F/out"
check AT-1.3 "unreadable file -> UNKNOWN (permission denied: path), run completes" sh -c "grep -q 'permission denied: /srv/locked/lib/certifi/cacert.pem' $F/out && grep -q VERDICT $F/out"
check AT-4.1 "system bundle with test root -> os_ca AFFECTED + bundle path" has "os_ca:   AFFECTED TEST-CA-1  "
# AT-4.5: ca_info (planned retirement) incident must never change the verdict
{ printf 'META\tversion\t9.9.5\nMETA\tpublished_at\t2099-01-01\n'
  printf 'INC\tTEST-INFO-1\tca_info\t9\t2099-01-01\tTest planned retirement\n'
  printf 'FP\tTEST-INFO-1\t%s\tos_ca,certifi,java,leaf_chain\tBR Test Distrusted Root\n' "$BADROOT_FP"
  printf 'ICN\tTEST-INFO-1\tBR Test Distrusted Root\n'; } > info.tsv
openssl pkeyutl -sign -rawin -inkey test-sign.key -in info.tsv -out info.tsv.sig; chmod 644 info.tsv*
su -s /bin/sh bruser -c "TMPDIR=/tmp $BR --trust-key $F/test-pub.pem --definitions $F/info.tsv --no-color" > out 2>&1; R=$?
check AT-4.5 "ca_info root present in bundle -> NOTE only, never ROTATE/PATCH, no actions" sh -c "grep -q 'os_ca:   NOTE TEST-INFO-1' $F/out && grep -q 'info only (does not change verdict)' $F/out && ! grep -q ':  *AFFECTED' $F/out && ! grep -q '^ACTIONS' $F/out && { [ $R = 0 ] || [ $R = 30 ]; }"
cp /tmp/bundle.orig "$B"
run
check AT-4.3 "root absent but package < fixed -> NOT AFFECTED + 'package older than fixed version'" sh -c "grep 'os_ca:' $F/out | grep -q 'NOT AFFECTED TEST-CA-1.*package older than fixed version'"
# AT-4.2: PKGMIN at 0 -> no note
grep -v '^PKGMIN' defs.tsv > d2; printf 'PKGMIN\tTEST-CA-1\t%s\tca-certificates\t0\n' "$PM" >> d2; mv d2 defs.tsv; openssl pkeyutl -sign -rawin -inkey test-sign.key -in defs.tsv -out defs.tsv.sig; chmod 644 defs.tsv*
run
check AT-4.2 "root absent, package >= fixed -> NOT AFFECTED, no note" sh -c "grep 'os_ca:' $F/out | grep 'NOT AFFECTED TEST-CA-1' | grep -vq 'older than'"

# ---------- Java ----------
if command -v keytool >/dev/null; then
  mkdir -p /usr/lib/jvm/testjdk/lib/security
  keytool -importcert -noprompt -alias brbad -file badroot.pem -keystore /usr/lib/jvm/testjdk/lib/security/cacerts -storepass changeit >/dev/null 2>&1
  chmod 644 /usr/lib/jvm/testjdk/lib/security/cacerts
  run
  check AT-3.2a "Java cacerts with test root + keytool -> AFFECTED" has "java:    AFFECTED TEST-CA-1  /usr/lib/jvm/testjdk/lib/security/cacerts"
  rm -rf /usr/lib/jvm/testjdk
else
  mkdir -p /etc/pki/java; cp badroot.pem /etc/pki/java/cacerts; chmod 644 /etc/pki/java/cacerts
  run
  check AT-3.2b "cacerts present, keytool absent -> UNKNOWN (keytool not found)" has "UNKNOWN (keytool not found)"
  rm -f /etc/pki/java/cacerts
fi

# ---------- US-5 leaf discovery ----------
mkdir -p /etc/nginx/conf.d /etc/apache2/sites-enabled /etc/haproxy /etc/postfix /etc/letsencrypt/live/good.example.test /etc/ssl/br
cat badleaf.pem badint.pem > /etc/ssl/br/bad-chain.pem
printf 'server {\n  listen 443 ssl;\n  ssl_certificate /etc/ssl/br/bad-chain.pem;\n  ssl_certificate_key /etc/ssl/br/bad.key;\n}\n' > /etc/nginx/conf.d/site.conf
cp badleaf.key /etc/ssl/br/bad.key
cat goodleaf.pem goodroot.pem > /etc/letsencrypt/live/good.example.test/fullchain.pem
cp goodleaf.pem /etc/ssl/br/apache.pem; cat goodroot.pem >> /etc/ssl/br/apache.pem
printf '<VirtualHost *:443>\n SSLCertificateFile /etc/ssl/br/apache.pem\n</VirtualHost>\n' > /etc/apache2/sites-enabled/default-ssl.conf
cp badleaf2.pem /etc/ssl/br/haproxy.pem
printf 'frontend fe\n  bind :443 ssl crt /etc/ssl/br/haproxy.pem\n' > /etc/haproxy/haproxy.cfg
cp orphan.pem /etc/ssl/br/orphan.pem
printf 'smtpd_tls_cert_file = /etc/ssl/br/orphan.pem\n' > /etc/postfix/main.cf
cp goodleaf.key /etc/ssl/trap.pem   # private key with a .pem name; must never be parsed
chmod -R a+rX /etc/nginx /etc/apache2 /etc/haproxy /etc/postfix /etc/letsencrypt /etc/ssl/br; chmod 644 /etc/ssl/trap.pem
run
check AT-5.1 "nginx-referenced leaf under distrusted intermediate -> AFFECTED with path, config, CN, expiry" sh -c "grep 'leaf:' $F/out | grep 'AFFECTED TEST-CA-1  /etc/ssl/br/bad-chain.pem' | grep 'CN=bad.example.test' | grep 'notAfter=' | grep -q 'ref: /etc/nginx/conf.d/site.conf'"
check AT-5.2 "unreferenced letsencrypt leaf on good CA -> NOT AFFECTED, unreferenced" sh -c "grep 'leaf:' $F/out | grep 'NOT AFFECTED TEST-CA-1  /etc/letsencrypt/live/good.example.test/fullchain.pem' | grep -q unreferenced"
check AT-5.3a "leaf-only, issuer name matches distrusted root -> AFFECTED" sh -c "grep 'leaf:' $F/out | grep -q 'AFFECTED TEST-CA-1  /etc/ssl/br/haproxy.pem'"
check AT-5.3b "leaf-only, unknown issuer -> UNKNOWN (chain incomplete)" sh -c "grep 'leaf:' $F/out | grep -q 'chain incomplete.*orphan.pem\|orphan.pem.*chain incomplete'"
check AT-5.5 "Apache/HAProxy/Postfix references discovered" sh -c "grep -q 'ref: /etc/apache2/sites-enabled/default-ssl.conf' $F/out && grep -q 'ref: /etc/haproxy/haproxy.cfg' $F/out && grep -q 'ref: /etc/postfix/main.cf' $F/out"
if command -v strace >/dev/null && strace -f -qq -e trace=none true >/dev/null 2>&1; then
  su -s /bin/sh bruser -c "TMPDIR=/tmp strace -f -qq -e trace=openat -o /tmp/st.log $BR --trust-key $F/test-pub.pem --definitions $F/defs.tsv --no-color" >/dev/null 2>&1
  # trap.pem may only be opened by 'head -c 64' (header peek); bad.key never
  check AT-5.4 "private keys never parsed (only 64-byte header peek)" sh -c "! grep -q 'bad.key' /tmp/st.log && ! grep 'trap.pem' /tmp/st.log | grep -v 'O_RDONLY' | grep -q . && [ \$(grep -c 'trap.pem\"' /tmp/st.log) -le 2 ]"
else
  echo "SKIP AT-5.4 strace not permitted in this container"
fi

# ---------- US-6 ranking ----------
check AT-6.1 "runtime + CA matches -> PATCH FIRST, action 1 runtime, action 2 CA" sh -c "grep -q 'VERDICT: PATCH FIRST' $F/out && grep -q '^1\. \[TEST-RT-1\]' $F/out && grep -q '^2\. \[TEST-CA-1\]' $F/out"
rm -f /usr/local/bin/php /usr/local/sbin/php-fpm9.2 /opt/php77/bin/php
run
check AT-6.2 "only CA matches -> ROTATE FIRST, leaf reissue after store update" sh -c "grep -q 'VERDICT: ROTATE FIRST' $F/out && [ $(rc) = 10 ] && grep -q 'Reissue from a trusted CA' $F/out"
# UNKNOWN only
rm -f /etc/ssl/br/bad-chain.pem /etc/ssl/br/haproxy.pem /home/bruser/venvA/lib/python3.11/site-packages/certifi/cacert.pem
run
check AT-6.3 "no matches + UNKNOWNs -> VERDICT UNKNOWN, exit 30, reasons listed" sh -c "grep -q 'VERDICT: UNKNOWN' $F/out && [ $(rc) = 30 ] && grep -q '^UNKNOWN checks' $F/out"

# ---------- US-7 JSON ----------
run --json
check AT-7.1 "--json: stdout is exactly one valid JSON document" python3 -c "import json,sys; d=json.load(open('$F/out')); assert d['verdict']=='UNKNOWN' and d['exit_code']==30"
check AT-7.3 "hostname excluded unless --include-hostname" sh -c "! grep -q '\"hostname\"' $F/out"
run --json --include-hostname
check AT-7.3b "--include-hostname adds hostname" grep -q '"hostname"' $F/out
su -s /bin/sh bruser -c "$BR --bogus" >/dev/null 2>&1; R=$?
check AT-7.2b "usage error -> exit 2" sh -c "[ $R = 2 ]"

# ---------- AT-1.4 performance: 50 distinct bundles, 200 leaf files ----------
SYS=$(cat /tmp/bundle.orig)
i=0; while [ $i -lt 50 ]; do mkdir -p /srv/perf/v$i/certifi; { printf '%s\n' "$SYS"; echo "# $i"; } > /srv/perf/v$i/certifi/cacert.pem; i=$((i+1)); done
i=0; while [ $i -lt 200 ]; do cp goodleaf.pem /etc/ssl/perf$i.pem; cat goodroot.pem >> /etc/ssl/perf$i.pem; i=$((i+1)); done
chmod -R a+rX /srv/perf; chmod 644 /etc/ssl/perf*.pem
NC=$(grep -c BEGIN /tmp/bundle.orig)
S=$(date +%s); run; E=$(( $(date +%s) - S ))
echo "     perf: 50 distinct certifi bundles x $NC certs + 200 leaf files: ${E}s"
check AT-1.4 "50 bundles + 200 leaf files in < 30 s (took ${E}s)" sh -c "[ $E -lt 30 ]"
rm -rf /srv/perf /etc/ssl/perf*.pem

echo "== RESULT $ID: $PASS passed, $FAILN failed"
