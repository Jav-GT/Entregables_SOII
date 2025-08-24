#!/usr/bin/env bash
# ------------------------------------------------------------
# Apache Modules Setup + Validation Suite (Ubuntu/Debian)
# Installs & configures key Apache modules for security & perf
# and runs repeatable checks/benchmarks before vs. after.
# ------------------------------------------------------------
# Usage:
#   sudo bash setup_apache_modules.sh [setup|test|all]
#   sudo bash setup_apache_modules.sh all   # install + configure + run tests
#
# Notes:
# - Designed for Ubuntu/Debian with a2enmod/a2dismod.
# - Safe for lab/VM use. Avoid loading DoS tests on production.
# - Generates: /root/apache_module_tests_report.md and CSV in /root.
# - Requires Internet for apt packages and (optionally) OWASP CRS.
# ------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'

# ----------- GLOBALS -----------
APACHE_SVC="apache2"
APACHECTL="apachectl"
DOCROOT="/var/www/html"
HTTP_URL="http://127.0.0.1"
HTTPS_URL="https://127.0.0.1"
ACCESS_LOG="/var/log/apache2/access.log"
ERROR_LOG="/var/log/apache2/error.log"
REPORT_MD="/root/apache_module_tests_report.md"
REPORT_CSV="/root/apache_module_tests_results.csv"
WORK_DIR="/root/apache-modules-lab"
SELF_CERT_DIR="/etc/ssl/localcerts"
REMOTEIP_TEST_IP="203.0.113.77"    # TEST-NET-3 RFC5737
DATE_STR="$(date -Is)"

# ----------- UTILITIES -----------
log() { echo -e "[+] $*"; }
warn() { echo -e "[!] $*" >&2; }
section() { echo -e "\n===== $* =====\n"; }
need_root() { if [[ $EUID -ne 0 ]]; then echo "Please run as root (sudo)."; exit 1; fi; }

retry(){
  local n=0 max=5 delay=2
  until "$@"; do
    n=$((n+1))
    if [[ $n -ge $max ]]; then return 1; fi
    sleep $delay
  done
}

# CSV header
init_reports(){
  mkdir -p "$WORK_DIR"
  echo "metric,module,baseline,with_module,unit,notes,timestamp" > "$REPORT_CSV"
  cat > "$REPORT_MD" <<EOF
# Apache Modules Validation Report
Generated: $DATE_STR

This report captures before/after checks for selected Apache modules on Ubuntu/Debian.

EOF
}

append_md(){ echo -e "$*" >> "$REPORT_MD"; }
append_csv(){ echo "$*" >> "$REPORT_CSV"; }

apt_install(){
  export DEBIAN_FRONTEND=noninteractive
  retry apt-get update -y
  apt-get install -y \
    apache2 apache2-utils \
    openssl curl jq bc \
    nghttp2-client \
    libapache2-mod-security2 \
    libapache2-mod-evasive || true
  # Optional CRS ruleset (may not exist on all distros)
  apt-get install -y modsecurity-crs || true
}

restart_apache(){ systemctl restart "$APACHE_SVC"; sleep 1; }
reload_apache(){ systemctl reload "$APACHE_SVC" || restart_apache; sleep 1; }

ensure_apache_running(){
  systemctl enable "$APACHE_SVC" >/dev/null 2>&1 || true
  systemctl start "$APACHE_SVC" || true
}

# ----------- BASE CONTENT -----------
seed_test_content(){
  mkdir -p "$DOCROOT"
  # Large-ish text to see gzip effect
  if [[ ! -f "$DOCROOT/test.txt" ]]; then
    base64 /dev/urandom | head -c 200000 > "$DOCROOT/test.txt"
  fi
  # Simple HTML page
  cat > "$DOCROOT/index.html" <<'HTML'
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Apache Modules Lab</title>
</head>
<body>
  <h1>Apache Modules Lab</h1>
  <p>Static index page for testing.</p>
  <p>Try <a href="/test.txt">/test.txt</a> (large text) and <a href="/backend">/backend</a> proxy test.</p>
</body>
</html>
HTML
}

# ----------- TLS (self-signed) -----------
setup_self_signed_tls(){
  mkdir -p "$SELF_CERT_DIR"
  if [[ ! -f "$SELF_CERT_DIR/selfsigned.key" ]]; then
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout "$SELF_CERT_DIR/selfsigned.key" \
      -out "$SELF_CERT_DIR/selfsigned.crt" \
      -subj "/C=CR/ST=CR/L=Local/O=Lab/OU=IT/CN=localhost" >/dev/null 2>&1
    chmod 600 "$SELF_CERT_DIR/selfsigned.key"
  fi
  a2enmod ssl >/dev/null 2>&1 || true
  a2ensite default-ssl >/dev/null 2>&1 || true
  sed -i "s#SSLCertificateFile .*#SSLCertificateFile $SELF_CERT_DIR/selfsigned.crt#" /etc/apache2/sites-available/default-ssl.conf
  sed -i "s#SSLCertificateKeyFile .*#SSLCertificateKeyFile $SELF_CERT_DIR/selfsigned.key#" /etc/apache2/sites-available/default-ssl.conf
  # Enable HTTP/2 on SSL vhost
  a2enmod http2 >/dev/null 2>&1 || true
  if ! grep -q "^\s*Protocols\s\+h2" /etc/apache2/sites-available/default-ssl.conf; then
    sed -i '/<VirtualHost \*:\s*443>/a \\tProtocols h2 http/1.1' /etc/apache2/sites-available/default-ssl.conf
  fi
}

# ----------- CONFIG SNIPPETS -----------
write_snippets(){
  # Security headers
  cat > /etc/apache2/conf-available/security-headers.conf <<'CONF'
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
  Header set X-Content-Type-Options "nosniff"
  Header set X-Frame-Options "SAMEORIGIN"
  # A conservative CSP for lab; adjust for real apps
  Header set Content-Security-Policy "default-src 'self'"
</IfModule>
CONF
  a2enmod headers >/dev/null 2>&1 || true
  a2enconf security-headers >/dev/null 2>&1 || true

  # RemoteIP behind proxy/HAProxy
  cat > /etc/apache2/conf-available/remoteip.conf <<CONF
<IfModule mod_remoteip.c>
  RemoteIPHeader X-Forwarded-For
  RemoteIPInternalProxy 127.0.0.1/8
  RemoteIPInternalProxy ::1
</IfModule>
CONF
  a2enmod remoteip >/dev/null 2>&1 || true
  a2enconf remoteip >/dev/null 2>&1 || true

  # mod_status (restricted to localhost)
  cat > /etc/apache2/conf-available/status.conf <<'CONF'
<IfModule mod_status.c>
  <Location /server-status>
    SetHandler server-status
    Require local
  </Location>
  ExtendedStatus On
</IfModule>
CONF
  a2enmod status >/dev/null 2>&1 || true
  a2enconf status >/dev/null 2>&1 || true

  # mod_evasive
  cat > /etc/apache2/mods-available/evasive.conf <<'CONF'
<IfModule mod_evasive20.c>
  DOSHashTableSize    3097
  DOSPageCount        20
  DOSSiteCount        150
  DOSPageInterval     1
  DOSSiteInterval     1
  DOSBlockingPeriod   10
  DOSEmailNotify      root@localhost
  DOSLogDir           "/var/log/mod_evasive" 
</IfModule>
CONF
  mkdir -p /var/log/mod_evasive && chown www-data:adm /var/log/mod_evasive || true
  a2enmod evasive >/dev/null 2>&1 || true

  # mod_deflate
  cat > /etc/apache2/conf-available/deflate.conf <<'CONF'
<IfModule mod_deflate.c>
  AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css application/javascript application/json
</IfModule>
CONF
  a2enmod deflate >/dev/null 2>&1 || true
  a2enconf deflate >/dev/null 2>&1 || true

  # mod_expires
  cat > /etc/apache2/conf-available/expires.conf <<'CONF'
<IfModule mod_expires.c>
  ExpiresActive On
  ExpiresByType text/css "access plus 7 days"
  ExpiresByType application/javascript "access plus 7 days"
  ExpiresByType image/jpeg "access plus 7 days"
  ExpiresByType image/png "access plus 7 days"
  ExpiresDefault "access plus 1 hour"
</IfModule>
CONF
  a2enmod expires >/dev/null 2>&1 || true
  a2enconf expires >/dev/null 2>&1 || true

  # mod_cache (disk)
  cat > /etc/apache2/conf-available/cache.conf <<'CONF'
<IfModule mod_cache.c>
  CacheQuickHandler On
  CacheLock on
  CacheLockPath /tmp/mod_cache-lock
  CacheIgnoreHeaders Set-Cookie
  <IfModule mod_cache_disk.c>
    CacheRoot "/var/cache/apache2/mod_cache_disk"
    CacheEnable disk "/"
    CacheDirLevels 2
    CacheDirLength 1
  </IfModule>
</IfModule>
CONF
  a2enmod cache cache_disk >/dev/null 2>&1 || true
  a2enconf cache >/dev/null 2>&1 || true

  # mod_rewrite redirect HTTP->HTTPS
  a2enmod rewrite >/dev/null 2>&1 || true
  if ! grep -q "RewriteEngine On" /etc/apache2/sites-available/000-default.conf; then
    sed -i '/<VirtualHost \*:\s*80>/a \\tRewriteEngine On\n\\tRewriteCond %{HTTPS} !=on\n\\tRewriteRule ^/(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]' /etc/apache2/sites-available/000-default.conf
  fi

  # mod_proxy test route
  a2enmod proxy proxy_http proxy_balancer lbmethod_byrequests >/dev/null 2>&1 || true
  cat > /etc/apache2/conf-available/proxy-test.conf <<'CONF'
<IfModule mod_proxy.c>
  ProxyRequests Off
  ProxyPass "/backend" "http://127.0.0.1:8080/"
  ProxyPassReverse "/backend" "http://127.0.0.1:8080/"
</IfModule>
CONF
  a2enconf proxy-test >/dev/null 2>&1 || true

  # ModSecurity base config + CRS
  a2enmod security2 >/dev/null 2>&1 || true
  if [[ -f /etc/modsecurity/modsecurity.conf-recommended ]]; then
    cp -f /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf || true
  fi
  if [[ -d /usr/share/modsecurity-crs ]]; then
    ln -sf /usr/share/modsecurity-crs/crs-setup.conf /etc/modsecurity/crs-setup.conf || true
    mkdir -p /etc/modsecurity/rules
    ln -sf /usr/share/modsecurity-crs/rules/*.conf /etc/modsecurity/rules/ || true
    if ! grep -q ". /etc/modsecurity/crs-setup.conf" /etc/apache2/mods-available/security2.conf; then
      sed -i '/^\s*<IfModule security2_module>/a \\tIncludeOptional /etc/modsecurity/crs-setup.conf\n\\tIncludeOptional /etc/modsecurity/rules/*.conf' /etc/apache2/mods-available/security2.conf
    fi
  else
    warn "OWASP CRS not found; ModSecurity will run with core config only."
  fi
}

# ----------- SIMPLE BACKEND FOR PROXY -----------
start_backend(){
  # Simple Python HTTP server as backend (8080)
  if command -v python3 >/dev/null 2>&1; then
    ( cd "$DOCROOT" && nohup python3 -m http.server 8080 >/tmp/backend8080.log 2>&1 & echo $! > /tmp/backend8080.pid ) || true
    sleep 1
  fi
}
stop_backend(){
  if [[ -f /tmp/backend8080.pid ]]; then
    kill "$(cat /tmp/backend8080.pid)" 2>/dev/null || true
    rm -f /tmp/backend8080.pid
  fi
}

# ----------- TEST HELPERS -----------
http_status(){
  local url="$1"; shift
  curl -k -s -o /dev/null -w "%{http_code}" "$url"
}

curl_head(){ curl -k -s -D - -o /dev/null "$1"; }

bench_ab(){
  local url="$1"; local n=${2:-200}; local c=${3:-20}
  ab -k -n "$n" -c "$c" "$url/" 2>/dev/null | awk -F':' '/Requests per second|Time per request|Transfer rate/{gsub(/^[ \t]+/,"",$2); print $1":"$2}'
}

bench_h2(){
  local url="$1"; local n=${2:-100}; local c=${3:-10}
  # h2load needs https://host:443/
  h2load -n "$n" -c "$c" "$url/" 2>/dev/null | awk -F':' '/requests:/{print}'
}

# ----------- MODULE TESTS -----------

test_headers(){
  section "Test: mod_headers (security headers)"
  local out
  out=$(curl_head "$HTTPS_URL")
  append_md "## mod_headers\n\n\n$out\n\n"
  for h in Strict-Transport-Security X-Content-Type-Options X-Frame-Options Content-Security-Policy; do
    if echo "$out" | grep -qi "^$h:"; then
      append_csv "header,$h,,present,,via curl -I,$(date -Is)"
    else
      append_csv "header,$h,,missing,,via curl -I,$(date -Is)"
    fi
  done
}


test_deflate(){
  section "Test: mod_deflate (gzip)"
  a2dismod -f deflate >/dev/null 2>&1 || true; reload_apache
  local size_plain size_gzip
  size_plain=$(curl -s -o /dev/null -w "%{size_download}" "$HTTP_URL/test.txt")
  a2enmod deflate >/dev/null 2>&1 || true; reload_apache
  size_gzip=$(curl --compressed -s -o /dev/null -w "%{size_download}" "$HTTP_URL/test.txt")
  append_md "## mod_deflate\n\nBytes w/o gzip: $size_plain\n\nBytes with gzip (accept-encoding): $size_gzip\n\n"
  append_csv "bytes,mod_deflate,$size_plain,$size_gzip,bytes,download size,$(date -Is)"
}


test_expires(){
  section "Test: mod_expires"
  local out
  out=$(curl_head "$HTTP_URL/test.txt")
  append_md "## mod_expires\n\n\n$out\n\n"
  if echo "$out" | grep -qi "^Expires:"; then
    append_csv "header,mod_expires,,present,,Expires header,$(date -Is)"
  else
    append_csv "header,mod_expires,,missing,,Expires header,$(date -Is)"
  fi
}


test_cache(){
  section "Test: mod_cache_disk"
  # Warm-up miss
  curl -s -o /dev/null "$HTTP_URL/test.txt" || true
  # Measure two runs
  local t1 t2
  t1=$( { /usr/bin/time -f %e curl -s -o /dev/null "$HTTP_URL/test.txt"; } 2>&1 )
  t2=$( { /usr/bin/time -f %e curl -s -o /dev/null "$HTTP_URL/test.txt"; } 2>&1 )
  append_md "## mod_cache_disk\n\nTime first request (s): $t1\n\nTime second request (s): $t2\n\n"
  append_csv "latency,mod_cache_disk,$t1,$t2,seconds,curl time,$(date -Is)"
}


test_http2(){
  section "Test: mod_http2"
  # Baseline HTTP/1.1 via ab
  local ab_metrics h2_metrics
  ab_metrics=$(bench_ab "$HTTP_URL" 200 20)
  # HTTP/2 via h2load (TLS)
  h2_metrics=$(bench_h2 "$HTTPS_URL" 100 10)
  append_md "## mod_http2\n\n**ab (HTTP/1.1)**\n\n\n$ab_metrics\n\n**h2load (HTTP/2)**\n\n\n$h2_metrics\n\n"
  # Best-effort parse RPS
  local ab_rps
  ab_rps=$(echo "$ab_metrics" | awk -F': ' '/Requests per second/{print $2}' | awk '{print $1}')
  append_csv "rps,mod_http2,$ab_rps,,req/s,ab vs h2load (see md),$(date -Is)"
}


test_remoteip(){
  section "Test: mod_remoteip"
  # Hit server with spoofed X-Forwarded-For
  curl -s -H "X-Forwarded-For: $REMOTEIP_TEST_IP" "$HTTP_URL/" >/dev/null || true
  sleep 1
  local last
  last=$(tail -n 1 "$ACCESS_LOG" || true)
  append_md "## mod_remoteip\n\nLast access log line (expect $REMOTEIP_TEST_IP appears):\n\n\n$last\n\n"
  if echo "$last" | grep -q "$REMOTEIP_TEST_IP"; then
    append_csv "logip,mod_remoteip,,ok,,found $REMOTEIP_TEST_IP,$(date -Is)"
  else
    append_csv "logip,mod_remoteip,,fail,,not found in last line,$(date -Is)"
  fi
}


test_modsecurity(){
  section "Test: ModSecurity + OWASP CRS"
  local benign malicious_code m_status b_status
  benign="$HTTP_URL/?id=1"
  malicious_code="$HTTP_URL/?id=1%20OR%201=1"
  b_status=$(http_status "$benign")
  m_status=$(http_status "$malicious_code")
  append_md "## ModSecurity\n\nBenign status: $b_status\n\nMalicious-like status: $m_status (expect 403/406 with CRS)\n\n"
  append_csv "status,mod_security,$b_status,$m_status,http_status,benign vs malicious,$(date -Is)"
}


test_evasive(){
  section "Test: mod_evasive"
  # Attempt to trigger blocking with burst requests
  local out
  out=$(ab -n 300 -c 100 "$HTTP_URL/" 2>&1 || true)
  append_md "## mod_evasive\n\nRaw ab output snippet:\n\n\n$(echo "$out" | tail -n 20)\n\nCheck $ERROR_LOG for mod_evasive entries.\n\n"
  if grep -qi "evasive" "$ERROR_LOG"; then
    append_csv "block,mod_evasive,,triggered,,error.log mentions,$(date -Is)"
  else
    append_csv "block,mod_evasive,,not_triggered,,tune thresholds,$(date -Is)"
  fi
}


test_proxy(){
  section "Test: mod_proxy"
  start_backend
  local code
  code=$(http_status "$HTTP_URL/backend")
  append_md "## mod_proxy\n\nGET /backend -> HTTP $code\n\n"
  append_csv "status,mod_proxy,,${code},http_status,/backend,$(date -Is)"
  stop_backend
}


test_status_endpoint(){
  section "Test: mod_status"
  local code
  code=$(http_status "$HTTP_URL/server-status?auto")
  append_md "## mod_status\n\n/server-status?auto -> HTTP $code (200 expected from localhost)\n\n"
  append_csv "status,mod_status,,${code},http_status,/server-status,$(date -Is)"
}


test_rewrite_ssl_redirect(){
  section "Test: mod_rewrite (HTTP->HTTPS)"
  local code loc
  code=$(curl -s -o /dev/null -D - "$HTTP_URL/" | awk '/^HTTP\//{c=$2} END{print c}')
  loc=$(curl -s -o /dev/null -D - "$HTTP_URL/" | awk -F': ' '/^Location:/{print $2}' | tr -d '\r')
  append_md "## mod_rewrite\n\nHTTP status from / : $code (expect 301)\n\nLocation: $loc\n\n"
  append_csv "status,mod_rewrite,,${code},http_status,expect 301 to HTTPS,$(date -Is)"
}

# ----------- MAIN OPS -----------
setup_all(){
  need_root
  section "Installing packages"
  apt_install
  ensure_apache_running
  section "Seeding test content"
  seed_test_content
  section "Writing configs"
  write_snippets
  section "Configuring TLS"
  setup_self_signed_tls
  section "(Re)start Apache"
  restart_apache
  log "Setup complete."
}

run_tests(){
  need_root
  init_reports
  test_headers
  test_deflate
  test_expires
  test_cache
  test_http2
  test_remoteip
  test_modsecurity
  test_evasive
  test_proxy
  test_status_endpoint
  test_rewrite_ssl_redirect
  append_md "\n---\n\nCSV data saved to: $REPORT_CSV\n\n"
  log "Report ready: $REPORT_MD"
}

all(){ setup_all; run_tests; }

# ----------- ENTRYPOINT -----------
case "${1:-all}" in
  setup) setup_all ;;
  test)  run_tests ;;
  all)   all ;;
  *)     echo "Usage: $0 [setup|test|all]"; exit 1 ;;
esac
