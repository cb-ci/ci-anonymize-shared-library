#!/bin/sh
# anonymize.sh - copy a source tree and replace sensitive details with consistent placeholders.
#
# The source directory is only ever READ. All output goes to a new destination directory.
# Replacements are consistent (same original -> same placeholder) so code stays readable.
# A mapping file (original -> placeholder) is written OUTSIDE the destination tree; it
# contains the real values, so treat it as sensitive and do not ship it with the output.
#
# Built-in rules (generic, project independent):
#   EMAIL   e-mail addresses                       -> user-NNN@example.com
#   EKS     EKS API endpoint hostnames             -> eks-endpoint-NNN.eks.example.com
#   IP      RFC1918 IPv4 (10/8, 172.16/12, 192.168/16) -> RFC5737 documentation ranges
#   AWSID   standalone 12-digit numbers (AWS account IDs) -> 00000000000N
#   SECRET  secrets (heuristic, see below)                -> REDACTED-SECRET-NNN
#             - PEM private key blocks (body removed, BEGIN/END lines kept)
#             - password in URLs      scheme://user:PASS@host
#             - known token formats   AWS access key IDs, GitHub (ghp_, github_pat_), GitLab
#                                     (glpat-), Slack (xox*-), Google API keys (AIza), JWTs
#             - Bearer/Basic values   Authorization: Bearer <20+ chars>
#             - CLI secret flags      --password X, --token=X, --api-key X, --client-secret X
#             - secret assignments    password|passwd|pwd|passphrase|token|api_key|access_key|
#                                     secret_key|client_secret|private_key  = / : <literal>
#           References are left alone (${VAR}, $VAR, credentials(...), <placeholder>, params.X)
#           and names ending in id/name/file/path/url/ref/env/var/type/prompt/dir (credentialsId
#           style). This is a safety net, not a guarantee: run a secret scanner on the output.
# Rules from a config file (project specific, see --init-config):
#   domain  internal domain; FQDNs under it        -> host-NNN.example.com
#   term    customer/product words (also in paths) -> replacement, case-preserving
#   name    personal names                         -> Person-NNN
#   regex   custom patterns (employee IDs, ...)    -> PREFIX-NNN  (regexi = case-insensitive)
#   keep    literal values that must never be replaced
#
# Requirements: POSIX sh, find, grep, sed, awk (BSD awk / gawk / mawk), sort.
# Limitations: text files get a trailing newline; filenames containing a single quote,
#              tab or newline are skipped (reported); symlinks are skipped; .git/.svn/.hg
#              are never copied (history is not anonymized).

set -eu

PROG=$(basename "$0")

usage() {
  cat <<EOF
Usage: $PROG [options] SRC DEST
       $PROG -n [options] SRC          (dry run: report only, write nothing)

Options:
  -c, --config FILE   rules file (default: \$ANON_RULES if set, else none)
  -m, --map FILE      mapping output file (default: DEST.mapping.tsv, next to DEST)
  -s, --skip CATS     comma-separated built-in categories to disable: EMAIL,EKS,IP,AWSID,SECRET
  -n, --dry-run       count matches per category/file, write nothing
      --init-config   print a rules template to stdout and exit
  -h, --help          this help

DEST must not exist, and must not be inside SRC (or vice versa).
EOF
}

print_template() {
  cat <<'EOF'
# anonymize.sh rules. One rule per line, fields separated by '|'.
# '#' starts a comment only at the beginning of a line.
# Replacement placeholders are generated; the values below are fictional examples.

# domain|<internal domain>
#   FQDNs under it -> host-NNN.example.com, the bare domain -> example.com
domain|corp.example.net

# term|<word>|<replacement>
#   case-insensitive substring match, case-preserving (acme->customer, Acme->Customer,
#   ACME->CUSTOMER); also applied to file and directory names.
term|acmecorp|customer

# name|<Full Name>
#   case-insensitive, whole words -> Person-NNN. List each spelling/order you need.
name|Jane Doe
name|Doe Jane

# regex|<CATEGORY>|<PREFIX>|<ERE>
#   custom POSIX ERE (case-sensitive, whole-word) -> PREFIX-NNN. Everything after the
#   third '|' is the pattern, so '|' alternation is fine. Avoid {n,m} intervals if you
#   run an old mawk (1.3.3).
# regexi|<CATEGORY>|<PREFIX>|<ERE>
#   same, but case-insensitive (write letters in lowercase). Use this for IDs that appear
#   in both cases, e.g. ab12345 and AB12345.
regexi|EMPID|USER|ab[0-9][0-9][0-9][0-9][0-9]

# keep|<literal>
#   exact matches (case-insensitive) that must never be replaced
keep|git@github.com
EOF
}

die() { echo "$PROG: error: $*" >&2; exit 1; }

CFG=${ANON_RULES:-}
MAP=
SKIP=
DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--dry-run) DRY=1 ;;
    -c|--config)  [ $# -ge 2 ] || die "$1 needs an argument"; CFG=$2; shift ;;
    -m|--map)     [ $# -ge 2 ] || die "$1 needs an argument"; MAP=$2; shift ;;
    -s|--skip)    [ $# -ge 2 ] || die "$1 needs an argument"; SKIP=$2; shift ;;
    --init-config) print_template; exit 0 ;;
    -h|--help)    usage; exit 0 ;;
    --)           shift; break ;;
    -*)           die "unknown option: $1 (see --help)" ;;
    *)            break ;;
  esac
  shift
done

if [ "$DRY" -eq 1 ]; then
  [ $# -ge 1 ] || { usage >&2; exit 2; }
else
  [ $# -eq 2 ] || { usage >&2; exit 2; }
fi

SRC=$1
DEST=${2:-}

[ -d "$SRC" ] || die "source is not a directory: $SRC"
SRC_ABS=$(cd "$SRC" && pwd -P)

if [ -n "$CFG" ]; then
  [ -f "$CFG" ] || die "config file not found: $CFG"
fi

DEST_ABS=-
MAP_ABS=-
if [ "$DRY" -eq 0 ]; then
  [ ! -e "$DEST" ] || die "destination already exists (refusing to overwrite): $DEST"
  DEST_PARENT=$(cd "$(dirname "$DEST")" 2>/dev/null && pwd -P) || die "parent of destination does not exist: $DEST"
  DEST_ABS="$DEST_PARENT/$(basename "$DEST")"
  case "$DEST_ABS/" in "$SRC_ABS"/*) die "destination is inside the source tree" ;; esac
  case "$SRC_ABS/" in "$DEST_ABS"/*) die "source is inside the destination tree" ;; esac

  [ -n "$MAP" ] || MAP="$DEST_ABS.mapping.tsv"
  [ ! -e "$MAP" ] || die "mapping file already exists (refusing to overwrite): $MAP"
  MAP_PARENT=$(cd "$(dirname "$MAP")" 2>/dev/null && pwd -P) || die "parent of mapping file does not exist: $MAP"
  MAP_ABS="$MAP_PARENT/$(basename "$MAP")"
  case "$MAP_ABS" in
    "$SRC_ABS"/*)  die "mapping file must not be inside the source tree" ;;
    "$DEST_ABS"/*) die "mapping file must not be inside the destination (it holds the real values)" ;;
  esac
fi

TMP_LIST=$(mktemp "${TMPDIR:-/tmp}/anonymize-list.XXXXXX")
TMP_AWK=$(mktemp "${TMPDIR:-/tmp}/anonymize-awk.XXXXXX")
trap 'rm -f "$TMP_LIST" "$TMP_AWK"' EXIT INT TERM

# Build the file list: "T<TAB>path" for text, "B<TAB>path" for binary. Never descends into VCS dirs.
(cd "$SRC_ABS" && find . \( -name .git -o -name .svn -o -name .hg \) -prune -o -type f -print) |
  sed 's|^\./||' |
  while IFS= read -r p; do
    if [ ! -s "$SRC_ABS/$p" ] || LC_ALL=C grep -Iq . "$SRC_ABS/$p"; then
      printf 'T\t%s\n' "$p"
    else
      printf 'B\t%s\n' "$p"
    fi
  done > "$TMP_LIST"

LINKS=$(cd "$SRC_ABS" && find . \( -name .git -o -name .svn -o -name .hg \) -prune -o -type l -print | wc -l | tr -d ' ')
[ "$LINKS" -eq 0 ] || echo "$PROG: note: $LINKS symlink(s) skipped" >&2

if [ "$DRY" -eq 0 ]; then
  mkdir "$DEST_ABS"
  ( umask 077; : > "$MAP_ABS" )
fi

cat > "$TMP_AWK" <<'AWK_EOF'
function rep(s, n,   o) { o = ""; while (n-- > 0) o = o s; return o }
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function esc(s,   i, c, o) {
  o = ""
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (index("\\.^$*+?(){}|[]", c)) o = o "\\" c; else o = o c
  }
  return o
}
function add_rule(c, e, k, b, ci_, a) {
  nr++; cat[nr] = c; re[nr] = e; kind[nr] = k; bnd[nr] = b; ci[nr] = ci_; aux[nr] = a; splt[nr] = ""
}
# Secret rule: only the secret value is replaced; sp is a regex (matched against the
# lowercased match) for the untouched prefix, e.g. 'password = "'.
function add_secret(e, ci_, k, sp) {
  add_rule("SECRET", e, k, (k == "secret") ? "word" : "none", ci_, "")
  splt[nr] = sp
}
function issec(k) { return (k == "secret" || k == "assign" || k == "cli" || k == "bearer" || k == "urlcred") }
function skipped_cat(c) { return index(skipcat, "," c ",") > 0 }

function pad12(n,   s) { s = "000000000000" n; return substr(s, length(s) - 11) }
function ipph(n) {
  if (n <= 254) return "192.0.2." n
  if (n <= 508) return "198.51.100." (n - 254)
  if (n <= 762) return "203.0.113." (n - 508)
  n -= 763
  return "10.255." int(n / 250) "." (n % 250 + 1)
}
function casepres(m, r,   f, rest) {
  if (m == toupper(m) && m != tolower(m)) return toupper(r)
  f = substr(m, 1, 1); rest = substr(m, 2)
  if (f == toupper(f) && f != tolower(f) && rest == tolower(rest))
    return toupper(substr(r, 1, 1)) substr(r, 2)
  return r
}

function ok(b, p, n1, n2) {
  if (b == "none") return 1
  if (b == "id")   return (p !~ /[0-9A-Za-z.]/ && n1 !~ /[0-9A-Za-z]/)
  if (b == "ip")   return (p !~ /[0-9A-Za-z.]/ && n1 !~ /[0-9]/ && !(n1 == "." && n2 ~ /[0-9]/))
  return (p !~ /[0-9A-Za-z_]/ && n1 !~ /[0-9A-Za-z_]/)
}
function skip(r, mt,   l) {
  l = tolower(mt)
  if (l in keep) return 1
  if (kind[r] == "email" && l ~ /@example\.(com|org|net)$/) return 1
  if (kind[r] == "email" && l ~ /^redacted-secret-/) return 1
  if (kind[r] == "awsid" && mt ~ /^00000000000[0-9]$/) return 1
  return 0
}
function placeholder(r, mt,   key, k, n, v) {
  key = cat[r] SUBSEP mt
  if (key in map) return map[key]
  k = kind[r]; n = ++seq[cat[r]]
  if      (k == "email")  v = sprintf("user-%03d@example.com", n)
  else if (k == "awsid")  v = pad12(n)
  else if (k == "eks")    v = sprintf("eks-endpoint-%03d.eks.example.com", n)
  else if (k == "ip")     v = ipph(n)
  else if (k == "domain") v = (tolower(mt) == dom[r]) ? aux[r] : sprintf("host-%03d.%s", n, aux[r])
  else if (k == "name")   v = sprintf("Person-%03d", n)
  else if (issec(k))      v = sprintf("REDACTED-SECRET-%03d", n)
  else if (k == "custom") v = sprintf("%s-%03d", aux[r], n)
  else                    v = casepres(mt, aux[r])
  map[key] = v
  return v
}

# Replacement for a prefix+value secret match; "" means leave the match unchanged.
function secret_repl(r, mt,   lm, pre, val, post, nm) {
  lm = tolower(mt)
  if (!match(lm, splt[r]) || RSTART != 1) return ""
  pre = substr(mt, 1, RLENGTH); val = substr(mt, RLENGTH + 1); post = ""
  if (kind[r] == "urlcred") { post = "@"; val = substr(val, 1, length(val) - 1) }
  if (val == "" || val ~ /^[$<{#(=~]/ || val ~ /^REDACTED-SECRET-/) return ""
  if (tolower(val) in keep) return ""
  if (tolower(val) ~ /^(true|false|null|none|nil)$/) return ""
  if (tolower(val) ~ /^(params|env|secrets|credentials|vars|config|data|args|opts)\./) return ""
  if (val ~ /^[A-Za-z_][A-Za-z0-9_.]*\(/) return ""     # function call, e.g. credentials('id')
  if (kind[r] == "assign") {
    nm = tolower(pre); sub(/[ \t]*[:=][ \t]*["']?$/, "", nm)
    if (nm ~ /(id|name|file|path|url|ref|env|var|type|prompt|dir)["']?$/) return ""
  }
  return pre placeholder(r, val) post
}

# Apply one rule to a string; returns the rewritten string.
function apply_rule(s, r,   acc, rest, low, st, n, mt, prv, n1, n2, rpl) {
  acc = ""; rest = s
  while (rest != "") {
    low = ci[r] ? tolower(rest) : rest
    if (!match(low, re[r])) break
    st = RSTART; n = RLENGTH
    if (n == 0) break
    mt = substr(rest, st, n)
    prv = (st > 1) ? substr(rest, st - 1, 1) : substr(acc, length(acc), 1)
    n1 = substr(rest, st + n, 1); n2 = substr(rest, st + n + 1, 1)
    if (!ok(bnd[r], prv, n1, n2)) {
      acc = acc substr(rest, 1, st); rest = substr(rest, st + 1)
      continue
    }
    if (skip(r, mt)) {                 # keep the whole match; do not retry inside it
      acc = acc substr(rest, 1, st + n - 1); rest = substr(rest, st + n)
      continue
    }
    if (splt[r] != "") {
      rpl = secret_repl(r, mt)
      if (rpl == "") { acc = acc substr(rest, 1, st + n - 1); rest = substr(rest, st + n); continue }
    } else rpl = placeholder(r, mt)
    acc = acc substr(rest, 1, st - 1) rpl
    rest = substr(rest, st + n)
    cnt[cat[r]]++; fh++
  }
  return acc rest
}
function mappath(p,   r) {
  for (r = 1; r <= nr; r++) if (kind[r] == "term") p = apply_rule(p, r)
  return p
}

BEGIN {
  FS = "\t"
  src = ENVIRON["ANON_SRC"]; dst = ENVIRON["ANON_DST"]; cfg = ENVIRON["ANON_CFG"]
  dry = (ENVIRON["ANON_DRY"] == "1"); mapf = ENVIRON["ANON_MAP"]
  skipcat = "," toupper(ENVIRON["ANON_SKIP"]) ","

  ncl = 0
  if (cfg != "") {
    while ((getline line < cfg) > 0) {
      sub(/\r$/, "", line)
      if (line ~ /^[ \t]*(#|$)/) continue
      t = line; sub(/\|.*/, "", t)
      ncl++; ct[ncl] = tolower(trim(t)); cr[ncl] = substr(line, index(line, "|") + 1)
      if (index(line, "|") == 0) { print "anonymize: bad rule (no '|'): ignored" > "/dev/stderr"; ncl-- }
    }
    close(cfg)
  }
  for (i = 1; i <= ncl; i++) if (ct[i] == "keep") keep[tolower(trim(cr[i]))] = 1

  # SECRET rules come first so a URL password is gone before the EMAIL rule sees user:pass@host.
  if (!skipped_cat("SECRET")) {
    add_secret("://[^/ \t:@$\"']+:[^/ \t@$\"']+@", 0, "urlcred", "^://[^/ \t:@$\"']+:")
    add_secret("(AKIA|ASIA)" rep("[0-9A-Z]", 16), 0, "secret", "")
    add_secret("gh[pousr]_" rep("[A-Za-z0-9]", 36) "[A-Za-z0-9]*", 0, "secret", "")
    add_secret("github_pat_" rep("[A-Za-z0-9_]", 22) "[A-Za-z0-9_]*", 0, "secret", "")
    add_secret("glpat-" rep("[A-Za-z0-9_-]", 20) "[A-Za-z0-9_-]*", 0, "secret", "")
    add_secret("xox[abprs]-" rep("[A-Za-z0-9-]", 10) "[A-Za-z0-9-]*", 0, "secret", "")
    add_secret("AIza" rep("[0-9A-Za-z_-]", 35), 0, "secret", "")
    add_secret("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+", 0, "secret", "")
    add_secret("(bearer|basic)[ \t]+" rep("[a-z0-9._~+/=-]", 20) "[a-z0-9._~+/=-]*", 1, "bearer", "^(bearer|basic)[ \t]+")
    add_secret("--(password|passwd|token|api-key|apikey|access-key|client-secret|secret-key)(=|[ \t]+)[\"']?[^ \t\"']+", 1, "cli", "^--[a-z-]+(=|[ \t]+)[\"']?")
    add_secret("(password|passwd|pwd|passphrase|token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key)[a-z0-9_.-]*[\"']?[ \t]*[:=][ \t]*[\"']?[^ \t\"',;)}]+", 1, "assign", "^[^:=]*[:=][ \t]*[\"']?")
  }
  if (!skipped_cat("EMAIL"))
    add_rule("EMAIL", "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z][A-Za-z]+", "email", "none", 0, "")
  if (!skipped_cat("EKS"))
    add_rule("EKS", rep("[a-f0-9]", 32) "\\.[a-z0-9]+\\.[a-z0-9-]+\\.eks\\.amazonaws\\.com(\\.cn)?", "eks", "none", 1, "")

  nd = 0
  for (i = 1; i <= ncl; i++) if (ct[i] == "domain") {
    v = tolower(trim(cr[i])); nd++
    add_rule("DOMAIN", "([a-z0-9-]+\\.)*" esc(v), "domain", "none", 1, (nd == 1) ? "example.com" : "example" nd ".com")
    dom[nr] = v
  }
  if (!skipped_cat("IP"))
    add_rule("IP", "(10\\.[0-9][0-9]?[0-9]?|172\\.(1[6-9]|2[0-9]|3[01])|192\\.168)\\.[0-9][0-9]?[0-9]?\\.[0-9][0-9]?[0-9]?", "ip", "ip", 0, "")
  if (!skipped_cat("AWSID"))
    add_rule("AWSID", rep("[0-9]", 12), "awsid", "id", 0, "")

  for (i = 1; i <= ncl; i++) if (ct[i] == "regex" || ct[i] == "regexi") {
    rest = cr[i]; a = index(rest, "|"); b2 = substr(rest, a + 1); b = index(b2, "|")
    if (a == 0 || b == 0) { print "anonymize: bad regex rule ignored" > "/dev/stderr"; continue }
    add_rule(toupper(trim(substr(rest, 1, a - 1))), (ct[i] == "regexi") ? tolower(substr(b2, b + 1)) : substr(b2, b + 1),
             "custom", "word", (ct[i] == "regexi"), trim(substr(b2, 1, b - 1)))
  }
  for (i = 1; i <= ncl; i++) if (ct[i] == "name") {
    nw = split(tolower(trim(cr[i])), w, /[ \t]+/); e = esc(w[1])
    for (j = 2; j <= nw; j++) e = e "[ \t]+" esc(w[j])
    add_rule("NAME", e, "name", "word", 1, "")
  }
  for (i = 1; i <= ncl; i++) if (ct[i] == "term") {
    rest = cr[i]; a = index(rest, "|")
    word = tolower(trim(a ? substr(rest, 1, a - 1) : rest))
    repl = a ? trim(substr(rest, a + 1)) : "example"
    if (repl == "") repl = "example"
    add_rule("TERM", esc(word), "term", "none", 1, repl)
  }
}

{
  mode = substr($0, 1, 1); rel = substr($0, 3)
  fh = 0
  drel = mappath(rel)
  if (index(rel, "'") || index(drel, "'")) { nskip++; print "anonymize: skipped (quote in filename): " rel > "/dev/stderr"; next }
  s = src "/" rel; d = dst "/" drel
  if (!dry) {
    dir = d; sub(/\/[^\/]*$/, "", dir)
    if (!(dir in made)) { system("mkdir -p '" dir "'"); made[dir] = 1 }
  }
  if (mode == "B") { nbin++; if (!dry) system("cp -p '" s "' '" d "'"); next }
  if (!dry) printf "" > (d)
  inkey = 0
  while ((getline line < s) > 0) {
    if (inkey) {                       # inside a multi-line PEM private key: drop the body
      if (line ~ /-----END [A-Z ]*PRIVATE KEY-----/) { inkey = 0; if (!dry) print line > (d) }
      continue
    }
    if (!skipped_cat("SECRET") && line ~ /-----BEGIN [A-Z ]*PRIVATE KEY-----/) {
      cnt["SECRET"]++; fh++
      if (line ~ /-----END [A-Z ]*PRIVATE KEY-----/)   # whole key on one line (e.g. JSON "\n")
        sub(/-----BEGIN [A-Z ]*PRIVATE KEY-----.*-----END [A-Z ]*PRIVATE KEY-----/, "-----BEGIN PRIVATE KEY-----REDACTED-PRIVATE-KEY-----END PRIVATE KEY-----", line)
      else {
        inkey = 1
        if (!dry) { print line > (d); print "REDACTED-PRIVATE-KEY" > (d) }
        continue
      }
      if (!dry) print line > (d)
      continue
    }
    out = line
    for (r = 1; r <= nr; r++) out = apply_rule(out, r)
    if (!dry) print out > (d)
  }
  close(s)
  if (!dry) { close(d); system("[ ! -x '" s "' ] || chmod +x '" d "'") }
  ntext++
  if (fh) { nchg++; perfile[rel] = fh }
}

END {
  if (!dry) {
    for (k in map) { split(k, kk, SUBSEP); print kk[1] "\t" kk[2] "\t" map[k] > (mapf) }
    close(mapf)
  }
  printf "%s: %d text file(s) (%d with changes), %d binary file(s) %s, %d skipped\n",
    (dry ? "DRY RUN" : "Done"), ntext, nchg, nbin, (dry ? "found" : "copied unchanged"), nskip > "/dev/stderr"
  for (c in cnt) printf "  %-8s %6d replacement(s)\n", c, cnt[c] | "sort 1>&2"
  close("sort 1>&2")
  for (f in perfile) printf "  %5d  %s\n", perfile[f], f | "sort -rn 1>&2"
  close("sort -rn 1>&2")
}
AWK_EOF

ANON_SRC="$SRC_ABS" ANON_DST="$DEST_ABS" ANON_CFG="$CFG" ANON_DRY="$DRY" \
ANON_MAP="$MAP_ABS" ANON_SKIP="$SKIP" LC_ALL=C \
  awk -f "$TMP_AWK" "$TMP_LIST"

if [ "$DRY" -eq 0 ]; then
  sort -o "$MAP_ABS" "$MAP_ABS"
  chmod 600 "$MAP_ABS"
  echo "Output:  $DEST_ABS" >&2
  echo "Mapping: $MAP_ABS  (contains REAL values - sensitive, keep it out of the output and out of git)" >&2
  echo "Next:    review the output and run a secret scanner (e.g. gitleaks) before sharing." >&2
fi
