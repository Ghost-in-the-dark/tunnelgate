#!/bin/sh
# TunnelGate - minimal JSON reader for busybox ash.
#
# Why not jq: OpenWrt does not ship jq, and the router must not download a JSON engine just
# to read one bootstrap response. Python is not guaranteed either. So this is a small
# recursive-descent JSON parser written in POSIX awk (busybox awk included) - it understands
# objects, arrays, strings with escapes (\n \t \r \" \\ \/ \b \f \uXXXX) and the
# number/true/false/null literals.
#
# API
#   json_get <dotted.path> [file]     print the decoded value, exit 0
#   json_has <dotted.path> [file]     exit 0 when the path exists (even if empty)
#
# Examples
#   json_get private_key /tmp/exchange.json    # real newlines, exact PEM text
#   json_get console.console_port /tmp/hb.json
#   json_get tunnel.remote_port
#
# Arrays are addressed by index: items.0.name
#
# Limitation that matters: \uXXXX above U+007F becomes '?'. Every field we read (hostnames,
# ports, PEM material, base64 keys) is ASCII, and silently emitting broken UTF-8 into an
# authorized_keys file would be worse than a visible replacement character.

# json_get <key> [file] -> stdout
json_get() {
    _json_key=${1:-}
    _json_file=${2:-${TG_JSON_FILE:-/tmp/tunnelgate-response.json}}
    [ -n "$_json_key" ] || return 2
    [ -r "$_json_file" ] || return 2
    awk -v want="$_json_key" '
        function jerr(msg) { ERR = msg; return 0 }

        function jskip(   c) {
            while (jp <= jlen) {
                c = substr(j, jp, 1)
                if (c == " " || c == "\t" || c == "\n" || c == "\r") jp++
                else break
            }
        }

        function jhex4(h,   i, c, v) {
            v = 0
            for (i = 1; i <= 4; i++) {
                c = tolower(substr(h, i, 1))
                if (c >= "0" && c <= "9") v = v * 16 + (c + 0)
                else if (c >= "a" && c <= "f") v = v * 16 + (index("abcdef", c) + 9)
                else return -1
            }
            return v
        }

        # Parse a JSON string at jp (which points at the opening quote).
        function jstring(   out, c, e, code) {
            jp++
            out = ""
            while (jp <= jlen) {
                c = substr(j, jp, 1)
                if (c == "\"") { jp++; SGVAL = out; return 1 }
                if (c != "\\") { out = out c; jp++; continue }
                e = substr(j, jp + 1, 1)
                jp += 2
                if (e == "n") out = out "\n"
                else if (e == "t") out = out "\t"
                else if (e == "r") out = out "\r"
                else if (e == "b") out = out "\b"
                else if (e == "f") out = out "\f"
                else if (e == "/" || e == "\\" || e == "\"") out = out e
                else if (e == "u") {
                    code = jhex4(substr(j, jp, 4))
                    jp += 4
                    if (code < 0) out = out "?"
                    else if (code < 128) out = out sprintf("%c", code)
                    else out = out "?"
                } else out = out e
            }
            return jerr("unterminated string")
        }

        function jvalue(path,   c, key, p, n, start, v) {
            jskip()
            if (jp > jlen) return jerr("unexpected end of input")
            c = substr(j, jp, 1)
            if (c == "{") {
                jp++; jskip()
                if (substr(j, jp, 1) == "}") { jp++; return 1 }
                while (jp <= jlen) {
                    jskip()
                    if (substr(j, jp, 1) != "\"") return jerr("expected object key")
                    if (!jstring()) return 0
                    key = SGVAL
                    jskip()
                    if (substr(j, jp, 1) != ":") return jerr("expected colon")
                    jp++
                    p = (path == "" ? key : path "." key)
                    if (!jvalue(p)) return 0
                    jskip()
                    c = substr(j, jp, 1)
                    if (c == ",") { jp++; continue }
                    if (c == "}") { jp++; return 1 }
                    return jerr("expected , or }")
                }
                return jerr("unterminated object")
            }
            if (c == "[") {
                jp++; jskip()
                if (substr(j, jp, 1) == "]") { jp++; return 1 }
                n = 0
                while (jp <= jlen) {
                    if (!jvalue(path "." n)) return 0
                    n++
                    jskip()
                    c = substr(j, jp, 1)
                    if (c == ",") { jp++; continue }
                    if (c == "]") { jp++; return 1 }
                    return jerr("expected , or ]")
                }
                return jerr("unterminated array")
            }
            if (c == "\"") {
                if (!jstring()) return 0
                val[path] = SGVAL
                typ[path] = "string"
                return 1
            }
            start = jp
            while (jp <= jlen) {
                c = substr(j, jp, 1)
                if (c == "," || c == "}" || c == "]" || c == " " || c == "\n" || c == "\r" || c == "\t") break
                jp++
            }
            if (jp == start) return jerr("empty literal")
            v = substr(j, start, jp - start)
            val[path] = v
            typ[path] = "literal"
            return 1
        }

        { j = j $0 "\n" }
        END {
            jlen = length(j)
            jp = 1
            if (!jvalue("")) {
                printf "json parse error: %s\n", (ERR == "" ? "unknown" : ERR) > "/dev/stderr"
                exit 3
            }
            if (want in typ) {
                printf "%s", val[want]
                exit 0
            }
            exit 1
        }
    ' "$_json_file"
}

# json_has <key> [file] -> exit 0 when the path exists
json_has() {
    json_get "$@" >/dev/null 2>&1
}
