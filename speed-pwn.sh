#!/usr/bin/env bash

blue="\e[34m"
clear="\e[0m"
bold="\e[1m"
title="$blue$bold"

data=$(readelf -h "$1" | grep 'Data' | cut -d':' -f2)
class=$(readelf -h "$1" | grep 'Class' | awk '{print $NF}')
machine=$(readelf -h "$1"| grep 'Machine' | awk '{print $NF}')

echo -e "$title\n=== ELF ===\n$clear"
echo -e "$machine $class $data"

echo -e "$title\n=== Checksec ===\n$clear"
checksec --file="$1"

echo -e "$title\n=== Strings ===\n$clear"
rabin2 -z "$1" | grep --color -E '/bin/sh|/bin/bash|/sh$|flag.txt|/flag'

echo -e "$\n=== Symbols ===\n"
rabin2 -s "$1"  | grep --color -E 'win$|main$|flag$|csu|pwn|challenge'

echo -e "$title\n=== Main diasm ===\n$clear"
r2 -A -Q -c 'pdf @main' "$1" 2>/dev/null

ropper --nocolor -f "$1" 2>/dev/null > "$1-gadgets.txt"
echo -e "$title\n=== `wc -l $1-gadgets.txt` ===$clear"

r2 -A -q -c 'e scr.color=0; afl; pdf @@f' "$1" 2>/dev/null > "$1-disasm.s"
echo -e "$title=== `wc -l $1-disasm.s` ===$clear"
