#!/bin/sh
# Generates reference NAR serializations with Nix itself, for
# crates/trustforge-core/tests/nar_reference.rs, which rebuilds the same trees
# and checks that TrustForge's tree digests match.
#
# Run it once, from the repository root, in a pinned container without
# network access:
#
#   mkdir -p fixtures/nar
#   docker run --rm --network=none \
#     -v "$PWD/scripts:/scripts:ro" -v "$PWD/fixtures/nar:/out" \
#     -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
#     docker.io/nixos/nix:2.35.4@sha256:f159a58f390677f41e8e900a74b6e2f9c7f27b364122ae6acf7a652ce6c551c0 \
#     sh /scripts/nar-reference.sh
#
# Any change to a tree here must be mirrored in the test, and the reverse.

set -eu
umask 022

out=/out
work=$(mktemp -d)

# file PATH MODE CONTENT
file() {
    printf '%s' "$3" > "$1"
    chmod "$2" "$1"
}

# numbers PATH LENGTH: the first LENGTH bytes of "1\n2\n3\n...".
numbers() {
    seq 1 100000 | head -c "$2" > "$1"
    chmod 644 "$1"
}

# An empty directory.
mkdir "$work/empty"

# Contents around the 8-byte padding boundary and the 128 KiB read buffer.
mkdir "$work/sizes"
for n in 0 1 7 8 9 131071 131072 131073; do
    numbers "$work/sizes/$n" "$n"
done

# Only the owner-execute bit is recorded; hard links are dumped like copies.
mkdir "$work/modes"
file "$work/modes/a" 644 'mode a'
file "$work/modes/b" 655 'mode b'
file "$work/modes/c" 744 'mode c'
file "$work/modes/d" 755 'mode d'
ln "$work/modes/d" "$work/modes/e"
cp -p "$work/modes/d" "$work/modes/f"

# Sorting by bytes, and names of every length from 1 to 17.
mkdir "$work/names" "$work/names/a"
file "$work/names/a/x" 644 'a/x'
for name in B a-b a.b a_b 'ä' Z z 10 9; do
    file "$work/names/$name" 644 "$name"
done
name=n
while [ ${#name} -le 17 ]; do
    file "$work/names/$name" 644 "$name"
    name="${name}n"
done

# The two Unicode normalization forms of "é" are different names.
mkdir "$work/unicode"
file "$work/unicode/$(printf '\303\251')" 644 'nfc'
file "$work/unicode/$(printf 'e\314\201')" 644 'nfd'

# Symbolic links are recorded, never followed.
mkdir "$work/links" "$work/links/dir"
file "$work/links/target" 644 'target'
file "$work/links/dir/f" 644 'f'
ln -s target "$work/links/rel"
ln -s /nix/store/does-not-exist "$work/links/abs"
ln -s missing "$work/links/dangling"
ln -s dir "$work/links/dirlink"
ln -s ../outside "$work/links/up"

# Nested and empty directories.
mkdir -p "$work/nested/a/b/c/d" "$work/nested/a/empty" "$work/nested/a/b/empty2" "$work/nested/x/y"
file "$work/nested/a/b/c/d/file" 644 'deep'
file "$work/nested/top" 644 'top'

{
    echo "# $(nix-store --version)"
    for tree in empty sizes modes names unicode links nested; do
        nix-store --dump "$work/$tree" > "$out/$tree.nar"
        echo "$(nix-hash --type sha256 --base16 "$work/$tree")  $tree"
    done
} > "$out/nix-hash.txt"

chown -R "$HOST_UID:$HOST_GID" "$out"
