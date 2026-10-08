#!/bin/sh
# Builds the OpenWRT .ipk + .apk and the Entware .ipk for one prebuilt static binary.
# Needs GNU tar, gzip, sha256sum and apk-tools 3 (`apk mkpkg`, e.g. Alpine 3.23+).
# Usage: ci/package.sh <rust-target> <path/to/udns> <out-dir>
#
# The binaries are static, so one package fits every OpenWRT subtarget of a CPU
# family. OpenWRT packages are therefore "all"/"noarch", and the CPU family is in
# the file name. Entware has few arches, so its packages use the real arch name.
set -eu

TARGET=$1
BIN=$2
OUT=$3

case $TARGET in
    x86_64-unknown-linux-musl)    CPU=x86_64;  ENTWARE=x64-3.2 ;;
    i686-unknown-linux-musl)      CPU=i386;    ENTWARE= ;;
    aarch64-unknown-linux-musl)   CPU=aarch64; ENTWARE=aarch64-3.10 ;;
    armv7-unknown-linux-musleabi) CPU=armv7;   ENTWARE=armv7-3.2 ;;
    arm-unknown-linux-musleabi)   CPU=armv6;   ENTWARE= ;;
    mips-unknown-linux-musl)      CPU=mips;    ENTWARE=mips-3.4 ;;
    mipsel-unknown-linux-musl)    CPU=mipsel;  ENTWARE=mipsel-3.4 ;;
    riscv64gc-unknown-linux-musl) CPU=riscv64; ENTWARE= ;;
    *) echo "package.sh: unknown target $TARGET" >&2; exit 1 ;;
esac

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -n1)
DESCRIPTION="Small ad-blocking DNS forwarder (DNS, DoT, DoQ, DoH)"
URL="https://github.com/ohaiibuzzle/udns"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
export SOURCE_DATE_EPOCH=0

# sed that fails if the pattern is missing, so a changed config.example.toml
# breaks the build instead of silently shipping a wrong default config.
edit() {
    grep -q -e "$1" "$3" || { echo "package.sh: '$1' not found in $3" >&2; exit 1; }
    sed -i "s|$1|$2|" "$3"
}

# Packaged configs listen next to dnsmasq (which keeps port 53) instead of on :53.
make_config() { # <dest> <etc-dir>
    cp "$ROOT/config.example.toml" "$1"
    edit 'listen = \["0.0.0.0:53", "\[::\]:53"\]' 'listen = ["127.0.0.1:5354"]' "$1"
    edit '"/etc/udns/' "\"$2/udns/" "$1"
}

tar_gz() { # <out.tar.gz> <dir> <entries...>
    out=$1; dir=$2; shift 2
    tar --numeric-owner --owner=0 --group=0 --sort=name --mtime=@0 -C "$dir" -cf - "$@" | gzip -n9 > "$out"
}

make_ipk() { # <data-dir> <control-dir> <out.ipk>
    echo 2.0 > "$WORK/debian-binary"
    tar_gz "$WORK/data.tar.gz" "$1" .
    tar_gz "$WORK/control.tar.gz" "$2" .
    # opkg reads this outer tar.gz layout (what OpenWRT's ipkg-build makes).
    tar_gz "$3" "$WORK" ./debian-binary ./data.tar.gz ./control.tar.gz
    rm "$WORK/debian-binary" "$WORK/data.tar.gz" "$WORK/control.tar.gz"
}

write_control() { # <control-dir> <arch> <conffile>
    mkdir -p "$1"
    cat > "$1/control" <<EOF
Package: udns
Version: $VERSION
Architecture: $2
Section: net
URL: $URL
Description: $DESCRIPTION
EOF
    echo "$3" > "$1/conffiles"
}

# --- OpenWRT: same files for .ipk (opkg, up to 24.10) and .apk (apk, 25.x+) ---
OW=$WORK/openwrt
install -D -m 0755 "$BIN" "$OW/usr/bin/udns"
install -D -m 0755 "$ROOT/openwrt/udns.init" "$OW/etc/init.d/udns"
mkdir -p "$OW/etc/udns"
make_config "$OW/etc/udns.toml" /etc
edit '^# resolv_conf = ' 'resolv_conf = ' "$OW/etc/udns.toml"
edit '^resolv_conf = "/etc/resolv.conf"$' '# resolv_conf = "/etc/resolv.conf"' "$OW/etc/udns.toml"

# Same scripts OpenWRT's buildroot generates: enable + start on install,
# stop + disable on removal.
write_control "$WORK/ow-control" all /etc/udns.toml
cat > "$WORK/ow-control/postinst" <<'EOF'
#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
default_postinst $0 $@
EOF
cat > "$WORK/ow-control/prerm" <<'EOF'
#!/bin/sh
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
default_prerm $0 $@
EOF
chmod 0755 "$WORK/ow-control/postinst" "$WORK/ow-control/prerm"
make_ipk "$OW" "$WORK/ow-control" "$OUT/udns_${VERSION}_openwrt_${CPU}.ipk"

# apk has no control dir: the file list and conffiles live in the package itself.
APKDB=$OW/lib/apk/packages
mkdir -p "$APKDB"
(cd "$OW" && find . -type f -o -type l | sed 's|^\.||' | sort) > "$WORK/udns.list"
mv "$WORK/udns.list" "$APKDB/udns.list"
echo /etc/udns.toml > "$APKDB/udns.conffiles"
echo "/etc/udns.toml $(sha256sum "$OW/etc/udns.toml" | cut -d' ' -f1)" > "$APKDB/udns.conffiles_static"
cat > "$WORK/post-install" <<'EOF'
#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
export root="${IPKG_INSTROOT}"
export pkgname="udns"
default_postinst
EOF
{ echo '#!/bin/sh'; echo 'export PKG_UPGRADE=1'; sed 1d "$WORK/post-install"; } > "$WORK/post-upgrade"
cat > "$WORK/pre-deinstall" <<'EOF'
#!/bin/sh
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
export root="${IPKG_INSTROOT}"
export pkgname="udns"
default_prerm
EOF
apk mkpkg \
    --info "name:udns" \
    --info "version:$VERSION" \
    --info "description:$DESCRIPTION" \
    --info "arch:noarch" \
    --info "url:$URL" \
    --script "post-install:$WORK/post-install" \
    --script "post-upgrade:$WORK/post-upgrade" \
    --script "pre-deinstall:$WORK/pre-deinstall" \
    --files "$OW" \
    --output "$OUT/udns_${VERSION}_openwrt_${CPU}.apk"

# --- Entware: everything under /opt, SysV-style init script ---
if [ -n "$ENTWARE" ]; then
    EW=$WORK/entware
    install -D -m 0755 "$BIN" "$EW/opt/bin/udns"
    install -D -m 0755 "$ROOT/entware/S55udns" "$EW/opt/etc/init.d/S55udns"
    mkdir -p "$EW/opt/etc/udns"
    make_config "$EW/opt/etc/udns.toml" /opt/etc
    write_control "$WORK/ew-control" "$ENTWARE" /opt/etc/udns.toml
    make_ipk "$EW" "$WORK/ew-control" "$OUT/udns_${VERSION}_${ENTWARE}.ipk"
fi

# --- Standalone binary ---
install -m 0755 "$BIN" "$OUT/udns-$VERSION-$TARGET"
