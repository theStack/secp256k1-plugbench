#!/usr/bin/env bash
set -e

build_libsecp256k1_so() {
    local versionsuffix=$1
    local gitref=$2
    local description=$3
    if [ -f ../libsecp256k1-${versionsuffix}.so ]; then
        echo "libsecp256k1 version ${description} (libsecp256k1-${versionsuffix}.so) already exists, skip build."
        return 0
    fi
    echo "Building libsecp256k1 version ${description} (commit ${gitref})..."
    git clean -fdxq
    git checkout -q .
    git checkout -q $gitref
    ./autogen.sh > $versionsuffix.log 2>&1
    ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no >> $versionsuffix.log 2>&1
    make -j8 >> $versionsuffix.log 2>&1
    cp ./.libs/libsecp256k1.so ../libsecp256k1-${versionsuffix}.so
}

# TODO: put that in separate "rebuild" script or something similar
#rm -rf *.so *.a
#rm -rf secp256k1
if [ -d secp256k1 ]; then
    echo "secp256k1 folder already exists, skip repository cloning."
else
    git clone https://github.com/bitcoin-core/secp256k1
fi
pushd secp256k1 > /dev/null

# policy: start with the first Bitcoin Core version that used libsecp256k1 for ECDSA signature validation
# (i.e. v0.12), add a new version only if the secp256k1 subtree changed compared to the previous listed version

# libsecp256k1-PR #357, bitcoin-core-PR #7088 (merged on Nov 25, 2015)
build_libsecp256k1_so "core-v0_12_0" "6c527eceee7f5105c33c98dfae24ffeffd71f7cf" "used in Bitcoin Core v0.12.0"
# libsecp256k1-PR #433, bitcoin-core-PR #9334 (merged on Dec 13, 2016)
build_libsecp256k1_so "core-v0_14_0" "8225239f490f79842a5a3b82ad6cc8aa11d5208e" "used in Bitcoin Core v0.14.0"
# libsecp256k1-PR #454, bitcoin-core-PR #10323 (merged on Jun 2, 2017)
build_libsecp256k1_so "core-v0_15_0" "84973d393ac240a90b2e1a6538c5368202bc2224" "used in Bitcoin Core v0.15.0"
# libsecp256k1-PR #474, bitcoin-core-PR #11421 (merged on Oct 4, 2017)
build_libsecp256k1_so "core-v0_16_0" "0b7024185045a49a1a6a4c5615bf31c94f63d9c4" "used in Bitcoin Core v0.16.0"
# libsecp256k1-PR #607, bitcoin-core-PR #15703 (merged on May 29, 2019)
build_libsecp256k1_so "core-v0_19_0" "b19c000063be11018b4d1a6b0a85871ab9d0bdcf" "used in Bitcoin Core v0.19.0"
# libsecp256k1-PR #838, bitcoin-core-PR #20257 (merged on Oct 29, 2020)
build_libsecp256k1_so "core-v0_20_0" "3967d96bf184519eb98b766af665b4d4b072563e" "used in Bitcoin Core v0.20.0"
# libsecp256k1-PR #906, bitcoin-core-PR #21573 (merged on Jun 7, 2021)
build_libsecp256k1_so "core-v22_0" "efad3506a8937162e8010f5839fdf3771dfcf516" "used in Bitcoin Core v22.0"
# libsecp256k1-PR #988, bitcoin-core-PR #23383 (merged on Dec 18, 2021)
build_libsecp256k1_so "core-v23_0" "0559fc6e41b65af6e52c32eb9b1286494412a162" "used in Bitcoin Core v23.0"
# libsecp256k1-PR #1105, bitcoin-core-PR #25251 (merged on Jun 13, 2022)
build_libsecp256k1_so "core-v24_0" "44c2452fd387f7ca604ab42d73746e7d3a44d8a2" "used in Bitcoin Core v24.0"
# libsecp256k1-PR #1276 (v0.3.1 + CI), bitcoin-core-PR #27445 (merged on Apr 25, 2023)
build_libsecp256k1_so "core-v25_0" "4258c54f4ebfc09390168e8a43306c46b315134b" "used in Bitcoin Core v25.0"
# libsecp256k1-PR #1415 (v0.4.0), bitcoin-core-PR #28404 (merged on Sep 5, 2023)
build_libsecp256k1_so "core-v26_0" "199d27cea32203b224b208627533c2e813cd3b21" "used in Bitcoin Core v26.0"
# libsecp256k1-PR #1466 (v0.4.1), bitcoin-core-PR #29169 (merged on Jan 4, 2024)
build_libsecp256k1_so "core-v27_0" "efe85c70a2e357e3605a8901a9662295bae1001f" "used in Bitcoin Core v27.0"
# libsecp256k1-PR #1575 (v0.5.1), bitcoin-core-PR #30573 (merged on Aug 6, 2024)
build_libsecp256k1_so "core-v28_0" "642c885b6102725e25623738529895a95addc4f4" "used in Bitcoin Core v28.0"
# libsecp256k1-PR #1631 (v0.6.0), bitcoin-core-PR #31216 (merged on Nov 6, 2024)
build_libsecp256k1_so "core-v29_0" "0cdc758a56360bf58a851fe91085a327ec97685a" "used in Bitcoin Core v29.0"
# libsecp256k1-PR #1708 (v0.7.0), bitcoin-core-PR #33036 (merged on Jul 23, 2025)
build_libsecp256k1_so "core-v30_0" "b9313c6e1a6082a66b4c75777e18ca4b176fcf9d" "used in Bitcoin Core v30.0"

# build static library as well, we use it for creating the signatures to verify
echo "Building libsecp256k1 version v0.7.0 for static linking..."
git clean -fdxq
git checkout -q v0.7.0
./autogen.sh > staticbuild.log 2>&1
./configure --enable-static=yes --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no > staticbuild.log 2>&1
make -j8 > staticbuild.log 2>&1
cp ./.libs/libsecp256k1.a ../libsecp256k1.a

popd > /dev/null

build_openssl_so() {
    local versionsuffix=$1
    local gitref=$2
    local description=$3
    if [ -f ../openssl-${versionsuffix}.so ]; then
        echo "libsecp256k1 version ${description} (openssl-${versionsuffix}.so) already exists, skip build."
        return 0
    fi
    echo "Building OpenSSL version ${description} (commit ${gitref})..."
    git clean -fdxq
    git checkout -q .
    git checkout -q $gitref
    ./config shared > $versionsuffix.log 2>&1
    make >> $versionsuffix.log 2>&1
    cp libcrypto.so ../openssl-${versionsuffix}.so
}


if [ -d openssl ]; then
    echo "openssl folder already exists, skip repository cloning."
else
    git clone https://github.com/openssl/openssl
fi
pushd openssl > /dev/null

build_openssl_so "0_9_8h" "OpenSSL_0_9_8h" "0.9.8 (used in early Bitcoin Core clients < v0.12)"

popd > /dev/null
