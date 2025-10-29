#!/usr/bin/env bash
rm -rf *.so *.a
rm -rf secp256k1
git clone https://github.com/bitcoin-core/secp256k1
pushd secp256k1

git clean -fdx
# secp256k1 commit "Merge pull request #357", Bitcoin Core PR #7088 (v0.12.0)
git checkout 6c527eceee7f5105c33c98dfae24ffeffd71f7cf
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v0_12_0.so

git clean -fdx
# secp256k1 commit "Merge #433", Bitcoin Core PR #9334 (v0.14.0)
git checkout 8225239f490f79842a5a3b82ad6cc8aa11d5208e
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v0_14_0.so

git clean -fdx
# secp256k1 commit "Merge #454", Bitcoin Core PR #10323 (v0.15.0)
git checkout 84973d393ac240a90b2e1a6538c5368202bc2224
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v0_15_0.so

git clean -fdx
# secp256k1 commit "Merge #474", Bitcoin Core PR #11421 (v0.16.0)
git checkout 0b7024185045a49a1a6a4c5615bf31c94f63d9c4
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v0_16_0.so

git clean -fdx
# secp256k1 commit "Merge #607", Bitcoin Core PR #15703 (v0.19.0)
git checkout b19c000063be11018b4d1a6b0a85871ab9d0bdcf
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v0_19_0.so

git clean -fdx
# secp256k1 commit "Merge #838", Bitcoin Core PR #20257 (v0.20.0)
git checkout 3967d96bf184519eb98b766af665b4d4b072563e
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v0_20_0.so

git clean -fdx
# secp256k1 commit "Merge #906", Bitcoin Core PR #21573 (v22.0)
git checkout efad3506a8937162e8010f5839fdf3771dfcf516
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v22_0.so

git clean -fdx
# secp256k1 commit "Merge #988", Bitcoin Core PR #23383 (v23.0)
git checkout 0559fc6e41b65af6e52c32eb9b1286494412a162
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v23_0.so

git clean -fdx
# secp256k1 commit "Merge #1105", Bitcoin Core PR #25251 (v24.0)
git checkout 44c2452fd387f7ca604ab42d73746e7d3a44d8a2
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v24_0.so

git clean -fdx
# secp256k1 commit "Merge #1276" (v0.3.1 + CI), Bitcoin Core PR #27445 (v25.0)
git checkout 4258c54f4ebfc09390168e8a43306c46b315134b
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v25_0.so

git clean -fdx
# secp256k1 commit "Merge #1415" (v0.4.0), Bitcoin Core PR #28404 (v26.0)
git checkout 199d27cea32203b224b208627533c2e813cd3b21
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v26_0.so

git clean -fdx
# secp256k1 commit "Merge #1466" (v0.4.1), Bitcoin Core PR #29169 (v27.0)
git checkout efe85c70a2e357e3605a8901a9662295bae1001f
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v27_0.so

git clean -fdx
# secp256k1 commit "Merge #1575" (v0.5.1), Bitcoin Core PR #30573 (v28.0)
git checkout 642c885b6102725e25623738529895a95addc4f4
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v28_0.so

git clean -fdx
# secp256k1 commit "Merge #1631" (v0.6.0), Bitcoin Core PR #31216 (v29.0)
git checkout 0cdc758a56360bf58a851fe91085a327ec97685a
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v29_0.so

git clean -fdx
# secp256k1 commit "Merge #1708" (v0.7.0), Bitcoin Core PR #33036 (v30.0)
git checkout b9313c6e1a6082a66b4c75777e18ca4b176fcf9d
./autogen.sh && ./configure --enable-static=no --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
cp ./.libs/libsecp256k1.so ../libsecp256k1-core-v30_0.so

git clean -fdx
git checkout v0.7.0
./autogen.sh && ./configure --enable-static=yes --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no && make -j8
# cp ./.libs/libsecp256k1.so ../libsecp256k1-v0_7_0.so
cp ./.libs/libsecp256k1.a ../libsecp256k1.a

popd
