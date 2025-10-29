#!/usr/bin/env bash
cc -o secp-plugbench secp-plugbench.c -I ./secp256k1/include -L . -lsecp256k1
