secp-plugbench: secp-plugbench.c
	cc -o secp-plugbench secp-plugbench.c -I ./secp256k1/include -L . -lsecp256k1

.PHONY: clean
clean:
	rm -rf secp-plugbench secp256k1/ openssl/ *.so *.a
