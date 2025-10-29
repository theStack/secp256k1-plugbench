#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <dlfcn.h>
#include <secp256k1.h>

#define N_SIGNATURES 5000

struct sig_verify_data {
    unsigned char sig_buf[128];
    size_t sig_len;
    unsigned char msghash[32];
    unsigned char pubkey[33];
} sigs[N_SIGNATURES];

unsigned long seed = 313372342;

void* load_symbol(void* handle, const char* symbol)
{
    void* symbol_result = dlsym(handle, symbol);
    if (!symbol_result) {
        fprintf(stderr, "dlsym error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    return symbol_result;
}

void perform_benchmark_libsecp(const char* so_file)
{
    void* handle;
    secp256k1_context* (*dyn_secp256k1_context_create)(unsigned int);
    void (*dyn_secp256k1_context_destroy)(secp256k1_context*);
    int (*dyn_secp256k1_ec_pubkey_parse)(const secp256k1_context*, secp256k1_pubkey*, const unsigned char*, size_t);
    int (*dyn_secp256k1_ecdsa_signature_parse_der)(const secp256k1_context*, secp256k1_ecdsa_signature*, const unsigned char*, size_t);
    int (*dyn_secp256k1_ecdsa_signature_normalize)(const secp256k1_context*, secp256k1_ecdsa_signature*, const secp256k1_ecdsa_signature*);
    int (*dyn_secp256k1_ecdsa_verify)(const secp256k1_context*, const secp256k1_ecdsa_signature*,
            const unsigned char*, const secp256k1_pubkey*);
    struct timespec start, end;
    int i, ret;
    double elapsed_ns;
    secp256k1_context *ctx;

    handle = dlopen(so_file, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    dyn_secp256k1_context_create = load_symbol(handle, "secp256k1_context_create");
    dyn_secp256k1_context_destroy = load_symbol(handle, "secp256k1_context_destroy");
    dyn_secp256k1_ec_pubkey_parse = load_symbol(handle, "secp256k1_ec_pubkey_parse");
    dyn_secp256k1_ecdsa_signature_parse_der = load_symbol(handle, "secp256k1_ecdsa_signature_parse_der");
    dyn_secp256k1_ecdsa_signature_normalize = load_symbol(handle, "secp256k1_ecdsa_signature_normalize");
    dyn_secp256k1_ecdsa_verify = load_symbol(handle, "secp256k1_ecdsa_verify");
    ctx = dyn_secp256k1_context_create((1 << 0) | (1 << 8)); /* matches SECP256K1_CONTEXT_VERIFY */
    assert(ctx);

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (i = 0; i < N_SIGNATURES; i++) {
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig;

        ret = dyn_secp256k1_ec_pubkey_parse(ctx, &pubkey, sigs[i].pubkey, sizeof(sigs[i].pubkey));
        assert(ret);
        ret = dyn_secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigs[i].sig_buf, sigs[i].sig_len);
        assert(ret);
        ret = dyn_secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
        assert(ret == 0); /* returns 0 if signature was already normalized; always the case since we create them with libsecp256k1 */
        ret = dyn_secp256k1_ecdsa_verify(ctx, &sig, sigs[i].msghash, &pubkey);
        assert(ret);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_ns = (end.tv_sec - start.tv_sec)*1e9 + (end.tv_nsec - start.tv_nsec);
    printf("Verifying %d ECDSA signatures using \"%s\" took %.2f ms\n", N_SIGNATURES, so_file, elapsed_ns/1000000);

    dyn_secp256k1_context_destroy(ctx);
    dlclose(handle);
}

int main()
{
    /* derive pseudo-random keys and messages from seed and create signatures */
    int i, ret;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    for (i = 0; i < N_SIGNATURES; i++) {
        unsigned char seckey[32];
        secp256k1_pubkey pubkey;
        size_t pubkey_len = 33;
        secp256k1_ecdsa_signature sig;
        unsigned char msghash[32];
        unsigned char seedbuf[4];

        seedbuf[0] = seed >> 24;
        seedbuf[1] = seed >> 16;
        seedbuf[2] = seed >> 8;
        seedbuf[3] = seed;
        ret = secp256k1_tagged_sha256(secp256k1_context_static, seckey, "seckey", 6, seedbuf, sizeof(seedbuf));
        assert(ret);
        ret = secp256k1_tagged_sha256(secp256k1_context_static, msghash, "msghash", 7, seedbuf, sizeof(seedbuf));
        assert(ret);
        ret = secp256k1_ecdsa_sign(ctx, &sig, msghash, seckey, NULL, NULL);
        assert(ret);
        ret = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
        assert(ret);

        /* store everything in serialized form */
        sigs[i].sig_len = 100;
        ret = secp256k1_ecdsa_signature_serialize_der(secp256k1_context_static, sigs[i].sig_buf, &sigs[i].sig_len, &sig);
        assert(ret);
        memcpy(sigs[i].msghash, msghash, 32);
        ret = secp256k1_ec_pubkey_serialize(secp256k1_context_static, sigs[i].pubkey, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);
        assert(ret && pubkey_len == 33);
    }
    secp256k1_context_destroy(ctx);

    perform_benchmark_libsecp("./libsecp256k1-core-v0_12_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v0_14_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v0_15_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v0_16_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v0_19_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v0_20_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v22_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v23_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v24_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v25_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v26_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v27_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v28_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v29_0.so");
    perform_benchmark_libsecp("./libsecp256k1-core-v30_0.so");

    return EXIT_SUCCESS;
}
