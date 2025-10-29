#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <dlfcn.h>
#include <secp256k1.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#define N_SIGNATURES 5000

struct sig_verify_data {
    unsigned char sig_buf[128];
    size_t sig_len;
    unsigned char msghash[32];
    //unsigned char pubkey[33];
    unsigned char pubkey[65];
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

void perform_benchmark_openssl(const char* so_file)
{
    void* handle;
    EC_KEY* (*dyn_EC_KEY_new_by_curve_name)(int);
    void    (*dyn_EC_KEY_free)(EC_KEY*);
    EC_KEY* (*dyn_o2i_ECPublicKey)(EC_KEY**, const unsigned char**, long);
    int 	(*dyn_ECDSA_verify)(int, const unsigned char*, int, const unsigned char*, int, EC_KEY*);

    struct timespec start, end;
    int i, ret;
    double elapsed_ns;

    handle = dlopen(so_file, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    dyn_EC_KEY_new_by_curve_name = load_symbol(handle, "EC_KEY_new_by_curve_name");
    dyn_EC_KEY_free = load_symbol(handle, "EC_KEY_free");
    dyn_o2i_ECPublicKey = load_symbol(handle, "o2i_ECPublicKey");
    dyn_ECDSA_verify = load_symbol(handle, "ECDSA_verify");

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (i = 0; i < N_SIGNATURES; i++) {
        printf("i == %d\n", i);
        EC_KEY* ec_key = dyn_EC_KEY_new_by_curve_name(NID_secp256k1);
        unsigned char* m = (unsigned char*)ec_key;
        printf("we have an ec_key: %p (first few bytes at this addr: %x %x %x %x %x %x %x %x %x %x %x %x)\n", ec_key,
                m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11]);
        const unsigned char* pubkey_bytes_begin = &sigs[i].pubkey[0];
        EC_KEY* pk_ret = dyn_o2i_ECPublicKey(&ec_key, &pubkey_bytes_begin, sizeof(sigs[i].pubkey));
        assert(pk_ret);
        ret = dyn_ECDSA_verify(0, sigs[i].msghash, sizeof(sigs[i].msghash), sigs[i].sig_buf, sigs[i].sig_len, ec_key);
        assert(ret == 1); /* 1 == good */
        dyn_EC_KEY_free(ec_key);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_ns = (end.tv_sec - start.tv_sec)*1e9 + (end.tv_nsec - start.tv_nsec);
    printf("Verifying %d ECDSA signatures using \"%s\" took %.2f ms\n", N_SIGNATURES, so_file, elapsed_ns/1000000);

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
        size_t pubkey_len = sizeof(sigs[i].pubkey);
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
        ret = secp256k1_ec_pubkey_serialize(secp256k1_context_static, sigs[i].pubkey, &pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        assert(ret && pubkey_len == sizeof(sigs[i].pubkey));
    }
    secp256k1_context_destroy(ctx);

    perform_benchmark_openssl("./openssl-0_9_8h.so");

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
