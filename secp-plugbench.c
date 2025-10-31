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
/* parameter passed to clock_gettime(...) for elapsed time measurement */
#define PLUGBENCH_CLOCK_ID CLOCK_PROCESS_CPUTIME_ID

struct sig_verify_data {
    unsigned char sig_buf[128];
    size_t sig_len;
    unsigned char msghash[32];
    unsigned char pubkey[33];
} sigs[N_SIGNATURES];

unsigned long seed = 313372342;
FILE *csv_file = NULL;

void* load_symbol(void* handle, const char* symbol)
{
    void* symbol_result = dlsym(handle, symbol);
    if (!symbol_result) {
        fprintf(stderr, "dlsym error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    return symbol_result;
}

void perform_benchmark_libsecp(const char* so_file, const char* version_desc)
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

    clock_gettime(PLUGBENCH_CLOCK_ID, &start);

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

    clock_gettime(PLUGBENCH_CLOCK_ID, &end);
    elapsed_ns = (end.tv_sec - start.tv_sec)*1e9 + (end.tv_nsec - start.tv_nsec);
    printf("secp256k1 version %s: %.3f ms\n", version_desc, elapsed_ns/1000000);
    char plot_label[64] = {0};
    size_t plot_label_len = strlen(so_file)-20-5; /* TODO: this is very ugly, fix it */
    memcpy(plot_label, so_file+20, plot_label_len);
    if (csv_file) fprintf(csv_file, "bc-%s,%.3f\n", plot_label, elapsed_ns/1000000);

    dyn_secp256k1_context_destroy(ctx);
    dlclose(handle);
}

void perform_benchmark_openssl(const char* so_file, const char* version_desc)
{
    void* handle;
    EC_GROUP* (*dyn_EC_GROUP_new_by_curve_name)(int);
    int       (*dyn_EC_GROUP_precompute_mult)(EC_GROUP*, BN_CTX*);
    int       (*dyn_EC_GROUP_have_precompute_mult)(const EC_GROUP*);
    void      (*dyn_EC_GROUP_free)(EC_GROUP*);
    EC_KEY*   (*dyn_EC_KEY_new)(void);
    int       (*dyn_EC_KEY_set_group)(EC_KEY*, const EC_GROUP*);
    void      (*dyn_EC_KEY_free)(EC_KEY*);
    EC_KEY*   (*dyn_o2i_ECPublicKey)(EC_KEY**, const unsigned char**, long);
    int       (*dyn_ECDSA_verify)(int, const unsigned char*, int, const unsigned char*, int, EC_KEY*);

    struct timespec start, end;
    int i, ret;
    double elapsed_ns;

    handle = dlopen(so_file, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    dyn_EC_GROUP_new_by_curve_name = load_symbol(handle, "EC_GROUP_new_by_curve_name");
    dyn_EC_GROUP_precompute_mult = load_symbol(handle, "EC_GROUP_precompute_mult");
    dyn_EC_GROUP_have_precompute_mult = load_symbol(handle, "EC_GROUP_have_precompute_mult");
    dyn_EC_GROUP_free = load_symbol(handle, "EC_GROUP_free");
    dyn_EC_KEY_new = load_symbol(handle, "EC_KEY_new");
    dyn_EC_KEY_set_group = load_symbol(handle, "EC_KEY_set_group");
    dyn_EC_KEY_free = load_symbol(handle, "EC_KEY_free");
    dyn_o2i_ECPublicKey = load_symbol(handle, "o2i_ECPublicKey");
    dyn_ECDSA_verify = load_symbol(handle, "ECDSA_verify");

    EC_GROUP* group = dyn_EC_GROUP_new_by_curve_name(NID_secp256k1);
    assert(group);
    ret = dyn_EC_GROUP_precompute_mult(group, NULL);
    assert(ret);
    ret = dyn_EC_GROUP_have_precompute_mult(group);
    assert(ret); /* ensure precomputation table is used (for fair comparison) */
    EC_KEY *key = dyn_EC_KEY_new();
    assert(key);
    dyn_EC_KEY_set_group(key, group);
    clock_gettime(PLUGBENCH_CLOCK_ID, &start);

    for (i = 0; i < N_SIGNATURES; i++) {
        const unsigned char* pubkey_bytes_begin = &sigs[i].pubkey[0];
        EC_KEY* pk_ret = dyn_o2i_ECPublicKey(&key, &pubkey_bytes_begin, sizeof(sigs[i].pubkey));
        assert(pk_ret);
        ret = dyn_ECDSA_verify(0, sigs[i].msghash, sizeof(sigs[i].msghash), sigs[i].sig_buf, sigs[i].sig_len, key);
        assert(ret == 1); /* 1 == good */
    }

    clock_gettime(PLUGBENCH_CLOCK_ID, &end);
    elapsed_ns = (end.tv_sec - start.tv_sec)*1e9 + (end.tv_nsec - start.tv_nsec);
    printf("OpenSSL version %s: %.3f ms\n", version_desc, elapsed_ns/1000000);
    char plot_label[64] = {0};
    size_t plot_label_len = strlen(so_file)-10-3; /* TODO: this is very ugly, fix it */
    memcpy(plot_label, so_file+10, plot_label_len);
    if (csv_file) fprintf(csv_file, "os-%s,%.3f\n", plot_label, elapsed_ns/1000000);

    dyn_EC_KEY_free(key);
    dyn_EC_GROUP_free(group);
    dlclose(handle);
}

int main(int argc, char **argv)
{
    /* write benchmarks to a .csv file, if a parameter is provided */
    if (argc == 2) {
        csv_file = fopen(argv[1], "w");
        if (!csv_file) {
            fprintf(stderr, "Couldn't open file \"%s\" for writing.\n", argv[1]);
            return EXIT_FAILURE;
        }
        fprintf(csv_file, "version,runtime\n");
    }

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
        ret = secp256k1_ec_pubkey_serialize(secp256k1_context_static, sigs[i].pubkey, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);
        assert(ret && pubkey_len == sizeof(sigs[i].pubkey));
    }
    secp256k1_context_destroy(ctx);

    printf("Benchmark scenario: verify %d ECDSA signatures (DER format) with compressed public keys\n\n", N_SIGNATURES);

    printf("===== OpenSSL =====\n");
    /* TODO: versions 0.9.8h and 1.0.0 crash on my arm64 machine, so skip them */
#ifndef __aarch64__
    perform_benchmark_openssl("./openssl-0_9_8h.so", "0.9.8h");
    perform_benchmark_openssl("./openssl-1_0_0.so",  "1.0.0");
#endif
    //perform_benchmark_openssl("./openssl-1_1_0.so",  "1.1.0");
    perform_benchmark_openssl("./openssl-1_1_1.so",  "1.1.1");
    perform_benchmark_openssl("./openssl-3_0_0.so",  "3.0.0");
    perform_benchmark_openssl("./openssl-3_1_0.so",  "3.1.0");
    perform_benchmark_openssl("./openssl-3_3_0.so",  "3.3.0");
    perform_benchmark_openssl("./openssl-3_5_0.so",  "3.5.0");

    printf("\n");
    printf("===== libsecp256k1 =====\n");
    perform_benchmark_libsecp("./libsecp256k1-core-v0_12_0.so", "used in Bitcoin Core v0.12");
    perform_benchmark_libsecp("./libsecp256k1-core-v0_14_0.so", "used in Bitcoin Core v0.14");
    perform_benchmark_libsecp("./libsecp256k1-core-v0_15_0.so", "used in Bitcoin Core v0.15");
    perform_benchmark_libsecp("./libsecp256k1-core-v0_16_0.so", "used in Bitcoin Core v0.16");
    perform_benchmark_libsecp("./libsecp256k1-core-v0_19_0.so", "used in Bitcoin Core v0.19");
    perform_benchmark_libsecp("./libsecp256k1-core-v0_20_0.so", "used in Bitcoin Core v0.20");
    perform_benchmark_libsecp("./libsecp256k1-core-v22_0.so",   "used in Bitcoin Core v22.0");
    perform_benchmark_libsecp("./libsecp256k1-core-v23_0.so",   "used in Bitcoin Core v23.0");
    perform_benchmark_libsecp("./libsecp256k1-core-v24_0.so",   "used in Bitcoin Core v24.0");
    perform_benchmark_libsecp("./libsecp256k1-core-v25_0.so",   "used in Bitcoin Core v25.0");
    perform_benchmark_libsecp("./libsecp256k1-core-v26_0.so",   "used in Bitcoin Core v26.0");
    perform_benchmark_libsecp("./libsecp256k1-core-v27_0.so",   "used in Bitcoin Core v27.0");
    perform_benchmark_libsecp("./libsecp256k1-core-v28_0.so",   "used in Bitcoin Core v28.0");
    perform_benchmark_libsecp("./libsecp256k1-core-v29_0.so",   "used in Bitcoin Core v29.0");
    perform_benchmark_libsecp("./libsecp256k1-core-v30_0.so",   "used in Bitcoin Core v30.0");

    if (csv_file) fclose(csv_file);
    return EXIT_SUCCESS;
}
