#define _POSIX_C_SOURCE 200809L

#include "composite_key.h"
#include "composite_sig.h"
#include "dilithium_wrapper.h"
#include "sm2_wrapper.h"

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>

#ifndef HYBRID_BENCH_BUILD_TYPE
#define HYBRID_BENCH_BUILD_TYPE "unspecified"
#endif

#define BENCHMARK_MESSAGE_BYTES 1024u
#define DEFAULT_WARMUP_ITERATIONS 1000u
#define DEFAULT_TIMED_ITERATIONS 10000u
#define COMPOSITE_REQUIREMENT_MS 50.0

typedef int (*verify_function)(void *argument);

typedef struct {
    const char *algorithm;
    size_t count;
    double mean_ms;
    double median_ms;
    double p95_ms;
    double p99_ms;
    double min_ms;
    double max_ms;
} BENCHMARK_RESULT;

typedef struct {
    EVP_PKEY *key;
    const uint8_t *message;
    size_t message_len;
    const uint8_t *signature;
    size_t signature_len;
} EVP_VERIFY_INPUT;

typedef struct {
    const uint8_t *public_key;
    size_t public_key_len;
    const uint8_t *message;
    size_t message_len;
    const uint8_t *signature;
    size_t signature_len;
} DILITHIUM_VERIFY_INPUT;

typedef struct {
    const HYBRID_PUBLIC_KEY *public_key;
    const uint8_t *message;
    size_t message_len;
    const uint8_t *signature;
    size_t signature_len;
} COMPOSITE_VERIFY_INPUT;

static volatile unsigned int verify_sink;

static void usage(const char *program)
{
    fprintf(stderr,
            "usage: %s [--warmup N] [--iterations N] [--csv PATH]\n",
            program);
}

static int parse_count(const char *text, size_t *value)
{
    char *end = NULL;
    uintmax_t parsed;

    if (text == NULL || value == NULL || text[0] == '\0' || text[0] == '-') {
        return 0;
    }
    errno = 0;
    parsed = strtoumax(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > SIZE_MAX) {
        return 0;
    }
    *value = (size_t)parsed;
    return 1;
}

static uint64_t now_ns(void)
{
    struct timespec timestamp;
#ifdef CLOCK_MONOTONIC_RAW
    const clockid_t clock_id = CLOCK_MONOTONIC_RAW;
#else
    const clockid_t clock_id = CLOCK_MONOTONIC;
#endif

    if (clock_gettime(clock_id, &timestamp) != 0 || timestamp.tv_sec < 0 ||
        timestamp.tv_nsec < 0) {
        return UINT64_MAX;
    }
    return (uint64_t)timestamp.tv_sec * UINT64_C(1000000000) +
           (uint64_t)timestamp.tv_nsec;
}

static int compare_u64(const void *left, const void *right)
{
    const uint64_t a = *(const uint64_t *)left;
    const uint64_t b = *(const uint64_t *)right;

    return (a > b) - (a < b);
}

static double ns_to_ms(long double nanoseconds)
{
    return (double)(nanoseconds / 1000000.0L);
}

static uint64_t nearest_rank(const uint64_t *sorted, size_t count,
                             size_t numerator, size_t denominator)
{
    size_t rank;

    rank = count / denominator * numerator;
    if (count % denominator != 0) {
        rank += (count % denominator * numerator + denominator - 1u) /
                denominator;
    }
    if (rank == 0) {
        rank = 1;
    }
    return sorted[rank - 1u];
}

static int run_benchmark(const char *algorithm, verify_function verify,
                         void *argument, size_t warmup_iterations,
                         size_t iterations, BENCHMARK_RESULT *result)
{
    uint64_t *samples = NULL;
    long double total_ns = 0.0L;
    uint64_t start;
    uint64_t stop;
    uint64_t median_ns;
    size_t i;
    int verified;

    if (algorithm == NULL || verify == NULL || result == NULL ||
        iterations == 0 || iterations > SIZE_MAX / sizeof(*samples)) {
        return 0;
    }
    samples = malloc(iterations * sizeof(*samples));
    if (samples == NULL) {
        fprintf(stderr, "FAIL: unable to allocate samples for %s\n", algorithm);
        return 0;
    }

    for (i = 0; i < warmup_iterations; i++) {
        verified = verify(argument);
        verify_sink ^= (unsigned int)verified;
        if (verified != 1) {
            fprintf(stderr, "FAIL: %s warm-up verification %zu failed\n",
                    algorithm, i + 1u);
            free(samples);
            return 0;
        }
    }

    for (i = 0; i < iterations; i++) {
        start = now_ns();
        verified = verify(argument);
        stop = now_ns();
        verify_sink ^= (unsigned int)verified;
        if (start == UINT64_MAX || stop == UINT64_MAX || stop < start) {
            fprintf(stderr, "FAIL: monotonic clock failed for %s\n", algorithm);
            free(samples);
            return 0;
        }
        if (verified != 1) {
            fprintf(stderr, "FAIL: %s timed verification %zu failed\n",
                    algorithm, i + 1u);
            free(samples);
            return 0;
        }
        samples[i] = stop - start;
        total_ns += (long double)samples[i];
    }

    qsort(samples, iterations, sizeof(*samples), compare_u64);
    if ((iterations & 1u) != 0) {
        median_ns = samples[iterations / 2u];
    } else {
        median_ns = samples[iterations / 2u - 1u] / 2u +
                    samples[iterations / 2u] / 2u +
                    ((samples[iterations / 2u - 1u] & 1u) +
                     (samples[iterations / 2u] & 1u)) /
                        2u;
    }

    result->algorithm = algorithm;
    result->count = iterations;
    result->mean_ms = ns_to_ms(total_ns / (long double)iterations);
    result->median_ms = ns_to_ms((long double)median_ns);
    result->p95_ms = ns_to_ms((long double)nearest_rank(samples, iterations,
                                                        95u, 100u));
    result->p99_ms = ns_to_ms((long double)nearest_rank(samples, iterations,
                                                        99u, 100u));
    result->min_ms = ns_to_ms((long double)samples[0]);
    result->max_ms = ns_to_ms((long double)samples[iterations - 1u]);
    free(samples);
    return 1;
}

static EVP_PKEY *generate_ecdsa_p256_key(void)
{
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;

    context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_CTX_set_group_name(context, "prime256v1") <= 0 ||
        EVP_PKEY_generate(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static int ecdsa_p256_sha256_sign(EVP_PKEY *key, const uint8_t *message,
                                  size_t message_len, uint8_t **signature,
                                  size_t *signature_len)
{
    EVP_MD_CTX *context = NULL;
    uint8_t *output = NULL;
    size_t output_len = 0;
    int ok = 0;

    if (key == NULL || message == NULL || signature == NULL ||
        signature_len == NULL) {
        return 0;
    }
    *signature = NULL;
    *signature_len = 0;
    context = EVP_MD_CTX_new();
    if (context == NULL ||
        EVP_DigestSignInit_ex(context, NULL, "SHA256", NULL, NULL, key, NULL) <=
            0 ||
        EVP_DigestSign(context, NULL, &output_len, message, message_len) <= 0) {
        goto done;
    }
    output = OPENSSL_malloc(output_len);
    if (output == NULL ||
        EVP_DigestSign(context, output, &output_len, message, message_len) <= 0) {
        goto done;
    }
    *signature = output;
    *signature_len = output_len;
    output = NULL;
    ok = 1;

done:
    OPENSSL_free(output);
    EVP_MD_CTX_free(context);
    return ok;
}

static int ecdsa_p256_sha256_verify(void *argument)
{
    const EVP_VERIFY_INPUT *input = argument;
    EVP_MD_CTX *context = NULL;
    int verified = 0;

    context = EVP_MD_CTX_new();
    if (context == NULL ||
        EVP_DigestVerifyInit_ex(context, NULL, "SHA256", NULL, NULL,
                                input->key, NULL) <= 0) {
        goto done;
    }
    verified = EVP_DigestVerify(context, input->signature,
                                input->signature_len, input->message,
                                input->message_len) == 1;

done:
    EVP_MD_CTX_free(context);
    return verified;
}

static int sm2_verify(void *argument)
{
    const EVP_VERIFY_INPUT *input = argument;

    return hybrid_sm2_verify(input->key, input->message, input->message_len,
                             input->signature, input->signature_len);
}

static int dilithium2_verify(void *argument)
{
    const DILITHIUM_VERIFY_INPUT *input = argument;

    return dilithium_verify(input->public_key, input->public_key_len,
                            input->message, input->message_len,
                            input->signature, input->signature_len);
}

static int composite_signature_verify(void *argument)
{
    const COMPOSITE_VERIFY_INPUT *input = argument;

    return composite_verify(input->public_key, input->message,
                            input->message_len, NULL, 0, input->signature,
                            input->signature_len);
}

static const char *compiler_name(void)
{
#if defined(__clang__)
    return "Clang " __clang_version__;
#elif defined(__GNUC__)
    return "GCC " __VERSION__;
#else
    return "unknown";
#endif
}

static void read_cpu_model(char *output, size_t output_size)
{
    FILE *stream = NULL;
    char line[512];

    if (output == NULL || output_size == 0) {
        return;
    }
    snprintf(output, output_size, "unavailable (record with lscpu)");
    stream = fopen("/proc/cpuinfo", "r");
    if (stream == NULL) {
        return;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        char *colon;
        char *value;
        size_t length;

        if (strncmp(line, "model name", strlen("model name")) != 0) {
            continue;
        }
        colon = strchr(line, ':');
        if (colon == NULL) {
            continue;
        }
        value = colon + 1;
        while (*value == ' ' || *value == '\t') {
            value++;
        }
        length = strcspn(value, "\r\n");
        value[length] = '\0';
        snprintf(output, output_size, "%s", value);
        break;
    }
    fclose(stream);
}

static void print_results(const BENCHMARK_RESULT *results, size_t result_count,
                          size_t warmup_iterations, const char *cpu,
                          const struct utsname *system)
{
    double baseline = results[0].mean_ms;
    double ratio = results[3].mean_ms / baseline;
    double overhead = results[3].mean_ms - results[0].mean_ms;
    double framework_overhead = results[3].mean_ms - results[1].mean_ms -
                                results[2].mean_ms;
    size_t i;

    puts("============================================================");
    puts("Composite Signature Verification Benchmark");
    puts("============================================================");
    puts("Platform:");
    printf("  CPU: %s\n", cpu);
    printf("  OS: %s %s\n", system->sysname, system->release);
    printf("  Architecture: %s\n", system->machine);
    printf("  Compiler: %s\n", compiler_name());
    printf("  Build: %s\n", HYBRID_BENCH_BUILD_TYPE);
    printf("  OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("  Dilithium parameter set: %s (DILITHIUM_MODE=2)\n",
           dilithium_algorithm_name());
    printf("  Message: %u bytes\n", BENCHMARK_MESSAGE_BYTES);
    printf("  Warm-up iterations: %zu\n", warmup_iterations);
    printf("  Timed iterations: %zu\n\n", results[0].count);
    printf("%-30s %10s %10s %10s %10s %10s %10s %10s\n", "Algorithm",
           "Count", "Mean", "P50", "P95", "P99", "Min", "Max");
    puts("----------------------------------------------------------------------------------------------------------");
    for (i = 0; i < result_count; i++) {
        printf("%-30s %10zu %8.3f ms %8.3f ms %8.3f ms %8.3f ms %8.3f ms %8.3f ms\n",
               results[i].algorithm, results[i].count, results[i].mean_ms,
               results[i].median_ms, results[i].p95_ms, results[i].p99_ms,
               results[i].min_ms, results[i].max_ms);
    }
    printf("\nComposite / P-256: %.2fx\n", ratio);
    printf("Composite - P-256 overhead: %.3f ms\n", overhead);
    printf("Approximate Composite framework overhead: %.3f ms\n",
           framework_overhead);
    puts("  (Composite - SM2 - Dilithium2; approximate comparison only)");
    printf("\nRequirement:\n  Composite verify mean < %.3f ms\n",
           COMPOSITE_REQUIREMENT_MS);
    printf("\nResult:\n  %s\n",
           results[3].mean_ms < COMPOSITE_REQUIREMENT_MS ? "PASS" : "FAIL");
    puts("============================================================");
}

static int write_csv(const char *path, const BENCHMARK_RESULT *results,
                     size_t result_count)
{
    FILE *stream;
    double baseline = results[0].mean_ms;
    size_t i;

    stream = fopen(path, "w");
    if (stream == NULL) {
        fprintf(stderr, "FAIL: cannot open CSV %s: %s\n", path,
                strerror(errno));
        return 0;
    }
    if (fprintf(stream,
                "algorithm,iterations,mean_ms,median_ms,p95_ms,p99_ms,min_ms,"
                "max_ms,baseline_ratio\n") < 0) {
        fclose(stream);
        return 0;
    }
    for (i = 0; i < result_count; i++) {
        if (fprintf(stream, "%s,%zu,%.9f,%.9f,%.9f,%.9f,%.9f,%.9f,%.9f\n",
                    results[i].algorithm, results[i].count,
                    results[i].mean_ms, results[i].median_ms,
                    results[i].p95_ms, results[i].p99_ms, results[i].min_ms,
                    results[i].max_ms, results[i].mean_ms / baseline) < 0) {
            fclose(stream);
            return 0;
        }
    }
    if (fclose(stream) != 0) {
        fprintf(stderr, "FAIL: cannot finish CSV %s\n", path);
        return 0;
    }
    return 1;
}

static char *markdown_path_for_csv(const char *csv_path)
{
    size_t length = strlen(csv_path);
    char *path;

    if (length > SIZE_MAX - 4u) {
        return NULL;
    }
    path = malloc(length + 4u);
    if (path == NULL) {
        return NULL;
    }
    memcpy(path, csv_path, length + 1u);
    if (length >= 4u && strcmp(path + length - 4u, ".csv") == 0) {
        memcpy(path + length - 4u, ".md", 4u);
    } else {
        memcpy(path + length, ".md", 4u);
    }
    return path;
}

static int write_markdown(const char *path, const BENCHMARK_RESULT *results,
                          size_t result_count, size_t warmup_iterations,
                          const char *cpu, const struct utsname *system)
{
    FILE *stream;
    double baseline = results[0].mean_ms;
    size_t i;

    stream = fopen(path, "w");
    if (stream == NULL) {
        fprintf(stderr, "FAIL: cannot open Markdown summary %s: %s\n", path,
                strerror(errno));
        return 0;
    }
    fprintf(stream, "# Composite Verification Benchmark\n\n");
    fprintf(stream, "- CPU: %s\n", cpu);
    fprintf(stream, "- OS: %s %s (%s)\n", system->sysname, system->release,
            system->machine);
    fprintf(stream, "- Compiler: %s\n", compiler_name());
    fprintf(stream, "- Build type: %s\n", HYBRID_BENCH_BUILD_TYPE);
    fprintf(stream, "- OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));
    fprintf(stream, "- Message size: %u bytes\n", BENCHMARK_MESSAGE_BYTES);
    fprintf(stream, "- Warm-up iterations: %zu\n", warmup_iterations);
    fprintf(stream, "- Timed iterations: %zu\n\n", results[0].count);
    fprintf(stream,
            "| Algorithm | Count | Mean (ms) | P50 (ms) | P95 (ms) | P99 "
            "(ms) | Min (ms) | Max (ms) | Relative to P-256 |\n");
    fprintf(stream,
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for (i = 0; i < result_count; i++) {
        fprintf(stream,
                "| %s | %zu | %.6f | %.6f | %.6f | %.6f | %.6f | %.6f | "
                "%.3fx |\n",
                results[i].algorithm, results[i].count, results[i].mean_ms,
                results[i].median_ms, results[i].p95_ms, results[i].p99_ms,
                results[i].min_ms, results[i].max_ms,
                results[i].mean_ms / baseline);
    }
    fprintf(stream,
            "\nRequirement: Composite verify mean < %.3f ms\n\nResult: "
            "**%s**\n\n",
            COMPOSITE_REQUIREMENT_MS,
            results[3].mean_ms < COMPOSITE_REQUIREMENT_MS ? "PASS" : "FAIL");
    fprintf(stream,
            "ECDSA-P256-SHA256 is the performance baseline only. The primary "
            "metric is the public `composite_verify()` call.\n");
    if (fclose(stream) != 0) {
        fprintf(stderr, "FAIL: cannot finish Markdown summary %s\n", path);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    size_t warmup_iterations = DEFAULT_WARMUP_ITERATIONS;
    size_t iterations = DEFAULT_TIMED_ITERATIONS;
    const char *csv_path = NULL;
    char *markdown_path = NULL;
    uint8_t message[BENCHMARK_MESSAGE_BYTES];
    HYBRID_PRIVATE_KEY private_key;
    HYBRID_PUBLIC_KEY public_key;
    EVP_PKEY *ecdsa_key = NULL;
    uint8_t *ecdsa_signature = NULL;
    size_t ecdsa_signature_len = 0;
    uint8_t *sm2_signature = NULL;
    size_t sm2_signature_len = 0;
    uint8_t *dilithium_signature = NULL;
    size_t dilithium_signature_len = 0;
    uint8_t *composite_signature = NULL;
    size_t composite_signature_len = 0;
    EVP_VERIFY_INPUT ecdsa_input;
    EVP_VERIFY_INPUT sm2_input;
    DILITHIUM_VERIFY_INPUT dilithium_input;
    COMPOSITE_VERIFY_INPUT composite_input;
    BENCHMARK_RESULT results[4];
    struct utsname system;
    char cpu[256];
    size_t i;
    int argument_index;
    int status = EXIT_FAILURE;

    hybrid_private_key_init(&private_key);
    hybrid_public_key_init(&public_key);
    for (argument_index = 1; argument_index < argc; argument_index++) {
        if (strcmp(argv[argument_index], "--warmup") == 0 &&
            argument_index + 1 < argc) {
            if (!parse_count(argv[++argument_index], &warmup_iterations)) {
                usage(argv[0]);
                goto done;
            }
        } else if (strcmp(argv[argument_index], "--iterations") == 0 &&
                   argument_index + 1 < argc) {
            if (!parse_count(argv[++argument_index], &iterations) ||
                iterations == 0) {
                usage(argv[0]);
                goto done;
            }
        } else if (strcmp(argv[argument_index], "--csv") == 0 &&
                   argument_index + 1 < argc) {
            csv_path = argv[++argument_index];
            if (csv_path[0] == '\0') {
                usage(argv[0]);
                goto done;
            }
        } else {
            usage(argv[0]);
            goto done;
        }
    }

    for (i = 0; i < sizeof(message); i++) {
        message[i] = (uint8_t)(i & 0xffu);
    }

    /* Setup is deliberately outside all timed regions. */
    ecdsa_key = generate_ecdsa_p256_key();
    if (ecdsa_key == NULL ||
        !ecdsa_p256_sha256_sign(ecdsa_key, message, sizeof(message),
                                &ecdsa_signature, &ecdsa_signature_len) ||
        !composite_key_generate(&private_key, &public_key) ||
        !hybrid_sm2_sign(private_key.sm2_private_key, message, sizeof(message),
                         &sm2_signature, &sm2_signature_len) ||
        !dilithium_sign(private_key.dilithium_secret_key,
                        sizeof(private_key.dilithium_secret_key), message,
                        sizeof(message), &dilithium_signature,
                        &dilithium_signature_len) ||
        !composite_sign(&private_key, message, sizeof(message), NULL, 0,
                        &composite_signature, &composite_signature_len)) {
        fputs("FAIL: benchmark setup failed\n", stderr);
        ERR_print_errors_fp(stderr);
        goto done;
    }

    ecdsa_input = (EVP_VERIFY_INPUT){ecdsa_key, message, sizeof(message),
                                     ecdsa_signature, ecdsa_signature_len};
    sm2_input = (EVP_VERIFY_INPUT){public_key.sm2_public_key, message,
                                  sizeof(message), sm2_signature,
                                  sm2_signature_len};
    dilithium_input = (DILITHIUM_VERIFY_INPUT){
        public_key.dilithium_public_key, sizeof(public_key.dilithium_public_key),
        message, sizeof(message), dilithium_signature,
        dilithium_signature_len};
    composite_input = (COMPOSITE_VERIFY_INPUT){
        &public_key, message, sizeof(message), composite_signature,
        composite_signature_len};

    /* Force provider/library initialization before even the warm-up phase. */
    if (!ecdsa_p256_sha256_verify(&ecdsa_input) || !sm2_verify(&sm2_input) ||
        !dilithium2_verify(&dilithium_input) ||
        !composite_signature_verify(&composite_input)) {
        fputs("FAIL: setup verification failed\n", stderr);
        goto done;
    }

    if (!run_benchmark("ECDSA-P256-SHA256", ecdsa_p256_sha256_verify,
                       &ecdsa_input, warmup_iterations, iterations,
                       &results[0]) ||
        !run_benchmark("SM2-SM3", sm2_verify, &sm2_input, warmup_iterations,
                       iterations, &results[1]) ||
        !run_benchmark("CRYSTALS-Dilithium2", dilithium2_verify,
                       &dilithium_input, warmup_iterations, iterations,
                       &results[2]) ||
        !run_benchmark("SM2+Dilithium2 Composite", composite_signature_verify,
                       &composite_input, warmup_iterations, iterations,
                       &results[3])) {
        goto done;
    }

    if (uname(&system) != 0) {
        memset(&system, 0, sizeof(system));
        snprintf(system.sysname, sizeof(system.sysname), "unavailable");
        snprintf(system.release, sizeof(system.release), "unavailable");
        snprintf(system.machine, sizeof(system.machine), "unavailable");
    }
    read_cpu_model(cpu, sizeof(cpu));
    print_results(results, sizeof(results) / sizeof(results[0]),
                  warmup_iterations, cpu, &system);

    if (csv_path != NULL) {
        markdown_path = markdown_path_for_csv(csv_path);
        if (markdown_path == NULL ||
            !write_csv(csv_path, results,
                       sizeof(results) / sizeof(results[0])) ||
            !write_markdown(markdown_path, results,
                            sizeof(results) / sizeof(results[0]),
                            warmup_iterations, cpu, &system)) {
            goto done;
        }
        printf("CSV: %s\n", csv_path);
        printf("Markdown: %s\n", markdown_path);
    }
    status = EXIT_SUCCESS;

done:
    free(markdown_path);
    OPENSSL_free(composite_signature);
    free(dilithium_signature);
    OPENSSL_free(sm2_signature);
    OPENSSL_free(ecdsa_signature);
    EVP_PKEY_free(ecdsa_key);
    hybrid_public_key_cleanup(&public_key);
    hybrid_private_key_cleanup(&private_key);
    return status;
}
