/* SPDX-License-Identifier: MIT
 * Minimal test runner: RUN(fn) executes a test function, CHECK* record
 * failures without aborting so one run reports every broken assertion. */
#ifndef NP_TEST_H
#define NP_TEST_H

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static int t_failed_checks, t_checks, t_tests, t_failed_tests;
static int t_cur_failed;
static const char *t_cur_name;

#define CHECK(cond)                                                          \
    do {                                                                     \
        t_checks++;                                                          \
        if (!(cond)) {                                                       \
            t_failed_checks++;                                               \
            t_cur_failed = 1;                                                \
            fprintf(stderr, "  FAIL %s:%d [%s]: %s\n", __FILE__, __LINE__,   \
                    t_cur_name, #cond);                                      \
        }                                                                    \
    } while (0)

#define CHECK_EQ(a, b)                                                       \
    do {                                                                     \
        long long _a = (long long)(a), _b = (long long)(b);                  \
        t_checks++;                                                          \
        if (_a != _b) {                                                      \
            t_failed_checks++;                                               \
            t_cur_failed = 1;                                                \
            fprintf(stderr, "  FAIL %s:%d [%s]: %s == %s (%lld != %lld)\n",  \
                    __FILE__, __LINE__, t_cur_name, #a, #b, _a, _b);         \
        }                                                                    \
    } while (0)

#define RUN(fn)                                                              \
    do {                                                                     \
        t_cur_name = #fn;                                                    \
        t_cur_failed = 0;                                                    \
        t_tests++;                                                           \
        fn();                                                                \
        if (t_cur_failed)                                                    \
            t_failed_tests++;                                                \
        printf("%-44s %s\n", #fn, t_cur_failed ? "FAIL" : "ok");             \
    } while (0)

#define TEST_SUMMARY()                                                       \
    (printf("\n%d tests, %d checks, %d failed tests, %d failed checks\n",    \
            t_tests, t_checks, t_failed_tests, t_failed_checks),             \
     t_failed_tests ? 1 : 0)

#endif
