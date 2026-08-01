// SPDX-License-Identifier: MIT

/* Race calibration for the RS480 reset-mask atomic claim loop.
 *
 * Compiles the exact kernel claim function from
 * drivers/gpu/drm/radeon/radeon_rs4xx_reset_mask_claim.h against userspace
 * atomics and races it under pthreads.  Build and run from the repository
 * root:
 *
 *   cc -O2 -pthread -I drivers/gpu/drm/radeon \
 *      scripts/calibrate_rs480_reset_mask_claim.c \
 *      -o build/calibrate_rs480_reset_mask_claim
 *   build/calibrate_rs480_reset_mask_claim
 *
 * Exit 0: the claim loop satisfies all four race contracts and the
 * known-bad torn consume (the pre-claim read-then-store shape) violates
 * at least one, so the harness distinguishes good from bad.  Exit 1: a
 * claim-loop contract failed.  Exit 2: the torn consume passed, so the
 * harness lost its known-bad discrimination and its verdict is not
 * trustworthy on this machine.
 *
 * Contracts checked, mirroring the reset-mask consume requirements:
 *   1. a disarm store (baseline) is never returned as a claim;
 *   2. every claimed value was armed by the writer (validity);
 *   3. each armed selection is claimed at most once (one-shot);
 *   4. an out-of-range selector yields baseline with no consume.
 * The writer arms unique values, so duplicate claims are observable.
 */

#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define READ_ONCE(x) __atomic_load_n(&(x), __ATOMIC_SEQ_CST)
#define cmpxchg(p, o, n) __sync_val_compare_and_swap(p, o, n)

#include "radeon_rs4xx_reset_mask_claim.h"

/* Known-bad shape: the pre-claim consume read the selector, validated it,
 * stored baseline nonatomically, and returned the originally read value.
 * The sched_yield models the sysfs-write window between read and store. */
static unsigned int rs480_reset_mask_consume_torn(unsigned int *selp,
						  unsigned int baseline,
						  unsigned int count)
{
	unsigned int sel = READ_ONCE(*selp);

	if (sel == baseline || sel >= count)
		return baseline;
	sched_yield();
	*selp = baseline;
	return sel;
}

#define BASELINE 0u
#define COUNT (1u << 24)
#define ARMS 20000u
#define CLAIMERS 8

static unsigned int slot;
static volatile int writer_done;

/* claimed[v] counts how many claimers returned armed value v. */
static unsigned int *claimed;
static pthread_mutex_t claimed_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned int baseline_claims;

typedef unsigned int (*consume_fn)(unsigned int *, unsigned int,
				   unsigned int);

static consume_fn consume;

static void *writer_main(void *arg)
{
	unsigned int v;

	(void)arg;
	for (v = 1; v <= ARMS; v++) {
		__atomic_store_n(&slot, v, __ATOMIC_SEQ_CST);
		sched_yield();
		/* Every fourth arm is followed by an explicit disarm, so
		 * disarm stores race the claimers too (contract 1). */
		if ((v & 3) == 0)
			__atomic_store_n(&slot, BASELINE, __ATOMIC_SEQ_CST);
	}
	__atomic_store_n(&writer_done, 1, __ATOMIC_SEQ_CST);
	return NULL;
}

static void *claimer_main(void *arg)
{
	(void)arg;
	while (!__atomic_load_n(&writer_done, __ATOMIC_SEQ_CST)) {
		unsigned int got = consume(&slot, BASELINE, COUNT);

		if (got == BASELINE)
			continue;
		pthread_mutex_lock(&claimed_lock);
		if (got > ARMS)
			baseline_claims = ~0u; /* impossible value: fail */
		else
			claimed[got]++;
		pthread_mutex_unlock(&claimed_lock);
	}
	return NULL;
}

/* Returns 0 when all four contracts hold for fn, 1 otherwise. */
static int race_round(consume_fn fn, const char *label)
{
	pthread_t writer, claimers[CLAIMERS];
	unsigned int v, duplicates = 0, total = 0;
	int i, rc = 0;

	consume = fn;
	writer_done = 0;
	slot = BASELINE;
	baseline_claims = 0;
	memset(claimed, 0, (ARMS + 1) * sizeof(*claimed));

	pthread_create(&writer, NULL, writer_main, NULL);
	for (i = 0; i < CLAIMERS; i++)
		pthread_create(&claimers[i], NULL, claimer_main, NULL);
	pthread_join(writer, NULL);
	for (i = 0; i < CLAIMERS; i++)
		pthread_join(claimers[i], NULL);

	for (v = 1; v <= ARMS; v++) {
		total += claimed[v];
		if (claimed[v] > 1)
			duplicates++;
	}
	if (baseline_claims) {
		printf("%s: FAIL invalid or baseline value claimed\n", label);
		rc = 1;
	}
	if (duplicates) {
		printf("%s: FAIL %u selections claimed more than once\n",
		       label, duplicates);
		rc = 1;
	}
	printf("%s: %u arms, %u claims, %u duplicate-claimed\n",
	       label, ARMS, total, duplicates);
	return rc;
}

static int out_of_range_round(void)
{
	unsigned int got, after;

	slot = COUNT + 5;
	got = rs480_reset_mask_claim(&slot, BASELINE, COUNT);
	after = slot;
	if (got != BASELINE || after != COUNT + 5) {
		printf("out-of-range: FAIL got %u slot %u\n", got, after);
		return 1;
	}
	printf("out-of-range: baseline returned, selector not consumed\n");
	return 0;
}

int main(void)
{
	int bad_rounds = 0, round;

	claimed = calloc(ARMS + 1, sizeof(*claimed));
	if (!claimed)
		return 1;

	if (race_round(rs480_reset_mask_claim, "claim-loop"))
		return 1;
	if (out_of_range_round())
		return 1;

	/* Known-bad calibration: the torn consume must violate a contract
	 * in at least one round, or the harness cannot discriminate. */
	for (round = 0; round < 10 && !bad_rounds; round++)
		bad_rounds += race_round(rs480_reset_mask_consume_torn,
					 "torn-consume");
	if (!bad_rounds) {
		printf("calibration: torn consume never failed; "
		       "harness verdict untrustworthy here\n");
		return 2;
	}
	printf("calibration: claim loop PASS, torn consume refuted\n");
	return 0;
}
