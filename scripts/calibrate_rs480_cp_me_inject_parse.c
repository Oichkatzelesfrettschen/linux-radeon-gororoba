// SPDX-License-Identifier: MIT

/* Calibration for the CP-ME injection command parser.
 *
 * Compiles the exact kernel parser from
 * drivers/gpu/drm/radeon/rs480_cp_me_inject_parse.h against userspace
 * sscanf and drives it through the accept/reject matrix.  Build and run
 * from the repository root:
 *
 *   cc -O2 -Wall -Wextra -I drivers/gpu/drm/radeon \
 *      scripts/calibrate_rs480_cp_me_inject_parse.c \
 *      -o build/calibrate_rs480_cp_me_inject_parse
 *   build/calibrate_rs480_cp_me_inject_parse
 *
 * Exit 0: every case parses to its expected verdict and the known-bad
 * parser (the three-conversion sscanf that ignores surplus text)
 * accepts at least one payload the exact parser rejects, so the harness
 * distinguishes good from bad.  Exit 1: a case failed.  Exit 2: the
 * known-bad parser matched the exact parser on the whole matrix.
 */

#include <stdio.h>

#include "rs480_cp_me_inject_parse.h"

/* Known-bad shape: the surplus-tolerant parser accepts "ARM 1 2 3 junk". */
static int cp_me_inject_parse_surplus_tolerant(const char *kbuf,
					       unsigned int *addr,
					       unsigned int *new_h,
					       unsigned int *new_l)
{
	return sscanf(kbuf, "ARM %x %x %x", addr, new_h, new_l) == 3;
}

struct parse_case {
	const char *name;
	const char *payload;
	int expected;
	unsigned int addr, new_h, new_l;
};

static const struct parse_case cases[] = {
	{ "exact command", "ARM ff 12345678 9abcdef0", 1,
	  0xff, 0x12345678, 0x9abcdef0 },
	{ "trailing newline", "ARM ff 1 2\n", 1, 0xff, 1, 2 },
	{ "trailing spaces", "ARM ff 1 2   ", 1, 0xff, 1, 2 },
	{ "surplus word", "ARM ff 1 2 junk", 0, 0, 0, 0 },
	{ "surplus glued to value", "ARM ff 1 2junk", 0, 0, 0, 0 },
	{ "fourth number", "ARM ff 1 2 3", 0, 0, 0, 0 },
	{ "missing value", "ARM ff 1", 0, 0, 0, 0 },
	{ "wrong keyword", "arm ff 1 2", 0, 0, 0, 0 },
	{ "empty payload", "", 0, 0, 0, 0 },
	{ "keyword only", "ARM", 0, 0, 0, 0 },
	{ "nonhex value", "ARM zz 1 2", 0, 0, 0, 0 },
};

int main(void)
{
	unsigned int i;
	unsigned int failures = 0;
	unsigned int bad_deviations = 0;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const struct parse_case *c = &cases[i];
		unsigned int addr = 0, new_h = 0, new_l = 0;
		int got = rs480_cp_me_inject_parse(c->payload, &addr,
						   &new_h, &new_l);

		if (got != c->expected ||
		    (c->expected && (addr != c->addr || new_h != c->new_h ||
				     new_l != c->new_l))) {
			printf("FAIL %s: got %d addr=%x h=%x l=%x\n",
			       c->name, got, addr, new_h, new_l);
			failures++;
		}

		if (cp_me_inject_parse_surplus_tolerant(c->payload, &addr,
							&new_h,
							&new_l) != c->expected)
			bad_deviations++;
	}

	if (failures) {
		printf("calibration FAILED: %u case(s)\n", failures);
		return 1;
	}
	if (!bad_deviations) {
		printf("known-bad parser matched the whole matrix: discrimination lost\n");
		return 2;
	}
	printf("calibration PASS: %u cases, known-bad deviates on %u\n",
	       (unsigned int)(sizeof(cases) / sizeof(cases[0])),
	       bad_deviations);
	return 0;
}
