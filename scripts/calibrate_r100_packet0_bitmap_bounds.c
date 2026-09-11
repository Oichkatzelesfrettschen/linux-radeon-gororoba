// SPDX-License-Identifier: MIT
/* Exercise the source-extracted packet0 admission function on bitmap edges. */
#include <errno.h>
#include <stdio.h>

struct radeon_cs_parser {
  unsigned callbacks;
  int callback_result;
};

struct radeon_cs_packet {
  unsigned idx;
  unsigned type;
  unsigned reg;
  unsigned opcode;
  int count;
  unsigned one_reg_wr;
};

typedef int (*radeon_packet0_check_t)(struct radeon_cs_parser *,
                                      struct radeon_cs_packet *, unsigned,
                                      unsigned);

#include "r100_packet0_source.inc"

static int check_register(struct radeon_cs_parser *parser,
                          struct radeon_cs_packet *packet, unsigned index,
                          unsigned reg) {
  (void)packet;
  (void)index;
  (void)reg;
  parser->callbacks++;
  return parser->callback_result;
}

int main(void) {
  /* Extra storage makes invalid admission observable without a host OOB read.
   * The function receives the declared entry count, not the storage count.
   */
  const unsigned bitmap[] = {~0u, ~0u, ~0u};
  unsigned failures = 0;
  unsigned cases = 0;

  for (unsigned entries = 0; entries <= 2; entries++) {
    for (unsigned repeated = 0; repeated <= 1; repeated++) {
      for (unsigned reg = 0; reg <= 256; reg += 4) {
        for (int count = 0; count <= 1; count++) {
          struct radeon_cs_parser parser = {0};
          struct radeon_cs_packet packet = {
              .reg = reg,
              .count = count,
              .one_reg_wr = repeated,
          };
          unsigned last = reg + (repeated ? 0 : (unsigned)count * 4);
          int expected = last / 128 < entries ? 0 : -EINVAL;
          int result = r100_cs_parse_packet0(&parser, &packet, bitmap, entries,
                                             check_register);
          unsigned callbacks = expected ? 0 : (unsigned)count + 1;

          cases++;
          if (result != expected || parser.callbacks != callbacks) {
            fprintf(stderr,
                    "entries=%u repeated=%u reg=%u count=%d: result=%d "
                    "expected=%d callbacks=%u expected=%u\n",
                    entries, repeated, reg, count, result, expected,
                    parser.callbacks, callbacks);
            failures++;
          }
        }
      }
    }
  }
  printf("packet0 source-body bounds: %u cases, %u failures\n", cases,
         failures);
  return failures ? 1 : 0;
}
