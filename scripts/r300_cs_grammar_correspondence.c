// SPDX-License-Identifier: MIT

/* Correspondence between the r300 command-stream grammar the kernel enforces
 * and the grammar replay_r300_cs_track models.
 *
 * The replay tool's own controls assert the replay's behavior, so they
 * establish self-consistency.  This tool derives the grammar a second time
 * from the kernel sources and holds the replay to it, which is the class of
 * control that decides fidelity.  Three derivations carry the weight, and
 * each one reads a kernel file rather than a constant in this program:
 *
 *   - the safe-register bitmap is rebuilt from reg_srcs/r300 by the rule
 *     mkregtable's table_build applies -- every word starts all ones and each
 *     listed offset toggles its bit -- and the result is compared word for
 *     word against the generated r300_reg_safe.h the kernel compiles, so the
 *     derivation is proven equivalent to the generator;
 *   - the set of registers r300_packet0_check names is extracted from the
 *     function's own top-level case labels, with symbolic labels resolved
 *     from the register headers and SYMBOL+N arithmetic evaluated, so a
 *     register number transcribed into the replay rather than taken from the
 *     tree lands on a different admission class here;
 *   - the relocation each named case consumes is counted from the calls in
 *     that case's body, and the tracking state r100_cs_track_clear starts
 *     from is read out of the r300 arm of that function.
 *
 * Those three facts decide one admission class per register: a register the
 * bitmap leaves clear passes unchecked, a register the bitmap flags and the
 * switch names reaches its case, and a register the bitmap flags and the
 * switch does not name reaches the switch's default arm, which rejects.  The
 * class plus the relocation count fixes what the replay must answer for a
 * two-packet stream carrying that register alone, and every register from
 * 0x0000 through the last the bitmap covers is run, so the correspondence is
 * total over the register space rather than sampled.
 *
 * A row whose kernel-derived facts disagree with the replay's answer is a
 * FAIL.  Two escapes exist and both are mechanical.  A SCOPE_CUT row is one
 * where the kernel admits a stream the replay refuses -- the conservative
 * direction -- and it holds only while the replay's header still declares
 * that cut by name; a row where the replay refuses less than the kernel is a
 * FAIL whatever the header says.  A MODEL_INTERNAL row is one whose expected
 * answer this program chooses rather than derives, because the kernel encodes
 * the restriction in C control flow; each such row still names a substring
 * its kernel case body must contain, so the choice is anchored to the source.
 *
 * Every control prints its authority class.  MODEL_INTERNAL is decided
 * inside this program, KERNEL_SOURCE_DERIVED is read out of the kernel tree,
 * and RUNNING_KERNEL would be read from a live parse on the target; no
 * control in this program is RUNNING_KERNEL.
 *
 * Usage:
 *   r300_cs_grammar_correspondence --tree DIR --replay PATH --workdir DIR
 *                                  [--reg-safe-header PATH] [--sweep 0|1]
 *
 * Exit 0 when every control holds, 1 when one does not, 2 on I/O or usage
 * failure.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* r100_cs_parse_packet0 range-checks with (reg >> 7) > n, so a register whose
 * word index equals the bitmap's entry count passes the check and indexes one
 * word past the array.  Both the kernel and the replay carry that window, so
 * this tool stays below it and asserts the bound rather than walking in.
 */
#define REG_STEP 4u

enum authority {
	AUTH_MODEL_INTERNAL,
	AUTH_KERNEL_SOURCE_DERIVED,
	AUTH_RUNNING_KERNEL,
};

static const char *authority_name(enum authority a)
{
	switch (a) {
	case AUTH_KERNEL_SOURCE_DERIVED:
		return "KERNEL_SOURCE_DERIVED";
	case AUTH_RUNNING_KERNEL:
		return "RUNNING_KERNEL";
	default:
		return "MODEL_INTERNAL";
	}
}

enum admission {
	ADM_UNCHECKED,		/* bitmap bit clear: written through unvalidated */
	ADM_NAMED,		/* bitmap bit set and r300_packet0_check names it */
	ADM_DEFAULT_REJECT,	/* bitmap bit set and the switch does not name it */
	ADM_RANGE_REJECT,	/* past the bitmap: r100_cs_parse_packet0 refuses */
};

static const char *admission_name(enum admission a)
{
	switch (a) {
	case ADM_UNCHECKED:
		return "unchecked";
	case ADM_NAMED:
		return "named-case";
	case ADM_DEFAULT_REJECT:
		return "default-reject";
	default:
		return "range-reject";
	}
}

static unsigned int pass_count, fail_count, scope_cut_count;
static unsigned int auth_kernel_rows, auth_model_rows, auth_running_rows;

/* --- file and text helpers --- */

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "rb");
	long size;
	char *buf;

	if (!f) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (size < 0) {
		fclose(f);
		return NULL;
	}
	buf = malloc((size_t)size + 1);
	if (!buf || fread(buf, 1, (size_t)size, f) != (size_t)size) {
		fprintf(stderr, "read %s failed\n", path);
		free(buf);
		fclose(f);
		return NULL;
	}
	buf[size] = 0;
	fclose(f);
	return buf;
}

static char *join(const char *a, const char *b)
{
	size_t n = strlen(a) + strlen(b) + 2;
	char *s = malloc(n);

	if (s)
		snprintf(s, n, "%s/%s", a, b);
	return s;
}

/* The byte range of one function, from its signature to the line holding the
 * closing brace in column zero.
 */
static int function_range(const char *text, const char *signature,
			  size_t *start, size_t *end)
{
	const char *p = strstr(text, signature);
	const char *q;

	if (!p)
		return -1;
	q = strstr(p, "\n}");
	if (!q)
		return -1;
	*start = (size_t)(p - text);
	*end = (size_t)(q + 2 - text);
	return 0;
}

/* --- symbol resolution out of the register headers --- */

struct symbol {
	char name[80];
	unsigned int value;
};

static struct symbol *symbols;
static size_t nsymbols, symbols_cap;

static void symbol_add(const char *name, unsigned int value)
{
	if (nsymbols == symbols_cap) {
		symbols_cap = symbols_cap ? symbols_cap * 2 : 1024;
		symbols = realloc(symbols, symbols_cap * sizeof(*symbols));
		if (!symbols) {
			fprintf(stderr, "out of memory\n");
			exit(2);
		}
	}
	snprintf(symbols[nsymbols].name, sizeof(symbols[nsymbols].name),
		 "%s", name);
	symbols[nsymbols].value = value;
	nsymbols++;
}

/* Collect every "#define NAME 0xVALUE" a header carries, including the
 * tab-indented subfield form, so a case label naming any of them resolves.
 */
static int symbols_load(const char *path)
{
	char *text = slurp(path);
	char *line, *save;

	if (!text)
		return -1;
	for (line = strtok_r(text, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char name[80];
		char value[80];
		const char *p = line;
		char *stop;
		unsigned long v;

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p != '#')
			continue;
		p++;
		while (*p == ' ' || *p == '\t')
			p++;
		if (strncmp(p, "define", 6) != 0)
			continue;
		p += 6;
		if (*p != ' ' && *p != '\t')
			continue;
		if (sscanf(p, "%79s %79s", name, value) != 2)
			continue;
		if (strchr(name, '('))
			continue;
		if (strncmp(value, "0x", 2) != 0 &&
		    (value[0] < '0' || value[0] > '9'))
			continue;
		v = strtoul(value, &stop, 0);
		if (*stop != 0)
			continue;
		symbol_add(name, (unsigned int)v);
	}
	free(text);
	return 0;
}

static int symbol_lookup(const char *name, unsigned int *out)
{
	size_t i;

	for (i = 0; i < nsymbols; i++) {
		if (strcmp(symbols[i].name, name) == 0) {
			*out = symbols[i].value;
			return 0;
		}
	}
	return -1;
}

/* --- the safe-register bitmap, rebuilt the way mkregtable builds it --- */

static unsigned int *safe_bm;
static unsigned int safe_bm_entries;

static int safe_bitmap_build(const char *reg_srcs_path)
{
	char *text = slurp(reg_srcs_path);
	char *line, *save;
	unsigned int offsets[4096];
	unsigned int noffsets = 0, offset_max = 0, last_reg = 0, i;
	int first = 1;

	if (!text)
		return -1;
	for (line = strtok_r(text, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		const char *p = strstr(line, "0x");
		unsigned long o;
		char *stop;

		if (first) {
			/* The header line names the chip and the last
			 * register, which floors the table's extent.
			 */
			first = 0;
			if (p)
				last_reg = (unsigned int)strtoul(p, NULL, 16);
			continue;
		}
		if (!p)
			continue;
		o = strtoul(p, &stop, 16);
		if (stop == p + 2)
			continue;
		if (noffsets == sizeof(offsets) / sizeof(offsets[0])) {
			fprintf(stderr, "reg_srcs holds more offsets than "
				"this tool carries room for\n");
			free(text);
			return -1;
		}
		offsets[noffsets++] = (unsigned int)o;
		if (o > offset_max)
			offset_max = (unsigned int)o;
	}
	free(text);
	if (offset_max < last_reg)
		offset_max = last_reg;
	safe_bm_entries = ((offset_max >> 2) + 31) / 32;
	safe_bm = malloc(safe_bm_entries * sizeof(*safe_bm));
	if (!safe_bm)
		return -1;
	memset(safe_bm, 0xff, safe_bm_entries * sizeof(*safe_bm));
	for (i = 0; i < noffsets; i++)
		safe_bm[(offsets[i] >> 2) / 32] ^=
			1u << ((offsets[i] >> 2) & 31);
	return 0;
}

static int register_flagged(unsigned int reg)
{
	return (safe_bm[(reg >> 2) / 32] & (1u << ((reg >> 2) & 31))) != 0;
}

/* --- r300_packet0_check's own case labels --- */

struct kcase {
	unsigned int reg;
	char label[80];		/* the label text as the switch spells it */
	unsigned int group;
	unsigned int nreloc;
	unsigned int nreloc_tiling_gated;
	int parses_vline;
	size_t body_start, body_end;
};

static struct kcase *kcases;
static size_t nkcases, kcases_cap;
static char *r300_text;

static void kcase_add(unsigned int reg, const char *label, unsigned int group)
{
	if (nkcases == kcases_cap) {
		kcases_cap = kcases_cap ? kcases_cap * 2 : 256;
		kcases = realloc(kcases, kcases_cap * sizeof(*kcases));
		if (!kcases) {
			fprintf(stderr, "out of memory\n");
			exit(2);
		}
	}
	memset(&kcases[nkcases], 0, sizeof(kcases[nkcases]));
	kcases[nkcases].reg = reg;
	kcases[nkcases].group = group;
	snprintf(kcases[nkcases].label, sizeof(kcases[nkcases].label), "%s",
		 label);
	nkcases++;
}

/* Resolve one case label: a hex literal, a symbol, or SYMBOL+N. */
static int label_value(const char *label, unsigned int *out)
{
	char name[80];
	const char *plus;
	unsigned int base;
	char *stop;

	while (*label == ' ' || *label == '\t')
		label++;
	if (label[0] == '0' && (label[1] == 'x' || label[1] == 'X')) {
		*out = (unsigned int)strtoul(label, &stop, 16);
		return 0;
	}
	plus = strchr(label, '+');
	if (plus) {
		size_t n = (size_t)(plus - label);

		while (n && (label[n - 1] == ' ' || label[n - 1] == '\t'))
			n--;
		if (n >= sizeof(name))
			return -1;
		memcpy(name, label, n);
		name[n] = 0;
		if (symbol_lookup(name, &base))
			return -1;
		*out = base + (unsigned int)strtoul(plus + 1, NULL, 0);
		return 0;
	}
	snprintf(name, sizeof(name), "%s", label);
	stop = name + strlen(name);
	while (stop > name && (stop[-1] == ' ' || stop[-1] == '\t'))
		*--stop = 0;
	return symbol_lookup(name, out);
}

/* Walk r300_packet0_check and collect its top-level case labels.  A label at
 * one tab of indentation belongs to this switch; the nested format and pitch
 * switches indent deeper, so the indentation separates them.
 */
static int kcases_load(const char *r300_c_path)
{
	size_t start, end, i, line_start;
	unsigned int group = 0;
	size_t group_first = 0;
	int in_labels = 0;

	r300_text = slurp(r300_c_path);
	if (!r300_text)
		return -1;
	if (function_range(r300_text, "static int r300_packet0_check(",
			   &start, &end)) {
		fprintf(stderr, "r300_packet0_check not found in %s\n",
			r300_c_path);
		return -1;
	}
	for (i = start; i < end; i = line_start) {
		const char *line = r300_text + i;
		const char *nl = strchr(line, '\n');
		size_t len = nl ? (size_t)(nl - line) : strlen(line);
		char label[80];
		const char *colon;

		line_start = i + len + (nl ? 1 : 0);
		if (len < 7 || line[0] != '\t' || line[1] == '\t' ||
		    strncmp(line + 1, "case ", 5) != 0)
			goto not_a_label;
		colon = memchr(line + 6, ':', len - 6);
		if (!colon)
			goto not_a_label;
		if ((size_t)(colon - (line + 6)) >= sizeof(label))
			return -1;
		memcpy(label, line + 6, (size_t)(colon - (line + 6)));
		label[colon - (line + 6)] = 0;
		if (!in_labels) {
			/* A new run of labels closes the previous group's
			 * body, which ran from its last label to here.
			 */
			for (size_t k = group_first; k < nkcases; k++)
				kcases[k].body_end = i;
			group++;
			group_first = nkcases;
			in_labels = 1;
		}
		{
			unsigned int reg;

			if (label_value(label, &reg)) {
				fprintf(stderr,
					"case label '%s' resolves to no "
					"register; the headers this tool reads "
					"do not define it\n", label);
				return -1;
			}
			kcase_add(reg, label, group);
			kcases[nkcases - 1].body_start = line_start;
		}
		continue;
not_a_label:
		if (in_labels) {
			in_labels = 0;
			for (size_t k = group_first; k < nkcases; k++)
				kcases[k].body_start = i;
		}
	}
	for (size_t k = group_first; k < nkcases; k++)
		kcases[k].body_end = end;
	return 0;
}

/* Count the relocations one case body consumes.  radeon_cs_packet_next_reloc
 * consumes one each time it is called, r100_reloc_pitch_offset consumes one
 * inside itself, and r100_cs_packet_parse_vline consumes one and then
 * advances past a second packet, which is the shape the replay does not
 * model.  A call the tiling-flag guard encloses is counted apart, because the
 * stream alone does not decide whether it runs.
 */
static void kcase_scan_bodies(void)
{
	size_t i;

	for (i = 0; i < nkcases; i++) {
		const char *p = r300_text + kcases[i].body_start;
		size_t len = kcases[i].body_end - kcases[i].body_start;
		char *body = malloc(len + 1);
		const char *q;

		if (!body) {
			fprintf(stderr, "out of memory\n");
			exit(2);
		}
		memcpy(body, p, len);
		body[len] = 0;
		for (q = body; (q = strstr(q, "radeon_cs_packet_next_reloc("));
		     q += 1)
			kcases[i].nreloc++;
		for (q = body; (q = strstr(q, "r100_reloc_pitch_offset("));
		     q += 1)
			kcases[i].nreloc++;
		if (strstr(body, "r100_cs_packet_parse_vline")) {
			kcases[i].parses_vline = 1;
			kcases[i].nreloc++;
		}
		/* COLORPITCH and ZB_DEPTHPITCH take their relocation inside
		 * the arm that runs when the client leaves the tiling flags
		 * to the kernel, so the count depends on a parser input the
		 * stream does not carry.  The negated guard is what separates
		 * them from TX_OFFSET, which consumes unconditionally and
		 * reads the same flag only to pick its rewrite.
		 */
		if (strstr(body, "!(p->cs_flags & RADEON_CS_KEEP_TILING_FLAGS)")) {
			kcases[i].nreloc_tiling_gated = kcases[i].nreloc;
			kcases[i].nreloc = 0;
		}
		free(body);
	}
}

static const struct kcase *kcase_find(unsigned int reg)
{
	size_t i;

	for (i = 0; i < nkcases; i++)
		if (kcases[i].reg == reg)
			return &kcases[i];
	return NULL;
}

static int kcase_body_has(unsigned int reg, const char *needle)
{
	const struct kcase *k = kcase_find(reg);
	size_t len;
	char *body;
	int found;

	if (!k)
		return 0;
	len = k->body_end - k->body_start;
	body = malloc(len + 1);
	if (!body)
		return 0;
	memcpy(body, r300_text + k->body_start, len);
	body[len] = 0;
	found = strstr(body, needle) != NULL;
	free(body);
	return found;
}

/* --- running the replay over a constructed stream --- */

/* The run-form controls carry a maximum-count PACKET0, whose payload is
 * 0x4000 dwords, so the stream holds header + payload + trailing packets.
 */
struct stream {
	uint32_t dw[16512];
	unsigned int ndw;
};

static void stream_pkt0(struct stream *s, unsigned int reg, uint32_t value)
{
	s->dw[s->ndw++] = (uint32_t)(reg >> 2);	/* type 0, count 0 */
	s->dw[s->ndw++] = value;
}

static void stream_reloc_nop(struct stream *s, uint32_t entry)
{
	s->dw[s->ndw++] = 0xC0001000u;		/* type 3, count 0, NOP */
	s->dw[s->ndw++] = entry;
}

static void stream_pkt3(struct stream *s, unsigned int opcode,
			unsigned int count)
{
	s->dw[s->ndw++] = 0xC0000000u | (uint32_t)(count << 16) |
			  (uint32_t)(opcode << 8);
}

struct verdict {
	int accepted;
	unsigned int relocs;
	int tool_error;
};

static const char *g_replay;
static const char *g_bundle;
static const char *g_ib;

static int run_replay(const struct stream *s, struct verdict *v)
{
	int fds[2];
	pid_t pid;
	FILE *f;
	char line[512];
	int status;

	f = fopen(g_ib, "wb");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", g_ib, strerror(errno));
		return -1;
	}
	if (fwrite(s->dw, 4, s->ndw, f) != s->ndw) {
		fclose(f);
		return -1;
	}
	fclose(f);

	memset(v, 0, sizeof(*v));
	if (pipe(fds))
		return -1;
	pid = fork();
	if (pid < 0) {
		close(fds[0]);
		close(fds[1]);
		return -1;
	}
	if (pid == 0) {
		char *argv[5];

		argv[0] = (char *)g_replay;
		argv[1] = (char *)"--verbose";
		argv[2] = (char *)g_bundle;
		argv[3] = (char *)g_ib;
		argv[4] = NULL;
		close(fds[0]);
		dup2(fds[1], 1);
		dup2(fds[1], 2);
		close(fds[1]);
		execv(g_replay, argv);
		_exit(127);
	}
	close(fds[1]);
	f = fdopen(fds[0], "r");
	if (!f) {
		close(fds[0]);
		return -1;
	}
	while (fgets(line, sizeof(line), f))
		if (strstr(line, "reloc -> entry"))
			v->relocs++;
	fclose(f);
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	if (!WIFEXITED(status)) {
		v->tool_error = 1;
		return 0;
	}
	switch (WEXITSTATUS(status)) {
	case 0:
		v->accepted = 1;
		break;
	case 1:
		v->accepted = 0;
		break;
	default:
		v->tool_error = 1;
		break;
	}
	return 0;
}

/* --- controls --- */

static void control(int ok, enum authority a, const char *fmt, ...)
{
	va_list ap;

	if (ok)
		pass_count++;
	else
		fail_count++;
	printf("  %-4s %-21s ", ok ? "PASS" : "FAIL", authority_name(a));
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	if (a == AUTH_KERNEL_SOURCE_DERIVED)
		auth_kernel_rows++;
	else if (a == AUTH_RUNNING_KERNEL)
		auth_running_rows++;
	else
		auth_model_rows++;
}

/* The generated header the kernel compiles, parsed back into words so the
 * rebuilt bitmap can be compared against it entry by entry.
 */
static int check_bitmap_matches_generated(const char *header_path)
{
	char *text = slurp(header_path);
	const char *p;
	unsigned int i = 0;
	int ok = 1;

	if (!text) {
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"generated r300_reg_safe.h unreadable at %s",
			header_path);
		return -1;
	}
	p = strchr(text, '{');
	if (!p) {
		free(text);
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"generated r300_reg_safe.h holds no initializer");
		return -1;
	}
	p++;
	while (*p && *p != '}') {
		char *stop;
		unsigned long v;

		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == ',')
			p++;
		if (*p == '}' || !*p)
			break;
		v = strtoul(p, &stop, 0);
		if (stop == p)
			break;
		p = stop;
		if (i >= safe_bm_entries || safe_bm[i] != (unsigned int)v)
			ok = 0;
		i++;
	}
	free(text);
	if (i != safe_bm_entries)
		ok = 0;
	control(ok, AUTH_KERNEL_SOURCE_DERIVED,
		"rebuilt safe bitmap equals generated r300_reg_safe.h "
		"(%u of %u entries)", i, safe_bm_entries);
	return ok ? 0 : -1;
}

/* --- initial tracking state --- */

/* Read "<prefix>-><field> = <literal>;" out of a region of text.  true and
 * false normalize to 1 and 0 so the kernel's bool and the replay's int
 * compare directly.
 */
static int read_field(const char *text, size_t start, size_t end,
		      const char *prefix, const char *field,
		      unsigned long *out)
{
	char pattern[128];
	const char *p = text + start;
	const char *limit = text + end;
	size_t plen;

	snprintf(pattern, sizeof(pattern), "%s->%s = ", prefix, field);
	plen = strlen(pattern);
	while (p < limit && (p = strstr(p, pattern)) != NULL && p < limit) {
		const char *v = p + plen;
		char *stop;
		unsigned long value;

		if (strncmp(v, "true", 4) == 0) {
			*out = 1;
			return 0;
		}
		if (strncmp(v, "false", 5) == 0) {
			*out = 0;
			return 0;
		}
		value = strtoul(v, &stop, 0);
		if (stop != v) {
			*out = value;
			return 0;
		}
		p += plen;
	}
	return -1;
}

struct initial_field {
	const char *field;
	const char *human;
};

static const struct initial_field r300_arm_fields[] = {
	{ "num_cb", "num_cb" },
	{ "maxy", "maxy" },
};

static const struct initial_field tail_fields[] = {
	{ "cb[i].pitch", "color pitch" },
	{ "cb[i].cpp", "color cpp" },
	{ "z_enabled", "z_enabled" },
	{ "zb.pitch", "z pitch" },
	{ "zb.cpp", "z cpp" },
	{ "vtx_size", "vtx_size" },
	{ "immd_dwords", "immd_dwords" },
	{ "num_arrays", "num_arrays" },
	{ "max_indx", "max_indx" },
};

/* The r300 arm of r100_cs_track_clear is the else block of the family test.
 * num_cb and maxy are written in both arms, so reading the function as one
 * region returns the pre-R300 values; the region split is what makes the
 * comparison meaningful, and the calibration below asserts that the naive
 * read really does return the other arm's value.
 */
static int track_clear_regions(const char *text, size_t fstart, size_t fend,
			       size_t *else_start, size_t *else_end)
{
	const char *p = strstr(text + fstart, "if (rdev->family < CHIP_R300) {");
	const char *q;
	int depth;

	if (!p || (size_t)(p - text) >= fend)
		return -1;
	q = strstr(p, "} else {");
	if (!q || (size_t)(q - text) >= fend)
		return -1;
	q += strlen("} else {");
	*else_start = (size_t)(q - text);
	depth = 1;
	while ((size_t)(q - text) < fend && depth) {
		if (*q == '{')
			depth++;
		else if (*q == '}')
			depth--;
		q++;
	}
	*else_end = (size_t)(q - text);
	return depth ? -1 : 0;
}

static void check_initial_state(const char *tree)
{
	char *r100_path = join(tree, "drivers/gpu/drm/radeon/r100.c");
	char *replay_path = join(tree, "scripts/replay_r300_cs_track.c");
	char *r100 = r100_path ? slurp(r100_path) : NULL;
	char *replay = replay_path ? slurp(replay_path) : NULL;
	size_t kstart, kend, kelse_start, kelse_end;
	size_t rstart, rend;
	unsigned long kv, rv;
	size_t i;

	free(r100_path);
	free(replay_path);
	if (!r100 || !replay) {
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"initial-state sources readable");
		free(r100);
		free(replay);
		return;
	}
	if (function_range(r100, "void r100_cs_track_clear(", &kstart, &kend) ||
	    function_range(replay, "static void track_clear(", &rstart,
			   &rend) ||
	    track_clear_regions(r100, kstart, kend, &kelse_start,
				&kelse_end)) {
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"r100_cs_track_clear and track_clear located");
		free(r100);
		free(replay);
		return;
	}

	/* Calibration for the region split: reading the whole function must
	 * return the pre-R300 arm's maxy, and the else region must return the
	 * R300 arm's.  Equal values would mean the split is doing nothing and
	 * every field below would be read from an unknown arm.
	 */
	if (read_field(r100, kstart, kend, "track", "maxy", &kv) ||
	    read_field(r100, kelse_start, kelse_end, "track", "maxy", &rv))
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"region-split calibration read maxy from both arms");
	else
		control(kv != rv && rv == 4096, AUTH_KERNEL_SOURCE_DERIVED,
			"region-split calibration: whole function reads maxy "
			"%lu, the R300 arm reads %lu", kv, rv);

	for (i = 0; i < sizeof(r300_arm_fields) / sizeof(r300_arm_fields[0]);
	     i++) {
		const char *f = r300_arm_fields[i].field;

		if (read_field(r100, kelse_start, kelse_end, "track", f, &kv) ||
		    read_field(replay, rstart, rend, "t", f, &rv)) {
			control(0, AUTH_KERNEL_SOURCE_DERIVED,
				"initial %s readable from both sources",
				r300_arm_fields[i].human);
			continue;
		}
		control(kv == rv, AUTH_KERNEL_SOURCE_DERIVED,
			"initial %s: kernel %lu, replay %lu",
			r300_arm_fields[i].human, kv, rv);
	}
	for (i = 0; i < sizeof(tail_fields) / sizeof(tail_fields[0]); i++) {
		const char *f = tail_fields[i].field;

		if (read_field(r100, kelse_end, kend, "track", f, &kv) ||
		    read_field(replay, rstart, rend, "t", f, &rv)) {
			control(0, AUTH_KERNEL_SOURCE_DERIVED,
				"initial %s readable from both sources",
				tail_fields[i].human);
			continue;
		}
		control(kv == rv, AUTH_KERNEL_SOURCE_DERIVED,
			"initial %s: kernel %lu, replay %lu",
			tail_fields[i].human, kv, rv);
	}
	free(r100);
	free(replay);
}

/* --- per-register rows --- */

/* A register whose case body restricts the value or the chip decides its
 * answer in C control flow rather than in the case list, so this program
 * chooses the probe value or the expected answer.  Each entry names a
 * substring its case body must still contain, which anchors the choice to
 * the kernel source: the row fails when the kernel drops the restriction.
 */
struct value_override {
	unsigned int reg;
	uint32_t value;
	int expect_reject;
	const char *anchor;
	const char *why;
};

static const struct value_override value_overrides[] = {
	/* RB3D_COLORPITCH0..3 reject an unnamed color format, and zero is
	 * unnamed, so the probe carries format 6.
	 */
	{ 0x4E38, 0x00C00000, 0, "Invalid color buffer format",
	  "COLORPITCH rejects the zero format" },
	{ 0x4E3C, 0x00C00000, 0, "Invalid color buffer format",
	  "COLORPITCH rejects the zero format" },
	{ 0x4E40, 0x00C00000, 0, "Invalid color buffer format",
	  "COLORPITCH rejects the zero format" },
	{ 0x4E44, 0x00C00000, 0, "Invalid color buffer format",
	  "COLORPITCH rejects the zero format" },
	/* VAP_ALT_NUM_VERTICES is admitted from RV515 forward, and the target
	 * family the bundle names is RS480.
	 */
	{ 0x2088, 0, 1, "CHIP_RV515",
	  "VAP_ALT_NUM_VERTICES is refused below RV515" },
	/* 0x4be8 is admitted on RV530 alone. */
	{ 0x4be8, 0, 1, "CHIP_RV530",
	  "0x4be8 is admitted on RV530 alone" },
};

static const struct value_override *override_find(unsigned int reg)
{
	size_t i;

	for (i = 0; i < sizeof(value_overrides) / sizeof(value_overrides[0]);
	     i++)
		if (value_overrides[i].reg == reg)
			return &value_overrides[i];
	return NULL;
}

static enum admission classify(unsigned int reg, const struct kcase **k)
{
	*k = NULL;
	/* r100_cs_parse_packet0 refuses a register whose word index runs past
	 * the bitmap, and the one word where its > comparison admits an index
	 * equal to the entry count reads past the array in both the kernel and
	 * the model, so this tool treats the whole tail as refused and never
	 * walks into that window.
	 */
	if ((reg >> 7) >= safe_bm_entries)
		return ADM_RANGE_REJECT;
	if (!register_flagged(reg))
		return ADM_UNCHECKED;
	*k = kcase_find(reg);
	return *k ? ADM_NAMED : ADM_DEFAULT_REJECT;
}

/* One row: the two-packet stream carrying this register alone, plus the
 * relocation NOP where the kernel case consumes one.  The paired arm without
 * the NOP discriminates a consuming case from a non-consuming one.
 */
static void row(unsigned int reg, const char *name)
{
	const struct kcase *k;
	enum admission adm = classify(reg, &k);
	const struct value_override *ov = override_find(reg);
	enum authority auth = AUTH_KERNEL_SOURCE_DERIVED;
	unsigned int want_relocs = k ? k->nreloc : 0;
	int want_accept;
	struct stream s;
	struct verdict v;
	int ok;

	memset(&s, 0, sizeof(s));
	want_accept = (adm == ADM_UNCHECKED || adm == ADM_NAMED);

	/* The replay fixes RADEON_CS_KEEP_TILING_FLAGS set, so it takes the
	 * arm that consumes nothing.  That is a choice this program makes
	 * about a parser input rather than a fact it derives, and it holds
	 * only while the replay's header still names the flag it fixes.
	 */
	if (k && k->nreloc_tiling_gated) {
		char *replay_src = slurp("scripts/replay_r300_cs_track.c");
		int declared = replay_src &&
			strstr(replay_src, "RADEON_CS_KEEP_TILING_FLAGS") != NULL;

		free(replay_src);
		if (!declared) {
			control(0, AUTH_KERNEL_SOURCE_DERIVED,
				"0x%04X %s: the model no longer declares which "
				"RADEON_CS_KEEP_TILING_FLAGS value it fixes",
				reg, name);
			return;
		}
		auth = AUTH_MODEL_INTERNAL;
	}
	if (ov) {
		auth = AUTH_MODEL_INTERNAL;
		if (!kcase_body_has(reg, ov->anchor)) {
			control(0, AUTH_KERNEL_SOURCE_DERIVED,
				"0x%04X %s: case body no longer carries '%s'",
				reg, name, ov->anchor);
			return;
		}
		if (ov->expect_reject)
			want_accept = 0;
	}

	/* A scope cut the replay's header declares: the kernel admits the
	 * register through a path the replay does not model, and the replay
	 * refuses it instead, which is the conservative direction.
	 */
	if (k && k->parses_vline) {
		char *replay_src = NULL;
		char *p = join(".", "scripts/replay_r300_cs_track.c");

		if (p) {
			replay_src = slurp(p);
			free(p);
		}
		stream_pkt0(&s, reg, ov ? ov->value : 0);
		stream_reloc_nop(&s, 0);
		if (run_replay(&s, &v)) {
			control(0, AUTH_KERNEL_SOURCE_DERIVED,
				"0x%04X %s: replay did not run", reg, name);
			free(replay_src);
			return;
		}
		ok = !v.accepted && replay_src &&
		     strstr(replay_src, "r100_cs_packet_parse_vline") != NULL;
		free(replay_src);
		if (ok) {
			scope_cut_count++;
			auth_kernel_rows++;
			printf("  %-4s %-21s 0x%04X %-28s %-14s "
			       "kernel admits through r100_cs_packet_parse_"
			       "vline; the replay refuses\n",
			       "CUT", authority_name(AUTH_KERNEL_SOURCE_DERIVED),
			       reg, name, admission_name(adm));
		} else {
			control(0, AUTH_KERNEL_SOURCE_DERIVED,
				"0x%04X %s: scope cut unsound -- the replay "
				"admits what it does not model, or the header "
				"stopped declaring the cut", reg, name);
		}
		return;
	}

	stream_pkt0(&s, reg, ov ? ov->value : 0);
	/* The consuming cases read this NOP as their relocation; for a
	 * non-consuming case a trailing type-3 NOP is a legal packet.
	 */
	stream_reloc_nop(&s, 0);
	if (run_replay(&s, &v)) {
		control(0, auth, "0x%04X %s: replay did not run", reg, name);
		return;
	}
	if (v.tool_error) {
		control(0, auth, "0x%04X %s: replay reported a tool error",
			reg, name);
		return;
	}
	ok = (v.accepted == want_accept);
	if (want_accept)
		ok = ok && (v.relocs == want_relocs);

	/* The paired arm: with the NOP removed, a consuming case must refuse
	 * for want of a relocation and a non-consuming one must still pass.
	 */
	if (ok && want_accept) {
		struct stream bare;
		struct verdict bv;

		memset(&bare, 0, sizeof(bare));
		stream_pkt0(&bare, reg, ov ? ov->value : 0);
		bare.dw[bare.ndw++] = 0x80000000u;	/* type 2 filler */
		bare.dw[bare.ndw++] = 0x80000000u;
		if (run_replay(&bare, &bv))
			ok = 0;
		else if (want_relocs)
			ok = !bv.accepted;
		else
			ok = bv.accepted && bv.relocs == 0;
	}

	if (ok)
		pass_count++;
	else
		fail_count++;
	if (auth == AUTH_KERNEL_SOURCE_DERIVED)
		auth_kernel_rows++;
	else
		auth_model_rows++;
	printf("  %-4s %-21s 0x%04X %-28s %-14s reloc=%u expect=%s got=%s "
	       "relocs=%u%s%s\n",
	       ok ? "PASS" : "FAIL", authority_name(auth), reg, name,
	       admission_name(adm), want_relocs,
	       want_accept ? "accept" : "reject",
	       v.accepted ? "accept" : "reject", v.relocs,
	       ov ? " -- " : "", ov ? ov->why : "");
	if (k && k->nreloc_tiling_gated)
		printf("       0x%04X takes its relocation only when the "
		       "client leaves the tiling flags to the kernel; the "
		       "model fixes them kept\n", reg);
}

/* --- the four permanent negative fixtures --- */

/* A stream that makes the zb_cb_clear term observable: with the color bound
 * check armed, a color buffer smaller than pitch * cpp * maxy is refused;
 * with the term clear, the check is skipped and the same stream passes.
 * Depth is disabled and the draw is an immediate one so the color term is
 * the only thing the check turns on.
 */
static void build_zb_cb_clear_stream(struct stream *s, unsigned int reg)
{
	memset(s, 0, sizeof(*s));
	stream_pkt0(s, 0x4F00, 0);		/* ZB_CNTL: depth off */
	stream_pkt0(s, 0x4E00, 0);		/* RB3D_CCTL: one color buffer */
	stream_pkt0(s, 0x20B4, 1);		/* VAP_VTX_SIZE */
	stream_pkt0(s, reg, 1u << 5);		/* the fixture register */
	stream_pkt0(s, 0x4E38, 0x00C00000 | 4);	/* COLORPITCH0: format 6 */
	stream_pkt0(s, 0x4E28, 0);		/* COLOROFFSET0 */
	stream_reloc_nop(s, 0);
	stream_pkt3(s, 0x35, 1);		/* 3D_DRAW_IMMD_2 */
	s->dw[s->ndw++] = 0x00010030u;		/* one vertex, PRIM_WALK 3 */
	s->dw[s->ndw++] = 0;			/* the vertex the count spans */
}

struct fixture {
	const char *name;
	unsigned int wrong;
	unsigned int right;
	int tracker_discriminator;
};

static const struct fixture fixtures[] = {
	{ "TX_OFFSET_0", 0x4C00, 0x4540, 0 },
	{ "ZB_ZPASS_ADDR", 0x4F58, 0x4F5C, 0 },
	{ "DST_PITCH_OFFSET", 0x1420, 0x142C, 0 },
	{ "ZB_BW_CNTL", 0x4F18, 0x4F1C, 1 },
};

static void check_fixtures(void)
{
	size_t i;

	for (i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++) {
		const struct fixture *f = &fixtures[i];
		const struct kcase *kw, *kr;
		enum admission aw = classify(f->wrong, &kw);
		enum admission ar = classify(f->right, &kr);
		struct verdict vw, vr;
		struct stream sw, sr;
		int ok;

		if (f->tracker_discriminator) {
			build_zb_cb_clear_stream(&sw, f->wrong);
			build_zb_cb_clear_stream(&sr, f->right);
			if (run_replay(&sw, &vw) || run_replay(&sr, &vr)) {
				control(0, AUTH_KERNEL_SOURCE_DERIVED,
					"%s fixture: replay did not run",
					f->name);
				continue;
			}
			ok = kcase_body_has(f->right, "zb_cb_clear") &&
			     aw != ar && vw.accepted && !vr.accepted;
			control(ok, AUTH_KERNEL_SOURCE_DERIVED,
				"%s 0x%04X (%s) vs 0x%04X (%s): the color "
				"bound check is armed by the correct register "
				"alone -- wrong=%s right=%s", f->name,
				f->wrong, admission_name(aw), f->right,
				admission_name(ar),
				vw.accepted ? "accept" : "reject",
				vr.accepted ? "accept" : "reject");
			continue;
		}

		memset(&sw, 0, sizeof(sw));
		memset(&sr, 0, sizeof(sr));
		stream_pkt0(&sw, f->wrong, 0);
		stream_reloc_nop(&sw, 0);
		stream_pkt0(&sr, f->right, 0);
		stream_reloc_nop(&sr, 0);
		if (run_replay(&sw, &vw) || run_replay(&sr, &vr)) {
			control(0, AUTH_KERNEL_SOURCE_DERIVED,
				"%s fixture: replay did not run", f->name);
			continue;
		}
		ok = (aw != ar) &&
		     (vw.accepted != vr.accepted || vw.relocs != vr.relocs);
		control(ok, AUTH_KERNEL_SOURCE_DERIVED,
			"%s 0x%04X (%s, %s, relocs=%u) vs 0x%04X (%s, %s, "
			"relocs=%u)", f->name, f->wrong, admission_name(aw),
			vw.accepted ? "accept" : "reject", vw.relocs,
			f->right, admission_name(ar),
			vr.accepted ? "accept" : "reject", vr.relocs);
	}
}

/* --- run-form correspondence --- */

/* The rows and the sweep hold the replay to the kernel's grammar one
 * register at a time.  These controls hold it to the run forms
 * r100_cs_parse_packet0 defines over a single PACKET0: the count field
 * naming count + 1 payload dwords, the register advancing by four per dword
 * in the normal form, the ONE_REG_WR form holding the register and breaking
 * at the first unflagged one, the bitmap bound taken over the whole run in
 * the normal form and over the first register alone in the ONE_REG_WR form,
 * type-2 advancement, and the chunk-end comparison radeon_cs_packet_parse
 * applies.  The expectations walk the same derived bitmap and case facts
 * the rows use, and the loop form itself is anchored to the kernel text.
 */

static void stream_pkt0_run(struct stream *s, unsigned int reg,
			    unsigned int count, int one_reg_wr,
			    uint32_t value)
{
	unsigned int i;

	s->dw[s->ndw++] = (uint32_t)(reg >> 2) |
			  (one_reg_wr ? 1u << 15 : 0) |
			  ((uint32_t)count << 16);
	for (i = 0; i <= count; i++)
		s->dw[s->ndw++] = value;
}

/* A register a run control may dispatch with value zero: no value override,
 * no tiling-gated relocation, no vline scope cut.  Its answer is then
 * decided by the bitmap class and the derived relocation count alone, which
 * the per-register rows already proved the replay honors.
 */
static int run_plain(unsigned int reg, enum admission *adm_out,
		     unsigned int *nreloc_out)
{
	const struct kcase *k;
	enum admission adm = classify(reg, &k);

	*adm_out = adm;
	*nreloc_out = k ? k->nreloc : 0;
	if (override_find(reg))
		return 0;
	if (k && (k->nreloc_tiling_gated || k->parses_vline))
		return 0;
	return 1;
}

/* Walk a run the way r100_cs_parse_packet0 walks it, over the derived
 * classes.  Returns 1 with the relocation total when the kernel accepts the
 * run, 0 when it rejects it, and -1 when a dispatched register is one these
 * controls do not model with value zero.
 */
static int run_expect(unsigned int reg, unsigned int count, int one_reg_wr,
		      unsigned int *relocs_out)
{
	unsigned int i, relocs = 0;

	if (one_reg_wr) {
		if ((reg >> 7) > safe_bm_entries)
			return 0;
	} else {
		if (((reg + (count << 2)) >> 7) > safe_bm_entries)
			return 0;
	}
	for (i = 0; i <= count; i++) {
		enum admission adm;
		unsigned int nreloc;

		if (run_plain(reg, &adm, &nreloc) == 0)
			return -1;
		if (adm == ADM_DEFAULT_REJECT || adm == ADM_RANGE_REJECT)
			return 0;
		if (adm == ADM_NAMED)
			relocs += nreloc;
		if (one_reg_wr) {
			if (adm == ADM_UNCHECKED)
				break;
		} else {
			reg += 4;
		}
	}
	*relocs_out = relocs;
	return 1;
}

/* One accepted run against the replay: build the packet, append the
 * relocation NOPs the derivation expects, and compare accept and count.
 */
static int run_probe(unsigned int reg, unsigned int count, int one_reg_wr,
		     unsigned int nops, struct verdict *v)
{
	struct stream s;
	unsigned int i;

	memset(&s, 0, sizeof(s));
	stream_pkt0_run(&s, reg, count, one_reg_wr, 0);
	for (i = 0; i < nops; i++)
		stream_reloc_nop(&s, 0);
	if (nops == 0) {
		s.dw[s.ndw++] = 0x80000000u;	/* type 2 filler */
		s.dw[s.ndw++] = 0x80000000u;
	}
	return run_replay(&s, v);
}

static int text_range_has(const char *text, const char *sig,
			  const char *needle)
{
	size_t start, end;
	char save;
	int found;

	if (!text || function_range(text, sig, &start, &end))
		return 0;
	save = ((char *)text)[end];
	((char *)text)[end] = 0;
	found = strstr(text + start, needle) != NULL;
	((char *)text)[end] = save;
	return found;
}

static void check_run_forms(void)
{
	char *r100 = slurp("drivers/gpu/drm/radeon/r100.c");
	char *rcs = slurp("drivers/gpu/drm/radeon/radeon_cs.c");
	const char *p0sig = "int r100_cs_parse_packet0(";
	unsigned int top = safe_bm_entries * 32 * REG_STEP - REG_STEP;
	unsigned int quad = 0, pair_a = 0, cross_a = 0, defrej_a = 0;
	unsigned int orw = 0, big = 0;
	unsigned int reg, e, e2;
	struct verdict v, v2;
	int r;

	/* The loop form the expectations mirror, read out of the kernel
	 * text: count + 1 iterations, advance by four, the ONE_REG_WR break,
	 * both bound forms, and the chunk-end comparison.
	 */
	control(text_range_has(r100, p0sig,
			       "for (i = 0; i <= pkt->count; i++, idx++)"),
		AUTH_KERNEL_SOURCE_DERIVED,
		"r100_cs_parse_packet0 iterates count + 1 payload dwords");
	control(text_range_has(r100, p0sig, "reg += 4;"),
		AUTH_KERNEL_SOURCE_DERIVED,
		"r100_cs_parse_packet0 advances one register per dword");
	control(text_range_has(r100, p0sig, "if (pkt->one_reg_wr)") &&
		text_range_has(r100, p0sig, "break;"),
		AUTH_KERNEL_SOURCE_DERIVED,
		"r100_cs_parse_packet0 holds the register under ONE_REG_WR "
		"and breaks at the first unflagged one");
	control(text_range_has(r100, p0sig, "(reg >> 7) > n") &&
		text_range_has(r100, p0sig,
			       "((reg + (pkt->count << 2)) >> 7) > n"),
		AUTH_KERNEL_SOURCE_DERIVED,
		"the bitmap bound covers the whole run in the normal form "
		"and the first register alone under ONE_REG_WR");
	control(text_range_has(rcs, "int radeon_cs_packet_parse(",
			       "(pkt->count + 1 + pkt->idx) >= "
			       "ib_chunk->length_dw"),
		AUTH_KERNEL_SOURCE_DERIVED,
		"radeon_cs_packet_parse admits a packet ending on the last "
		"chunk dword and refuses one past it");
	free(r100);
	free(rcs);

	/* Register selection, from the derivation rather than a list: each
	 * scan names the class shape its control needs.
	 */
	for (reg = 0; reg + 12 <= top && !quad; reg += REG_STEP) {
		enum admission a;
		unsigned int n, i, ok = 1;

		for (i = 0; i < 4; i++)
			if (run_plain(reg + 4 * i, &a, &n) != 1 ||
			    a != ADM_NAMED || n != 1)
				ok = 0;
		if (ok)
			quad = reg;
	}
	for (reg = 0; reg + 16 <= top && !pair_a; reg += REG_STEP) {
		enum admission a0, a1, a4;
		unsigned int n0, n1, n4;

		if (run_plain(reg, &a0, &n0) != 1 ||
		    run_plain(reg + 4, &a1, &n1) != 1 ||
		    run_plain(reg + 16, &a4, &n4) != 1)
			continue;
		/* First register contributes nothing, the second one
		 * relocation; the register four steps on answers
		 * differently, so a walk advancing four registers per dword
		 * lands on a different verdict than one advancing one.
		 */
		if ((a0 == ADM_UNCHECKED || (a0 == ADM_NAMED && n0 == 0)) &&
		    a1 == ADM_NAMED && n1 == 1 &&
		    (a4 == ADM_DEFAULT_REJECT ||
		     ((a4 == ADM_UNCHECKED || a4 == ADM_NAMED) &&
		      (a4 == ADM_UNCHECKED ? 0 : n4) != 1)))
			pair_a = reg;
	}
	for (reg = REG_STEP; reg + 4 <= top && !cross_a; reg += REG_STEP) {
		enum admission a0, a1;
		unsigned int n0, n1;

		if (run_plain(reg, &a0, &n0) != 1 ||
		    run_plain(reg + 4, &a1, &n1) != 1)
			continue;
		if (a0 == ADM_NAMED && n0 == 1 && a1 == ADM_UNCHECKED)
			cross_a = reg;
	}
	for (reg = 0; reg + 4 <= top && !defrej_a; reg += REG_STEP) {
		enum admission a0, a1;
		unsigned int n0, n1;

		if (run_plain(reg, &a0, &n0) != 1 ||
		    run_plain(reg + 4, &a1, &n1) != 1)
			continue;
		if ((a0 == ADM_UNCHECKED || a0 == ADM_NAMED) &&
		    a1 == ADM_DEFAULT_REJECT)
			defrej_a = reg;
	}
	for (reg = 0; reg + 8 <= top && !orw; reg += REG_STEP) {
		enum admission a0;
		unsigned int n0;
		int rn;

		if (run_plain(reg, &a0, &n0) != 1 || a0 != ADM_NAMED ||
		    n0 != 1)
			continue;
		/* The held-register walk consumes two relocations; the
		 * normal walk over the same header must answer differently,
		 * so a decoder ignoring ONE_REG_WR is caught.
		 */
		rn = run_expect(reg, 1, 0, &e2);
		if (rn == 0 || (rn == 1 && e2 != 2))
			orw = reg;
	}
	for (reg = 0; reg <= top && !big; reg += REG_STEP) {
		enum admission a0;
		unsigned int n0;

		if (run_plain(reg, &a0, &n0) == 1 && a0 == ADM_NAMED &&
		    n0 == 0)
			big = reg;
	}
	control(quad && pair_a && cross_a && defrej_a && orw && big,
		AUTH_KERNEL_SOURCE_DERIVED,
		"run registers derived: quad 0x%04X, pair 0x%04X, "
		"cross 0x%04X, default-reject 0x%04X, one-reg-wr 0x%04X, "
		"max-count 0x%04X", quad, pair_a, cross_a, defrej_a, orw,
		big);
	if (!(quad && pair_a && cross_a && defrej_a && orw && big))
		return;

	/* Four consuming registers under one header: the count field names
	 * count + 1 dwords and the switch dispatches every register in the
	 * run, so four relocations are consumed and a stream carrying three
	 * starves the last register's case.
	 */
	r = run_expect(quad, 3, 0, &e);
	if (r == 1 && !run_probe(quad, 3, 0, e, &v) && !v.tool_error) {
		control(v.accepted && v.relocs == e,
			AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X+3 normal run consumes %u relocations "
			"(got %s, %u)", quad, e,
			v.accepted ? "accept" : "reject", v.relocs);
	} else {
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X+3 normal run: derivation or replay failed",
			quad);
	}
	if (!run_probe(quad, 3, 0, 3, &v) && !v.tool_error)
		control(!v.accepted, AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X+3 with one relocation short starves the "
			"last register's case (got %s)", quad,
			v.accepted ? "accept" : "reject");
	else
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X+3 short-relocation probe failed", quad);

	/* A non-consuming register followed by a consuming one: one
	 * relocation, from the second register, so a walk that fails to
	 * advance, or advances four registers per dword, answers with the
	 * wrong count or verdict.
	 */
	r = run_expect(pair_a, 1, 0, &e);
	if (r == 1 && !run_probe(pair_a, 1, 0, e, &v) && !v.tool_error)
		control(v.accepted && v.relocs == e,
			AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X+1 run advances into its consuming neighbor "
			"(want %u relocations, got %s, %u)", pair_a, e,
			v.accepted ? "accept" : "reject", v.relocs);
	else
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X+1 heterogeneous run: derivation or replay "
			"failed", pair_a);

	/* A run crossing from a flagged register into unflagged space: the
	 * flagged register dispatches, the unflagged one passes unchecked,
	 * and the bitmap is consulted per register rather than once.
	 */
	r = run_expect(cross_a, 1, 0, &e);
	if (r == 1 && !run_probe(cross_a, 1, 0, e, &v) && !v.tool_error)
		control(v.accepted && v.relocs == e,
			AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X+1 run crosses the safe boundary unchecked "
			"(want %u relocations, got %s, %u)", cross_a, e,
			v.accepted ? "accept" : "reject", v.relocs);
	else
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X+1 boundary run: derivation or replay failed",
			cross_a);

	/* A run reaching a flagged-and-unnamed register rejects through the
	 * default arm, so the switch is consulted for every register in the
	 * run rather than the first.
	 */
	if (!run_probe(defrej_a, 1, 0, 1, &v) && !v.tool_error)
		control(!v.accepted, AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X+1 run rejects at its flagged-and-unnamed "
			"neighbor (got %s)", defrej_a,
			v.accepted ? "accept" : "reject");
	else
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X+1 default-arm run probe failed", defrej_a);

	/* ONE_REG_WR holds the register: three payload dwords on one
	 * consuming register take three relocations, a stream carrying two
	 * starves the third write, and the normal walk over the same header
	 * answers differently.
	 */
	if (!run_probe(orw, 2, 1, 3, &v) && !v.tool_error)
		control(v.accepted && v.relocs == 3,
			AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X ONE_REG_WR count=2 consumes three "
			"relocations (got %s, %u)", orw,
			v.accepted ? "accept" : "reject", v.relocs);
	else
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X ONE_REG_WR probe failed", orw);
	if (!run_probe(orw, 2, 1, 2, &v) && !v.tool_error)
		control(!v.accepted, AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X ONE_REG_WR with one relocation short "
			"starves the held register (got %s)", orw,
			v.accepted ? "accept" : "reject");
	else
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X ONE_REG_WR short probe failed", orw);
	r = run_expect(orw, 1, 0, &e2);
	if (!run_probe(orw, 1, 1, 2, &v) && !v.tool_error &&
	    !run_probe(orw, 1, 0, r == 1 ? e2 : 1, &v2) && !v2.tool_error)
		control(v.accepted && v.relocs == 2 &&
			(v2.accepted != v.accepted ||
			 v2.relocs != v.relocs),
			AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X count=1: held form (%s, %u) and normal form "
			"(%s, %u) separate", orw,
			v.accepted ? "accept" : "reject", v.relocs,
			v2.accepted ? "accept" : "reject", v2.relocs);
	else
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X held-vs-normal probe failed", orw);

	/* The bound forms at the maximum count field: a normal run of
	 * 0x4000 registers from zero leaves the bitmap's range and rejects
	 * before any dispatch; the held form checks its one register alone
	 * and iterates the full payload.
	 */
	if (!run_probe(0, 0x3FFF, 0, 0, &v) && !v.tool_error)
		control(!v.accepted, AUTH_KERNEL_SOURCE_DERIVED,
			"0x0000+0x3FFF normal run rejects on the whole-run "
			"bitmap bound (got %s)",
			v.accepted ? "accept" : "reject");
	else
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"maximum-count normal probe failed");
	if (!run_probe(big, 0x3FFF, 1, 0, &v) && !v.tool_error)
		control(v.accepted && v.relocs == 0,
			AUTH_KERNEL_SOURCE_DERIVED,
			"0x%04X ONE_REG_WR count=0x3FFF iterates 0x4000 "
			"payload dwords under the single-register bound "
			"(got %s, %u)", big,
			v.accepted ? "accept" : "reject", v.relocs);
	else
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"maximum-count held probe failed");

	/* Chunk-end framing: a packet whose last dword is the chunk's last
	 * dword is admitted, and a header claiming one dword more rejects.
	 * A maximum-count header over a payload one dword short is the same
	 * comparison at the far boundary.
	 */
	{
		struct stream s;

		memset(&s, 0, sizeof(s));
		stream_pkt0_run(&s, big, 0, 0, 0);
		if (!run_replay(&s, &v) && !v.tool_error)
			control(v.accepted, AUTH_KERNEL_SOURCE_DERIVED,
				"0x%04X packet ending exactly at the chunk "
				"end is admitted (got %s)", big,
				v.accepted ? "accept" : "reject");
		else
			control(0, AUTH_KERNEL_SOURCE_DERIVED,
				"exact-end probe failed");

		memset(&s, 0, sizeof(s));
		s.dw[s.ndw++] = (uint32_t)(big >> 2) | (1u << 16);
		s.dw[s.ndw++] = 0;
		if (!run_replay(&s, &v) && !v.tool_error)
			control(!v.accepted, AUTH_KERNEL_SOURCE_DERIVED,
				"0x%04X header claiming one dword past the "
				"chunk end rejects (got %s)", big,
				v.accepted ? "accept" : "reject");
		else
			control(0, AUTH_KERNEL_SOURCE_DERIVED,
				"past-end probe failed");

		memset(&s, 0, sizeof(s));
		s.dw[s.ndw++] = (uint32_t)(big >> 2) | (1u << 15) |
				(0x3FFFu << 16);
		for (reg = 0; reg < 0x3FFF; reg++)
			s.dw[s.ndw++] = 0;
		if (!run_replay(&s, &v) && !v.tool_error)
			control(!v.accepted, AUTH_KERNEL_SOURCE_DERIVED,
				"0x%04X maximum-count header over a payload "
				"one dword short rejects (got %s)", big,
				v.accepted ? "accept" : "reject");
		else
			control(0, AUTH_KERNEL_SOURCE_DERIVED,
				"short-payload maximum-count probe failed");
	}

	/* A type-2 packet advances one dword, so the consuming packet after
	 * it still finds its relocation.
	 */
	{
		struct stream s;

		memset(&s, 0, sizeof(s));
		s.dw[s.ndw++] = 0x80000000u;
		stream_pkt0_run(&s, orw, 0, 0, 0);
		stream_reloc_nop(&s, 0);
		if (!run_replay(&s, &v) && !v.tool_error)
			control(v.accepted && v.relocs == 1,
				AUTH_KERNEL_SOURCE_DERIVED,
				"type-2 advances one dword ahead of a "
				"consuming packet (got %s, %u)",
				v.accepted ? "accept" : "reject", v.relocs);
		else
			control(0, AUTH_KERNEL_SOURCE_DERIVED,
				"type-2 advancement probe failed");
	}
}

/* --- the exhaustive sweep --- */

/* Every register the bitmap covers, other than the ones the rows already
 * ran, is walked so the replay's admitted set is proven equal to the
 * kernel's named set rather than sampled at the registers this tool thought
 * to list.
 */
static void sweep(void)
{
	unsigned int reg;
	unsigned int checked = 0, mismatches = 0, reported = 0;
	unsigned int top = (safe_bm_entries * 32 * REG_STEP) - REG_STEP;

	for (reg = 0; reg <= top; reg += REG_STEP) {
		const struct kcase *k;
		enum admission adm = classify(reg, &k);
		struct stream s;
		struct verdict v;
		int want_accept;

		if (adm == ADM_NAMED || adm == ADM_RANGE_REJECT)
			continue;	/* covered by a row */
		want_accept = (adm == ADM_UNCHECKED);
		memset(&s, 0, sizeof(s));
		stream_pkt0(&s, reg, 0);
		stream_reloc_nop(&s, 0);
		if (run_replay(&s, &v) || v.tool_error) {
			mismatches++;
			continue;
		}
		checked++;
		if (v.accepted != want_accept ||
		    (want_accept && v.relocs != 0)) {
			mismatches++;
			if (reported < 8) {
				printf("       sweep 0x%04X %s expected %s "
				       "got %s relocs=%u\n", reg,
				       admission_name(adm),
				       want_accept ? "accept" : "reject",
				       v.accepted ? "accept" : "reject",
				       v.relocs);
				reported++;
			}
		}
	}
	control(mismatches == 0, AUTH_KERNEL_SOURCE_DERIVED,
		"sweep over 0x0000..0x%04X: %u registers outside the named "
		"cases answer their bitmap class, %u disagree", top, checked,
		mismatches);
}

int main(int argc, char **argv)
{
	const char *tree = ".";
	const char *replay = NULL;
	const char *workdir = NULL;
	const char *reg_safe_header = NULL;
	int do_sweep = 1;
	int arg;
	size_t i;

	setbuf(stdout, NULL);
	for (arg = 1; arg < argc; arg++) {
		if (strcmp(argv[arg], "--tree") == 0 && arg + 1 < argc)
			tree = argv[++arg];
		else if (strcmp(argv[arg], "--replay") == 0 && arg + 1 < argc)
			replay = argv[++arg];
		else if (strcmp(argv[arg], "--workdir") == 0 && arg + 1 < argc)
			workdir = argv[++arg];
		else if (strcmp(argv[arg], "--reg-safe-header") == 0 &&
			 arg + 1 < argc)
			reg_safe_header = argv[++arg];
		else if (strcmp(argv[arg], "--sweep") == 0 && arg + 1 < argc)
			do_sweep = atoi(argv[++arg]);
		else {
			fprintf(stderr,
				"usage: %s --tree DIR --replay PATH "
				"--workdir DIR [--reg-safe-header PATH] "
				"[--sweep 0|1]\n", argv[0]);
			return 2;
		}
	}
	if (!replay || !workdir) {
		fprintf(stderr, "--replay and --workdir are required\n");
		return 2;
	}
	if (chdir(tree)) {
		fprintf(stderr, "chdir %s: %s\n", tree, strerror(errno));
		return 2;
	}

	g_replay = replay;
	g_bundle = join(workdir, "correspondence_bundle.txt");
	g_ib = join(workdir, "correspondence_ib.bin");
	if (!g_bundle || !g_ib)
		return 2;
	{
		FILE *f = fopen(g_bundle, "w");

		if (!f) {
			fprintf(stderr, "open %s: %s\n", g_bundle,
				strerror(errno));
			return 2;
		}
		/* One buffer object, small enough that an armed color bound
		 * check refuses it, and the family the target host runs.
		 */
		fprintf(f, "family rs480\n");
		fprintf(f, "bo 0 role=probe size=16 read_domains=2 "
			"write_domain=0\n");
		fclose(f);
	}

	printf("r300 CS-grammar correspondence\n");
	printf("kernel sources:\n");
	printf("  drivers/gpu/drm/radeon/r300.c (r300_packet0_check)\n");
	printf("  drivers/gpu/drm/radeon/r100.c (r100_cs_track_clear)\n");
	printf("  drivers/gpu/drm/radeon/reg_srcs/r300 (safe register list)\n");
	printf("model under test: %s\n\n", replay);

	static const char *headers[] = {
		"drivers/gpu/drm/radeon/r300_reg.h",
		"drivers/gpu/drm/radeon/radeon_reg.h",
		"drivers/gpu/drm/radeon/r500_reg.h",
		"drivers/gpu/drm/radeon/r100_track.h",
	};

	for (i = 0; i < sizeof(headers) / sizeof(headers[0]); i++)
		if (symbols_load(headers[i]))
			return 2;

	if (safe_bitmap_build("drivers/gpu/drm/radeon/reg_srcs/r300"))
		return 2;
	if (kcases_load("drivers/gpu/drm/radeon/r300.c"))
		return 2;
	kcase_scan_bodies();

	printf("derivation:\n");
	control(nkcases > 0, AUTH_KERNEL_SOURCE_DERIVED,
		"r300_packet0_check names %zu registers across its top-level "
		"case labels", nkcases);
	control(safe_bm_entries > 0, AUTH_KERNEL_SOURCE_DERIVED,
		"reg_srcs/r300 rebuilds a %u-entry safe bitmap covering "
		"0x0000..0x%04X", safe_bm_entries,
		safe_bm_entries * 32 * REG_STEP - REG_STEP);
	if (reg_safe_header)
		check_bitmap_matches_generated(reg_safe_header);
	else
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"generated r300_reg_safe.h given for the equivalence "
			"check");

	printf("\ninitial tracking state (r100_cs_track_clear, R300 arm):\n");
	check_initial_state(".");

	printf("\nper-register rows:\n");
	for (i = 0; i < nkcases; i++) {
		char name[80];

		snprintf(name, sizeof(name), "%s", kcases[i].label);
		row(kcases[i].reg, name);
	}
	/* The two classes the named cases do not exercise. */
	row(0x2100, "flagged-and-unnamed");
	row(0x1434, "SRC_Y_X (safe list)");

	printf("\nnegative fixtures (wrong register number vs correct):\n");
	check_fixtures();

	printf("\nrun forms (r100_cs_parse_packet0 over multi-register "
	       "packets):\n");
	check_run_forms();

	printf("\n");
	if (do_sweep)
		sweep();
	else
		control(0, AUTH_KERNEL_SOURCE_DERIVED,
			"sweep skipped by --sweep 0");

	control(scope_cut_count == 1, AUTH_KERNEL_SOURCE_DERIVED,
		"scope cuts pinned at 1 (RADEON_CRTC_GUI_TRIG_VLINE reaches "
		"r100_cs_packet_parse_vline), found %u", scope_cut_count);

	/* The case list this tool resolved, one line per label, so a second
	 * extraction can diff against it without parsing this report.
	 */
	printf("\n");
	for (i = 0; i < nkcases; i++)
		printf("KCASE 0x%04x %s\n", kcases[i].reg, kcases[i].label);

	printf("\nauthority classes: KERNEL_SOURCE_DERIVED %u, "
	       "MODEL_INTERNAL %u, RUNNING_KERNEL %u\n",
	       auth_kernel_rows, auth_model_rows, auth_running_rows);
	printf("controls: PASS %u, FAIL %u, SCOPE_CUT %u\n",
	       pass_count, fail_count, scope_cut_count);
	if (fail_count) {
		printf("r300_cs_grammar_correspondence: %u controls did not "
		       "hold\n", fail_count);
		return 1;
	}
	printf("r300_cs_grammar_correspondence: every control held\n");
	return 0;
}

/* Four register numbers are permanent fixtures because each one has a
 * near neighbor the safe bitmap leaves clear or the switch does not name:
 * a number transcribed rather than read out of the tree lands on a different
 * admission class, where the case that should own it becomes dead code and
 * the relocation it should consume shifts every later relocation onto the
 * wrong buffer object.
 */
_Static_assert(sizeof(fixtures) / sizeof(fixtures[0]) == 4,
	       "the four negative register-number fixtures are permanent");
