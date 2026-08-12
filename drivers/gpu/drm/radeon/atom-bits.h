/*
 * Copyright 2008 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Author: Stanislaw Skowronek
 */

#ifndef ATOM_BITS_H
#define ATOM_BITS_H

static inline bool atom_span_valid(struct atom_context *ctx, int ptr,
				   size_t length)
{
	if (ptr < 0 || (size_t)ptr < ctx->bios_read_start ||
	    (size_t)ptr > ctx->bios_read_limit ||
	    length > ctx->bios_read_limit - (size_t)ptr) {
		ctx->io_error = true;
		return false;
	}

	return true;
}

static inline bool atom_bios_span_valid(struct atom_context *ctx, int ptr,
					size_t length)
{
	if (ptr < 0 || (size_t)ptr > ctx->bios_size ||
	    length > ctx->bios_size - (size_t)ptr) {
		ctx->io_error = true;
		return false;
	}

	return true;
}

static inline uint8_t get_u8(struct atom_context *ctx, int ptr)
{
	if (!atom_span_valid(ctx, ptr, sizeof(uint8_t)))
		return 0;

	return ((uint8_t *)ctx->bios)[ptr];
}

static inline uint16_t get_u16(struct atom_context *ctx, int ptr)
{
	if (!atom_span_valid(ctx, ptr, sizeof(uint16_t)))
		return 0;

	return get_unaligned_le16((uint8_t *)ctx->bios + ptr);
}

static inline uint32_t get_u32(struct atom_context *ctx, int ptr)
{
	if (!atom_span_valid(ctx, ptr, sizeof(uint32_t)))
		return 0;

	return get_unaligned_le32((uint8_t *)ctx->bios + ptr);
}

static inline uint8_t get_bios_u8(struct atom_context *ctx, int ptr)
{
	if (!atom_bios_span_valid(ctx, ptr, sizeof(uint8_t)))
		return 0;

	return ((uint8_t *)ctx->bios)[ptr];
}

static inline uint16_t get_bios_u16(struct atom_context *ctx, int ptr)
{
	if (!atom_bios_span_valid(ctx, ptr, sizeof(uint16_t)))
		return 0;

	return get_unaligned_le16((uint8_t *)ctx->bios + ptr);
}

static inline uint32_t get_bios_u32(struct atom_context *ctx, int ptr)
{
	if (!atom_bios_span_valid(ctx, ptr, sizeof(uint32_t)))
		return 0;

	return get_unaligned_le32((uint8_t *)ctx->bios + ptr);
}

#define U8(ptr) get_u8(ctx->ctx, (ptr))
#define CU8(ptr) get_bios_u8(ctx, (ptr))
#define U16(ptr) get_u16(ctx->ctx, (ptr))
#define CU16(ptr) get_bios_u16(ctx, (ptr))
#define U32(ptr) get_u32(ctx->ctx, (ptr))
#define CU32(ptr) get_bios_u32(ctx, (ptr))

#endif
