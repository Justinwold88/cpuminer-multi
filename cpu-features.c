/*
 * Which instruction set extensions the processor has, and the operating
 * system supports, for the code that picks its implementation at run time.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#include "miner.h"

#if (defined(__x86_64__) || defined(__i386__)) && \
	(defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5))
#include <cpuid.h>

#define CPU_X86 1

/* cpuid leaf 1 ecx/edx, leaf 7 ebx, and XCR0 (the registers the system
 * saves) */
static void cpu_x86_features(unsigned *ecx1, unsigned *edx1, unsigned *ebx7,
		unsigned *xcr0)
{
	unsigned eax, ebx, ecx, edx, lo = 0, hi = 0;

	*ecx1 = *edx1 = *ebx7 = *xcr0 = 0;
	if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
		return;
	*ecx1 = ecx;
	*edx1 = edx;
	if (ecx & (1u << 27)) {		/* OSXSAVE: XGETBV works */
		__asm__ ("xgetbv" : "=a" (lo), "=d" (hi) : "c" (0));
		*xcr0 = lo;
	}
	if (__get_cpuid_max(0, NULL) >= 7) {
		__cpuid_count(7, 0, eax, ebx, ecx, edx);
		*ebx7 = ebx;
	}
	(void) hi;
}
#endif

bool cpu_has_sse2(void)
{
#if defined(__SSE2__)
	return true;
#elif defined(CPU_X86)
	unsigned ecx1, edx1, ebx7, xcr0;

	cpu_x86_features(&ecx1, &edx1, &ebx7, &xcr0);
	return (edx1 & (1u << 26)) != 0;
#else
	return false;
#endif
}

/* AVX2, with the AVX registers saved by the system */
bool cpu_has_avx2(void)
{
#ifdef CPU_X86
	unsigned ecx1, edx1, ebx7, xcr0;

	cpu_x86_features(&ecx1, &edx1, &ebx7, &xcr0);
	return (ecx1 & (1u << 28))		/* AVX */
		&& (xcr0 & 0x6) == 0x6		/* XMM and YMM state */
		&& (ebx7 & (1u << 5));		/* AVX2 */
#else
	return false;
#endif
}

/* AVX-512 Foundation and Vector Length extensions (and AVX2), with the
 * AVX-512 registers saved by the system */
bool cpu_has_avx512vl(void)
{
#ifdef CPU_X86
	unsigned ecx1, edx1, ebx7, xcr0;

	cpu_x86_features(&ecx1, &edx1, &ebx7, &xcr0);
	return cpu_has_avx2()
		&& (xcr0 & 0xe6) == 0xe6	/* and opmask, ZMM state */
		&& (ebx7 & (1u << 16))		/* AVX512F */
		&& (ebx7 & (1u << 31));		/* AVX512VL */
#else
	return false;
#endif
}
