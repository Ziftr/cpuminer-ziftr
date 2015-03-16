/*
 * Copyright 2014 mkimid
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
 /*
***** ZiftrCOIN Hashing Algo Module  by ocminer (admin at suprnova.cc)  ******
*/
/*
 * Further modified by Stephen Morse and Justin Wilcox
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#define USE_SPH_KECCAK 1  // Don't comment this out unless fixed for 80 byte input
// #define USE_SPH_BLAKE 1   // Works
#define USE_SPH_GROESTL 1 // Works on windows
// #define USE_SPH_JH 1      // Works
// #define USE_SPH_SKEIN 1   // Works

#ifdef USE_SPH_KECCAK
#include "sph_keccak.h"
#else
#include "algos/keccak.c"
#endif

#ifdef USE_SPH_BLAKE
#include "sph_blake.h"
#else
#include "algos/blake.c"
#endif

#ifdef USE_SPH_GROESTL
#include "sph_groestl.h"
#else
#include "algos/grso.c"
#include "algos/grso-asm.c"
#endif

#ifdef USE_SPH_JH
#include "sph_jh.h"
#else
#include "algos/jh_sse2_opt64.h"
#endif

#ifdef USE_SPH_SKEIN
#include "sph_skein.h"
#else
#include "algos/skein.c"
#endif
 
#define POK_BOOL_MASK 0x00008000
#define POK_DATA_MASK 0xFFFF0000

#if defined(__GNUC__)
      #define DATA_ALIGN16(x) x __attribute__ ((aligned(16)))
#else
      #define DATA_ALIGN16(x) __declspec(align(16)) x
#endif

// Pre-computed table of permutations
static const int arrOrder[][4] =
{
    {0, 1, 2, 3},
    {0, 1, 3, 2},
    {0, 2, 1, 3},
    {0, 2, 3, 1},
    {0, 3, 1, 2},
    {0, 3, 2, 1},
    {1, 0, 2, 3},
    {1, 0, 3, 2},
    {1, 2, 0, 3},
    {1, 2, 3, 0},
    {1, 3, 0, 2},
    {1, 3, 2, 0},
    {2, 0, 1, 3},
    {2, 0, 3, 1},
    {2, 1, 0, 3},
    {2, 1, 3, 0},
    {2, 3, 0, 1},
    {2, 3, 1, 0},
    {3, 0, 1, 2},
    {3, 0, 2, 1},
    {3, 1, 0, 2},
    {3, 1, 2, 0},
    {3, 2, 0, 1},
    {3, 2, 1, 0}
};

static void ziftrhash(void *state, const void *input)
{
    DATA_ALIGN16(unsigned char hashbuf[128]);
    DATA_ALIGN16(unsigned char hash[128]);

#if !defined(USE_SPH_BLAKE) || !defined(USE_SPH_SKEIN)
    DATA_ALIGN16(size_t hashptr);
    DATA_ALIGN16(sph_u64 hashctA);
#endif

#if !defined(USE_SPH_BLAKE)
    DATA_ALIGN16(sph_u64 hashctB);
#endif

#ifdef USE_SPH_KECCAK
    sph_keccak512_context    ctx_keccak;
#endif

#ifdef USE_SPH_BLAKE
    sph_blake512_context     ctx_blake;
#endif

#ifdef USE_SPH_GROESTL
    sph_groestl512_context   ctx_groestl;
#else
    grsoState sts_grs;
#endif

#ifdef USE_SPH_JH
    sph_jh512_context        ctx_jh;
#endif

#ifdef USE_SPH_SKEIN
    sph_skein512_context     ctx_skein;
#endif

#ifdef USE_SPH_KECCAK
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, input, 80);
    sph_keccak512_close(&ctx_keccak, (&hash));
#else
{
    // I believe this is optimized for 64 length input,
    // so probably won't work for zrc, since we use
    // input of length 80 here
    DECL_KEC;
    KEC_I;
    KEC_U;
    KEC_C;
}
#endif

    unsigned int nOrder = *(unsigned int *)(&hash) % 24;

    unsigned int i = 0;

    for (i = 0; i < 4; i++)
    {

        switch (arrOrder[nOrder][i])
        {
        case 0:
#ifdef USE_SPH_BLAKE
            sph_blake512_init(&ctx_blake);
            sph_blake512 (&ctx_blake, (&hash), 64);
            sph_blake512_close(&ctx_blake, (&hash));
#else
        {
            DECL_BLK;
            BLK_I;
            BLK_U;
            BLK_C;
        }
#endif
            break;

        case 1:
#ifdef USE_SPH_GROESTL
            sph_groestl512_init(&ctx_groestl);
            sph_groestl512 (&ctx_groestl, (&hash), 64);
            sph_groestl512_close(&ctx_groestl, (&hash));
#else
        {
            GRS_I; // init
            GRS_U; // update
            GRS_C; // close
        }
#endif
            break;

        case 2:
#ifdef USE_SPH_JH
            sph_jh512_init(&ctx_jh);
            sph_jh512 (&ctx_jh, (&hash), 64);
            sph_jh512_close(&ctx_jh, (&hash));
#else
        {
            DECL_JH;
            JH_H;
        }
#endif

            break;
        case 3:
#ifdef USE_SPH_SKEIN
            sph_skein512_init(&ctx_skein);
            sph_skein512 (&ctx_skein, (&hash), 64);
            sph_skein512_close(&ctx_skein, (&hash));
#else
        {
            DECL_SKN;
            SKN_I;
            SKN_U;
            SKN_C;
        }
#endif
            break;
        default:
            break;
        }
    }

#ifndef USE_SPH_GROESTL
    asm volatile ("emms");
#endif
	memcpy(state, hash, 32);
}

int scanhash_ziftr(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{

	uint32_t hash[16] __attribute__((aligned(64)));
	uint32_t tmpdata[20] __attribute__((aligned(64)));

    const uint32_t version = pdata[0] & (~POK_DATA_MASK);
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
 
	memcpy(tmpdata, pdata, 80);
 
	do {
		#define Htarg ptarget[7]
 
		tmpdata[0]  = version;
		tmpdata[19] = nonce;
		ziftrhash(hash, tmpdata);
		tmpdata[0] = version | (hash[0] & POK_DATA_MASK);
		ziftrhash(hash, tmpdata);
 
		if (hash[7] <= Htarg && fulltest(hash, ptarget))
		{
			pdata[0] = tmpdata[0];
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce + 1;
			if (opt_debug)
				applog(LOG_INFO, "found nonce %x", nonce);

            return 1;
		}
		nonce++;
 
	} while (nonce < max_nonce && !work_restart[thr_id].restart);
 
	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;

}

