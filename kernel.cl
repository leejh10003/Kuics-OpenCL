#include "kernel.h"
__kernel void JV_SEED_CBC128_Decrypt_OneBlock(__global uchar *in,
											  __global uchar *out,
											  __global const uint *K,
											  __global uchar* ivec)
{
	__private size_t n;
	__private uchar tmp[16];
	__private uint* midtmp;
	__private uint L0, L1, R0, R1;		// Iuput/output values at each rounds
	__private uint T0, T1;				// Temporary variables for round function F
	__private uint idx = get_global_id(0) + get_global_size(0) * (get_global_id(1) + get_local_size(1) * get_local_id(2)); //Getting Thread ID
	__global uchar* convertIn = in + idx * SeedBlockSize;//Converted input address
	__global uchar* convertOut = out + idx * SeedBlockSize;//Converted output address

// Set up input values for first round
	L0 = ((uint *)convertIn)[0];
	L1 = ((uint *)convertIn)[1];
	R0 = ((uint *)convertIn)[2];
	R1 = ((uint *)convertIn)[3];

// Reorder for big endian
	if (__ENDIAN_LITTLE__){
		L0 = EndianChange(L0);
		L1 = EndianChange(L1);
		R0 = EndianChange(R0);
		R1 = EndianChange(R1);
	}

	SeedRound(L0, L1, R0, R1, K+30); 	// Round 1
	SeedRound(R0, R1, L0, L1, K+28); 	// Round 2
	SeedRound(L0, L1, R0, R1, K+26); 	// Round 3
	SeedRound(R0, R1, L0, L1, K+24); 	// Round 4
	SeedRound(L0, L1, R0, R1, K+22); 	// Round 5
	SeedRound(R0, R1, L0, L1, K+20); 	// Round 6
	SeedRound(L0, L1, R0, R1, K+18); 	// Round 7
	SeedRound(R0, R1, L0, L1, K+16); 	// Round 8
	SeedRound(L0, L1, R0, R1, K+14); 	// Round 9
	SeedRound(R0, R1, L0, L1, K+12); 	// Round 10
	SeedRound(L0, L1, R0, R1, K+10); 	// Round 11
	SeedRound(R0, R1, L0, L1, K+ 8); 	// Round 12
	SeedRound(L0, L1, R0, R1, K+ 6); 	// Round 13
	SeedRound(R0, R1, L0, L1, K+ 4); 	// Round 14
	SeedRound(L0, L1, R0, R1, K+ 2); 	// Round 15
	SeedRound(R0, R1, L0, L1, K+ 0); 	// Round 16

	if(__ENDIAN_LITTLE__){
		L0 = EndianChange(L0);
		L1 = EndianChange(L1);
		R0 = EndianChange(R0);
		R1 = EndianChange(R1);
	}

// Copy output values from last round to pbData
	midtmp = (uint *)tmp;
	midtmp[0] = R0;
	midtmp[1] = R1;
	midtmp[2] = L0;
	midtmp[3] = L1;

// CBC - IV XOR TMP_OUT
	for (n = 0; n < SeedBlockSize; ++n)
		convertOut[n] = tmp[n] ^ (idx == 0 ? ivec[n] : (convertIn - SeedBlockSize)[n]);
}