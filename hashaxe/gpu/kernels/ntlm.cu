/**
 * hashaxe/gpu/kernels/ntlm.cu
 * Optimized CUDA NTLM (MD4) Kernel
 *
 * Target: fast hash NTLM hashaxeing via MD4 of UTF-16LE passwords
 * GANGA Offensive Ops · HashAxe V3
 */

#include <stdint.h>

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

__device__ void md4_transform(uint32_t state[4], const uint8_t block[64]) {
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint32_t x[16];

  // Load words
  for (int i = 0; i < 16; ++i) {
    x[i] = ((uint32_t)block[i * 4]) | (((uint32_t)block[i * 4 + 1]) << 8) |
           (((uint32_t)block[i * 4 + 2]) << 16) |
           (((uint32_t)block[i * 4 + 3]) << 24);
  }

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

// Round 1
#define FF(a, b, c, d, x, s)                                                   \
  {                                                                            \
    (a) += F((b), (c), (d)) + (x);                                             \
    (a) = LEFTROTATE((a), (s));                                                \
  }
  FF(a, b, c, d, x[0], 3);
  FF(d, a, b, c, x[1], 7);
  FF(c, d, a, b, x[2], 11);
  FF(b, c, d, a, x[3], 19);
  FF(a, b, c, d, x[4], 3);
  FF(d, a, b, c, x[5], 7);
  FF(c, d, a, b, x[6], 11);
  FF(b, c, d, a, x[7], 19);
  FF(a, b, c, d, x[8], 3);
  FF(d, a, b, c, x[9], 7);
  FF(c, d, a, b, x[10], 11);
  FF(b, c, d, a, x[11], 19);
  FF(a, b, c, d, x[12], 3);
  FF(d, a, b, c, x[13], 7);
  FF(c, d, a, b, x[14], 11);
  FF(b, c, d, a, x[15], 19);

// Round 2
#define GG(a, b, c, d, x, s)                                                   \
  {                                                                            \
    (a) += G((b), (c), (d)) + (x) + 0x5a827999;                                \
    (a) = LEFTROTATE((a), (s));                                                \
  }
  GG(a, b, c, d, x[0], 3);
  GG(d, a, b, c, x[4], 5);
  GG(c, d, a, b, x[8], 9);
  GG(b, c, d, a, x[12], 13);
  GG(a, b, c, d, x[1], 3);
  GG(d, a, b, c, x[5], 5);
  GG(c, d, a, b, x[9], 9);
  GG(b, c, d, a, x[13], 13);
  GG(a, b, c, d, x[2], 3);
  GG(d, a, b, c, x[6], 5);
  GG(c, d, a, b, x[10], 9);
  GG(b, c, d, a, x[14], 13);
  GG(a, b, c, d, x[3], 3);
  GG(d, a, b, c, x[7], 5);
  GG(c, d, a, b, x[11], 9);
  GG(b, c, d, a, x[15], 13);

// Round 3
#define HH(a, b, c, d, x, s)                                                   \
  {                                                                            \
    (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1;                                \
    (a) = LEFTROTATE((a), (s));                                                \
  }
  HH(a, b, c, d, x[0], 3);
  HH(d, a, b, c, x[8], 9);
  HH(c, d, a, b, x[4], 11);
  HH(b, c, d, a, x[12], 15);
  HH(a, b, c, d, x[2], 3);
  HH(d, a, b, c, x[10], 9);
  HH(c, d, a, b, x[6], 11);
  HH(b, c, d, a, x[14], 15);
  HH(a, b, c, d, x[1], 3);
  HH(d, a, b, c, x[9], 9);
  HH(c, d, a, b, x[5], 11);
  HH(b, c, d, a, x[13], 15);
  HH(a, b, c, d, x[3], 3);
  HH(d, a, b, c, x[11], 9);
  HH(c, d, a, b, x[7], 11);
  HH(b, c, d, a, x[15], 15);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

__global__ void ntlm_hashaxeKernel(const uint8_t *candidates,
                                   const int *lengths, int num_candidates,
                                   const uint32_t *target_hash,
                                   int *d_found_idx) {
  int idx = blockIdx.x * blockDim.x + threadIdx.x;
  if (idx >= num_candidates)
    return;

  if (*d_found_idx >= 0)
    return; // Already found

  const uint8_t *word = &candidates[idx * 64];
  int len = lengths[idx];

  // Initialize MD4 state
  uint32_t state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

  // Create 64-byte block with padding (NTLM uses UTF-16LE, so each char is 2
  // bytes)
  uint8_t block[64] = {0};
  int utf16_len = len * 2;

  for (int i = 0; i < len; ++i) {
    block[i * 2] = word[i];
    block[i * 2 + 1] = 0x00;
  }
  block[utf16_len] = 0x80;

  // Append length in bits
  uint64_t bits = utf16_len * 8;
  block[56] = bits & 0xFF;
  block[57] = (bits >> 8) & 0xFF;
  block[58] = (bits >> 16) & 0xFF;
  block[59] = (bits >> 24) & 0xFF;

  md4_transform(state, block);

  if (state[0] == target_hash[0] && state[1] == target_hash[1] &&
      state[2] == target_hash[2] && state[3] == target_hash[3]) {
    atomicCAS(d_found_idx, -1, idx);
  }
}
