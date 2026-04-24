/**
 * @file sha256d_metal.metal
 * @brief Metal compute kernel for SHA-256d mining (DineroCoin)
 *
 * This kernel performs double SHA-256 hashing for cryptocurrency mining.
 * Optimized for Apple Silicon GPUs (M1/M2/M3/M4) via Metal Shading Language.
 *
 * Input: 128-byte block header (BlockHeader v1) + 256-bit target
 * Output: Nonce that produces hash < target (if found)
 *
 * Architecture: SHA-256d = SHA-256(SHA-256(header + nonce))
 * DineroCoin BlockHeader v1: 128 bytes with Utreexo commitment
 *
 * DineroCoin BlockHeader v1 (128 bytes):
 *   [0-3]:     version (4 bytes)
 *   [4-35]:    prev_block_hash (32 bytes)
 *   [36-67]:   merkle_root (32 bytes)
 *   [68-99]:   utreexo_root (32 bytes)
 *   [100-107]: timestamp (8 bytes)
 *   [108-111]: difficulty (4 bytes)
 *   [112-115]: nonce (4 bytes) <-- MINERS MODIFY THIS
 *   [116-127]: reserved (12 bytes, MUST be zero)
 */

#include <metal_stdlib>
using namespace metal;

// SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
constant uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
constant uint32_t H_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Rotate right
inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// SHA-256 functions
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t ep0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t ep1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t sig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t sig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

/**
 * @brief Convert uint32 from little-endian to big-endian
 */
inline uint32_t swap_endian(uint32_t x) {
    return ((x << 24) & 0xFF000000) |
           ((x <<  8) & 0x00FF0000) |
           ((x >>  8) & 0x0000FF00) |
           ((x >> 24) & 0x000000FF);
}

/**
 * @brief SHA-256 compression function (single 64-byte block)
 *
 * @param state Current hash state (8 x 32-bit words), modified in place
 * @param block Input block (16 x 32-bit words, big-endian)
 */
void sha256_transform(thread uint32_t* state, thread uint32_t* block) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;

    // Prepare message schedule (expand 16 words to 64)
    for (int i = 0; i < 16; i++) {
        W[i] = block[i];
    }
    for (int i = 16; i < 64; i++) {
        W[i] = sig1(W[i - 2]) + W[i - 7] + sig0(W[i - 15]) + W[i - 16];
    }

    // Initialize working variables
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    // Main compression loop (64 rounds)
    for (int i = 0; i < 64; i++) {
        t1 = h + ep1(e) + ch(e, f, g) + K[i] + W[i];
        t2 = ep0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Add compressed chunk to current hash value
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

/**
 * @brief Check if hash meets target difficulty
 *
 * @param hash Hash to check (8 x 32-bit words, big-endian)
 * @param target Target difficulty (8 x 32-bit words, big-endian)
 * @return true if hash < target
 */
bool hash_meets_target(thread uint32_t* hash, device const uint32_t* target) {
    // Compare hash against target (MSW-first). SHA-256 standard output
    // places the first 4 bytes of the digest in hash[0]; with target also
    // laid out MSW-first (target[0] = most-significant 4 bytes of the
    // 256-bit target), this gives a correct byte-wise lexicographic
    // comparison of the raw hash against the raw target.
    for (int i = 0; i < 8; i++) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return false; // hash == target (not valid)
}

/**
 * @brief Metal compute kernel for SHA-256d mining (DineroCoin BlockHeader v1 - 128 bytes)
 *
 * Each thread tries one nonce value:
 * - nonce = nonce_start + thread_position
 * - Performs SHA-256d(header with nonce inserted)
 * - If hash < target, writes result atomically
 *
 * @param header Block header (32 x uint32 = 128 bytes, little-endian)
 * @param target Difficulty target (8 x uint32, big-endian)
 * @param result_nonce Output: winning nonce (if found)
 * @param result_found Output: 1 if solution found, 0 otherwise
 * @param nonce_start Starting nonce value (passed as single-element buffer)
 * @param gid Thread position in grid
 */
kernel void sha256d_mine(
    device const uint32_t* header        [[buffer(0)]],  // 128-byte block header (LE)
    device const uint32_t* target        [[buffer(1)]],  // 256-bit target (BE)
    device atomic_uint*    result_nonce  [[buffer(2)]],  // Output: winning nonce
    device atomic_uint*    result_found  [[buffer(3)]],  // Output: found flag
    device const uint32_t* nonce_start_buf [[buffer(4)]], // Starting nonce
    uint                   gid           [[thread_position_in_grid]])
{
    // Calculate this thread's nonce
    uint32_t nonce = nonce_start_buf[0] + gid;

    // SHA-256 processes 64-byte blocks. 128-byte header = 2 blocks.
    // Block 1: bytes 0-63   (words 0-15)
    // Block 2: bytes 64-127 (words 16-31), nonce is at word 28

    uint32_t block1[16];

    // Copy header words 0-15 (first 64 bytes), convert to big-endian
    for (int i = 0; i < 16; i++) {
        block1[i] = swap_endian(header[i]);
    }

    // Prepare second block (bytes 64-127)
    uint32_t block2[16];

    // Words 16-27 (bytes 64-111, before nonce)
    for (int i = 0; i < 12; i++) {
        block2[i] = swap_endian(header[16 + i]);
    }

    // Word 28 is the nonce (offset 112) - we modify this
    block2[12] = swap_endian(nonce);

    // Words 29-31 are reserved (offset 116-127, should be zero)
    block2[13] = swap_endian(header[29]);
    block2[14] = swap_endian(header[30]);
    block2[15] = swap_endian(header[31]);

    // First SHA-256 on 128-byte header (two blocks)
    uint32_t state1[8];
    for (int i = 0; i < 8; i++) {
        state1[i] = H_INIT[i];
    }
    sha256_transform(state1, block1);
    sha256_transform(state1, block2);

    // Finalize the first SHA-256 with padding
    // Padding block for 128-byte message: 0x80 + zeros + length (1024 bits)
    uint32_t pad_block[16];
    pad_block[0] = 0x80000000;  // 0x80 byte followed by zeros
    for (int i = 1; i < 14; i++) {
        pad_block[i] = 0;
    }
    pad_block[14] = 0;          // High 32 bits of length
    pad_block[15] = 1024;       // Low 32 bits: 128 bytes = 1024 bits

    sha256_transform(state1, pad_block);

    // Second SHA-256 (hash the 32-byte output of first SHA-256)
    uint32_t block3[16];

    // First 8 words are the output of first SHA-256
    for (int i = 0; i < 8; i++) {
        block3[i] = state1[i];
    }

    // SHA-256 padding for 32-byte input
    block3[8] = 0x80000000;
    block3[9] = 0;
    block3[10] = 0;
    block3[11] = 0;
    block3[12] = 0;
    block3[13] = 0;
    block3[14] = 0;
    block3[15] = 256; // Message length: 32 bytes = 256 bits

    uint32_t state2[8];
    for (int i = 0; i < 8; i++) {
        state2[i] = H_INIT[i];
    }
    sha256_transform(state2, block3);

    // Check if final hash meets target
    if (hash_meets_target(state2, target)) {
        // Found a valid solution!
        // Use atomic to prevent race condition (only first finder writes)
        uint expected = 0;
        if (atomic_compare_exchange_weak_explicit(result_found, &expected, 1u,
                memory_order_relaxed, memory_order_relaxed)) {
            // We're the first to find it
            atomic_store_explicit(result_nonce, nonce, memory_order_relaxed);
        }
    }
}
