/**
 * @file sha256d_opencl.cl
 * @brief Optimized OpenCL kernel for SHA-256d mining (DineroCoin)
 *
 * This kernel performs double SHA-256 hashing for cryptocurrency mining.
 * Optimized for AMD GCN/RDNA and Intel GPUs, with portable NVIDIA support.
 *
 * Input: 128-byte block header (BlockHeader v1) + 256-bit target
 * Output: Nonce that produces hash < target (if found)
 *
 * Architecture: SHA-256d = SHA-256(SHA-256(header + nonce))
 * DineroCoin BlockHeader v1: 128 bytes with Utreexo commitment
 */

// SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
__constant uint K[64] = {
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
__constant uint H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Rotate right macro
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// SHA-256 functions
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x)       (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x)      (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/**
 * @brief SHA-256 compression function (single block)
 *
 * @param state Current hash state (8 x 32-bit words)
 * @param block Input block (16 x 32-bit words, big-endian)
 */
void sha256_transform(uint *state, const uint *block) {
    uint W[64];
    uint a, b, c, d, e, f, g, h;
    uint t1, t2;
    int i;

    // Prepare message schedule (expand 16 words to 64)
    for (i = 0; i < 16; i++) {
        W[i] = block[i];
    }
    for (i = 16; i < 64; i++) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
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
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + W[i];
        t2 = EP0(a) + MAJ(a, b, c);
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
 * @brief Convert uint32 from little-endian to big-endian
 */
inline uint swap_endian(uint x) {
    return ((x << 24) & 0xFF000000) |
           ((x <<  8) & 0x00FF0000) |
           ((x >>  8) & 0x0000FF00) |
           ((x >> 24) & 0x000000FF);
}

/**
 * @brief Check if hash meets target difficulty
 *
 * @param hash Hash to check (8 x 32-bit words, big-endian)
 * @param target Target difficulty (8 x 32-bit words, big-endian)
 * @return 1 if hash < target, 0 otherwise
 */
int hash_meets_target(const uint *hash, __global const uint *target) {
    // Compare hash against target (big-endian, most significant word first)
    for (int i = 7; i >= 0; i--) {
        if (hash[i] < target[i]) return 1;
        if (hash[i] > target[i]) return 0;
    }
    return 0; // hash == target (not valid)
}

/**
 * @brief OpenCL kernel for SHA-256d mining (DineroCoin BlockHeader v1 - 128 bytes)
 *
 * Each work item tries one nonce value:
 * - nonce = nonce_start + global_id
 * - Performs SHA-256d(header + nonce)
 * - If hash < target, writes result
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
 *
 * @param header Block header (32 x 32-bit words = 128 bytes, little-endian)
 * @param target Difficulty target (8 x 32-bit words, big-endian)
 * @param nonce_start Starting nonce value
 * @param result_nonce Output: winning nonce (if found)
 * @param result_found Output: 1 if solution found, 0 otherwise
 */
__kernel void sha256d_mine(
    __global const uint *header,        // 128-byte block header (little-endian)
    __global const uint *target,        // 256-bit target (big-endian)
    uint nonce_start,                   // Starting nonce value
    __global uint *result_nonce,        // Output: winning nonce
    __global uint *result_found         // Output: found flag
) {
    // Calculate this work item's nonce
    uint nonce = nonce_start + get_global_id(0);

    // SHA-256 processes 64-byte blocks. 128-byte header = 2 blocks.
    // Block 1: bytes 0-63   (words 0-15)
    // Block 2: bytes 64-127 (words 16-31), nonce is at word 28

    uint block1[16];

    // Copy header words 0-15 (first 64 bytes), convert to big-endian
    for (int i = 0; i < 16; i++) {
        block1[i] = swap_endian(header[i]);
    }

    // Prepare second block (bytes 64-127)
    uint block2[16];

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
    uint state1[8];
    for (int i = 0; i < 8; i++) {
        state1[i] = H[i];
    }
    sha256_transform(state1, block1);
    sha256_transform(state1, block2);

    // Now we need to finalize the first SHA-256 with padding
    // Padding block for 128-byte message: 0x80 + zeros + length (1024 bits)
    uint pad_block[16];
    pad_block[0] = 0x80000000;  // 0x80 byte followed by zeros
    for (int i = 1; i < 14; i++) {
        pad_block[i] = 0;
    }
    pad_block[14] = 0;          // High 32 bits of length (0 for < 2^32 bits)
    pad_block[15] = 1024;       // Low 32 bits: 128 bytes = 1024 bits

    sha256_transform(state1, pad_block);

    // Second SHA-256 (hash the 32-byte output of first SHA-256)
    uint block3[16];

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

    uint state2[8];
    for (int i = 0; i < 8; i++) {
        state2[i] = H[i];
    }
    sha256_transform(state2, block3);

    // Check if final hash meets target
    if (hash_meets_target(state2, target)) {
        // Found a valid solution!
        // Use atomic to prevent race condition (only first finder writes)
        uint old = atomic_cmpxchg(result_found, 0, 1);
        if (old == 0) {
            // We're the first to find it
            *result_nonce = nonce;
        }
    }
}
