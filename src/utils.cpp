
#include "../deps.hpp"
#include "utils.hpp"

uint16_t RandomGen::obj_num = 0;

RandomGen::RandomGen(uint64_t seed) {
    s[0] = splitmix64(seed);
    s[1] = splitmix64(s[0]);

    /* TODO: Not sure this make non-overlapping sequences.
     * Probably should somehow use long_jump()  */
    for (int i = 0; i < obj_num; i++)
        jump();
    obj_num++;
}

uint64_t RandomGen::next() {
    const uint64_t s0 = s[0];
    uint64_t s1 = s[1];
    const uint64_t result = s0 + s1;

    s1 ^= s0;
    s[0] = rotl(s0, 24) ^ s1 ^ (s1 << 16);
    s[1] = rotl(s1, 37);
    return result;
}

/* equivalent to 2^64 call to next */
void RandomGen::jump() {
    static const uint64_t JUMP[] = { 0xdf900294d8f554a5, 0x170865df4b3201fc };
    uint64_t s0 = 0;
    uint64_t s1 = 0;
    for (unsigned int i = 0; i < sizeof(JUMP) / sizeof(*JUMP); i++)
        for (int b = 0; b < 64; b++) {
            if (JUMP[i] & UINT64_C(1) << b) {
                s0 ^= s[0];
                s1 ^= s[1];
            }
            next();
        }
    s[0] = s0;
    s[1] = s1;
}

/* equivalent to 2^96 call to next */
void RandomGen::long_jump() {
    static const uint64_t LONG_JUMP[] = { 0xd2a98b26625eee7b, 0xdddf9b1090aa7ac1 };
    uint64_t s0 = 0;
    uint64_t s1 = 0;
    for (unsigned int i = 0; i < sizeof(LONG_JUMP) / sizeof(*LONG_JUMP); i++)
        for (int b = 0; b < 64; b++) {
            if (LONG_JUMP[i] & UINT64_C(1) << b) {
                s0 ^= s[0];
                s1 ^= s[1];
            }
            next();
        }
    s[0] = s0;
    s[1] = s1;
}

uint64_t RandomGen::splitmix64(uint64_t x) {
    uint64_t z = (x += 0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    return z ^ (z >> 31);
}

int set_cpu_affinity(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    assert((core_id >= 0) && (core_id < num_cores));

    pthread_t current_thread = pthread_self();
    int err = pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
    if (err < 0) {
        log_error("Couldn't set affinity to core %d", core_id);
        return err;
    }

    return 0;
}


