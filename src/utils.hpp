#ifndef _UTILS_H_
#define _UTILS_H_

/* We used xoroshiro128+ fast random generator 
 * and SplitMix64 to generate the seed.
 * source: https://prng.di.unimi.it
 */
class RandomGen {
private:
    static uint16_t obj_num;
    uint64_t s[2];

private:
    inline uint64_t rotl(const uint64_t x, int k) {
        return (x << k) | (x >> (64 - k));
    }

    void jump();
    void long_jump();
    uint64_t splitmix64(uint64_t x);

public:
    RandomGen(uint64_t seed);
    uint64_t next();
};

template<typename T, typename U>
class Histogram {
private:
    std::map<T,U> hist;
    uint64_t sample_num = 0;

public:
    void populate_hist(T data) {
        auto it = hist.find(data);
        if (it != hist.end())
            it->second++;
        else
            hist[data] = 1;
        sample_num++;
    }

    float calc_percentile(float percent) {
        float percentile_value = 0;
        for (auto it = hist.begin(); it != hist.end(); it++)
            percentile_value += it->second;
        percentile_value *= percent;

        float total = 0;
        float index = 0.0;
        for (auto it = hist.begin(); it != hist.end(); it++) {
            total += it->second;
            if (total > percentile_value) {
                index = it->first;
                break;
            }
        }
        index = index + (percentile_value - (total - hist[index])) / hist[index];
        return index;
    }

    std::pair<T,U> get_last_element() {
        auto it = hist.crbegin();
        std::pair<T,U> last_element = std::make_pair(it->first, it->second);
        return last_element;
    }

    std::pair<T,U> get_first_element() {
        auto it = hist.begin();
        std::pair<T,U> first_element = std::make_pair(it->first, it->second);
        return first_element;
    }

    void print_hist() {
        for (auto it : hist)
            log_info("Hist %ld: %.3f", it.first, (float)it.second / (float)sample_num * 100);
    }

    void merge(Histogram& other) {
        for (auto pair : other.hist) {
            auto it = hist.find(pair.first);
            if (it != hist.end())
                it->second += pair.second;
            else
                hist[pair.first] = pair.second;

            sample_num += pair.second;
        }
    }

    uint64_t get_sample_num() const {
        return sample_num;
    }
};

int set_cpu_affinity(int core_id);

#endif
