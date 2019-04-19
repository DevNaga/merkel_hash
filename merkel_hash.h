#ifndef __MERKEL_HASH_H__
#define __MERKEL_HASH_H__

struct hash_val {
    uint8_t hash[32];
};

class merkel_hash {
    public:
        merkel_hash();
        ~merkel_hash();
        int compute_hash(std::vector<std::string> blocks);
        void dump_merkel_hash();
    private:
        hash_val merkelh;

        int compute_hash_val(const char *input, size_t input_len, uint8_t *out, unsigned int *outlen);
        int compute_merkel_hash_val(uint8_t *input_a, size_t input_a_len, uint8_t *input_b, size_t input_b_len, uint8_t *out, unsigned int *outlen);
        void dump(uint8_t *hash_val);
};

#endif


