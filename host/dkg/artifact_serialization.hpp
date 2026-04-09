#ifndef HOST_DKG_ARTIFACT_SERIALIZATION_HPP
#define HOST_DKG_ARTIFACT_SERIALIZATION_HPP

#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "dkg_artifacts.hpp"

namespace host
{
namespace dkg
{
struct PreprocessingNoiseKey
{
    // Noise records are keyed both by semantic role and by the final target
    // TUniform bound, because the same NoiseKind can appear with different bounds.
    NoiseKind kind = NoiseKind::kLwe;
    uint32_t bound_bits = 0;

    bool operator<(const PreprocessingNoiseKey& other) const
    {
        if (kind != other.kind)
        {
            return static_cast<uint32_t>(kind) < static_cast<uint32_t>(other.kind);
        }
        return bound_bits < other.bound_bits;
    }
};

class PreprocessingStreamReader
{
public:
    // Open a preprocessing bundle without materializing the whole file in memory.
    // The reader builds lightweight section cursors and then serves records on demand.
    bool open(const std::string& path, std::string* error_message = nullptr);

    const DkgPlan& plan() const { return plan_; }
    const PublicSeed& seed() const { return seed_; }
    size_t raw_bit_count() const { return raw_bit_count_; }
    size_t triple_count() const { return triple_count_; }
    size_t noise_count(NoiseKind kind, uint32_t bound_bits) const;

    bool next_raw_bit(SharedBitVector* bit, std::string* error_message = nullptr);
    bool next_noise(
        NoiseKind kind,
        uint32_t bound_bits,
        SharedNoiseVector* noise,
        std::string* error_message = nullptr);
    bool next_triple(SharedTripleVector* triple, std::string* error_message = nullptr);

private:
    struct Segment
    {
        // Each noise bucket can be split across multiple append rounds, so we keep
        // a list of file segments rather than assuming one contiguous section.
        std::streampos offset{};
        size_t remaining = 0;
    };

    DkgPlan plan_{};
    PublicSeed seed_{};
    std::string path_;
    std::ifstream bit_in_;
    std::ifstream noise_in_;
    std::ifstream triple_in_;
    std::streampos raw_bits_offset_{};
    std::streampos triple_offset_{};
    size_t raw_bit_count_ = 0;
    size_t raw_bits_remaining_ = 0;
    size_t triple_count_ = 0;
    size_t triples_remaining_ = 0;
    std::map<PreprocessingNoiseKey, std::vector<Segment>> noise_segments_;
    std::map<PreprocessingNoiseKey, size_t> noise_total_counts_;
};


class PreprocessingStreamWriter
{
public:
    // The preprocessing file is written in three append-only sections:
    // raw bits, noise records, then triples. This keeps controller memory bounded.
    bool open(
        const std::string& path,
        const DkgPlan& plan,
        const PublicSeed& seed,
        size_t raw_bit_count,
        size_t noise_count,
        size_t triple_count,
        std::string* error_message = nullptr);

    bool write_raw_bit(const SharedBitVector& bit, std::string* error_message = nullptr);
    bool write_noise(const SharedNoiseVector& noise, std::string* error_message = nullptr);
    bool write_triple(const SharedTripleVector& triple, std::string* error_message = nullptr);
    bool close(std::string* error_message = nullptr);

private:
    enum class Section
    {
        kClosed,
        kBits,
        kNoises,
        kTriples,
        kDone,
    };

    bool advance_to(Section target, std::string* error_message);
    bool ensure_section(Section section, std::string* error_message) const;

    std::ofstream out_;
    Section section_ = Section::kClosed;
    size_t bit_count_ = 0;
    size_t noise_count_ = 0;
    size_t triple_count_ = 0;
    size_t written_ = 0;
};


bool save_secret_key_file(
    const std::string& path,
    const SecretKeyBundle& bundle,
    std::string* error_message = nullptr);

bool load_secret_key_file(
    const std::string& path,
    SecretKeyBundle* bundle,
    std::string* error_message = nullptr);

bool save_public_key_file(
    const std::string& path,
    const PublicKeyBundle& bundle,
    std::string* error_message = nullptr);

bool load_public_key_file(
    const std::string& path,
    PublicKeyBundle* bundle,
    std::string* error_message = nullptr);

struct PublicKeyStreamCounts
{
    size_t pk = 0;
    size_t pksk_lwe = 0;
    size_t pksk_glwe = 0;
    size_t ksk = 0;
    size_t bk = 0;
    size_t bk_sns = 0;
    size_t compression_key = 0;
    size_t decompression_key = 0;
};

class PublicKeyStreamWriter
{
public:
    enum class Section
    {
        kClosed,
        kPk,
        kPkskLwe,
        kPkskGlwe,
        kKsk,
        kBk,
        kBkSns,
        kCompressionKey,
        kDecompressionKey,
        kSnsCompressionKey,
        kDone,
    };

    bool open(
        const std::string& path,
        const DkgPlan& plan,
        const PublicSeed& public_seed,
        const PublicKeyStreamCounts& counts,
        std::string* error_message = nullptr);

    bool write_pk(const SharedLweCiphertext& ciphertext, std::string* error_message = nullptr);
    bool write_pksk_lwe(const SharedLevCiphertext& ciphertext, std::string* error_message = nullptr);
    bool write_pksk_glwe(const SharedGlevCiphertext& ciphertext, std::string* error_message = nullptr);
    bool write_ksk(const SharedLevCiphertext& ciphertext, std::string* error_message = nullptr);
    bool write_bk(const SharedGgswCiphertext& ciphertext, std::string* error_message = nullptr);
    bool write_bk_sns(const SharedGgswCiphertext& ciphertext, std::string* error_message = nullptr);
    bool write_compression_key(const SharedGgswCiphertext& ciphertext, std::string* error_message = nullptr);
    bool write_decompression_key(const SharedGlevCiphertext& ciphertext, std::string* error_message = nullptr);
    bool write_sns_compression_key(const SharedLwePackingKeyswitchKey& key, std::string* error_message = nullptr);
    bool begin_sns_compression_key(
        size_t input_lwe_dimension,
        size_t output_glwe_dimension,
        size_t output_polynomial_size,
        size_t base_log,
        size_t level_count,
        std::string* error_message = nullptr);
    bool write_sns_compression_block(
        const SharedPackingKeyswitchBlock& block,
        std::string* error_message = nullptr);

    bool close(std::string* error_message = nullptr);
    bool ok() const;

private:
    // Public key material is emitted in a fixed order so readers can reconstruct
    // the exact TFHE/KMS-style key layout without buffering the full key in memory.
    bool advance_to(Section target, std::string* error_message);
    bool ensure_section(Section section, std::string* error_message) const;

    std::ofstream out_;
    PublicKeyStreamCounts counts_{};
    Section section_ = Section::kClosed;
    size_t written_ = 0;
    bool wrote_sns_compression_key_ = false;
    bool streaming_sns_compression_key_ = false;
    size_t sns_blocks_expected_ = 0;
    size_t sns_blocks_written_ = 0;
};
} // namespace dkg
} // namespace host

#endif
