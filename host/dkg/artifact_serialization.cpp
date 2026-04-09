#include "artifact_serialization.hpp"

#include <cstdint>
#include <fstream>
#include <type_traits>

namespace host
{
namespace dkg
{
namespace
{
constexpr uint32_t kFormatVersion = 2;
constexpr uint32_t kPreprocMagic = 0x50525043; // PRPC
constexpr uint32_t kSecretKeyMagic = 0x534b4559; // SKEY
constexpr uint32_t kPublicKeyMagic = 0x504b4559; // PKEY

bool set_error(std::string* error_message, const std::string& message)
{
    if (error_message != nullptr)
    {
        *error_message = message;
    }
    return false;
}

class BinaryWriter
{
public:
    explicit BinaryWriter(std::ostream* out) : out_(out) {}

    template <typename T>
    void write_pod(const T& value)
    {
        static_assert(std::is_trivially_copyable<T>::value, "POD required");
        out_->write(reinterpret_cast<const char*>(&value), sizeof(T));
    }

    void write_string(const std::string& value)
    {
        const uint64_t size = static_cast<uint64_t>(value.size());
        write_pod(size);
        out_->write(value.data(), static_cast<std::streamsize>(value.size()));
    }

    bool ok() const { return out_ != nullptr && out_->good(); }

private:
    std::ostream* out_;
};

class BinaryReader
{
public:
    explicit BinaryReader(std::istream* in) : in_(in) {}

    template <typename T>
    bool read_pod(T* out)
    {
        static_assert(std::is_trivially_copyable<T>::value, "POD required");
        if (out == nullptr)
        {
            return false;
        }
        in_->read(reinterpret_cast<char*>(out), sizeof(T));
        return in_->good();
    }

    bool read_string(std::string* out)
    {
        if (out == nullptr)
        {
            return false;
        }
        uint64_t size = 0;
        if (!read_pod(&size))
        {
            return false;
        }
        out->assign(static_cast<size_t>(size), '\0');
        in_->read(out->data(), static_cast<std::streamsize>(size));
        return in_->good();
    }

    bool ok() const { return in_ != nullptr && in_->good(); }

private:
    std::istream* in_;
};

void write_ring_raw(BinaryWriter* writer, const noise::RingElementRaw& value)
{
    writer->write_pod(value);
}

bool read_ring_raw(BinaryReader* reader, noise::RingElementRaw* out)
{
    return reader->read_pod(out);
}

// Shares and triples are persisted in a compact binary form so streaming readers
// can reconstruct party-local preprocessing material with minimal allocations.
void write_ring_share(BinaryWriter* writer, const algebra::RingShare& share)
{
    writer->write_pod(share.owner);
    write_ring_raw(writer, noise::raw_from_ring(share.value));
}

bool read_ring_share(BinaryReader* reader, algebra::RingShare* out)
{
    if (out == nullptr)
    {
        return false;
    }
    noise::RingElementRaw raw{};
    if (!reader->read_pod(&out->owner) || !read_ring_raw(reader, &raw))
    {
        return false;
    }
    out->value = noise::ring_from_raw(raw);
    return true;
}

void write_ring_share_vector(BinaryWriter* writer, const std::vector<algebra::RingShare>& shares)
{
    const uint64_t size = static_cast<uint64_t>(shares.size());
    writer->write_pod(size);
    for (const auto& share : shares)
    {
        write_ring_share(writer, share);
    }
}

bool read_ring_share_vector(BinaryReader* reader, std::vector<algebra::RingShare>* shares)
{
    if (shares == nullptr)
    {
        return false;
    }
    uint64_t size = 0;
    if (!reader->read_pod(&size))
    {
        return false;
    }
    shares->assign(static_cast<size_t>(size), algebra::RingShare{});
    for (auto& share : *shares)
    {
        if (!read_ring_share(reader, &share))
        {
            return false;
        }
    }
    return true;
}

void write_triple_share_vector(BinaryWriter* writer, const std::vector<algebra::RingTripleShare>& triples)
{
    const uint64_t size = static_cast<uint64_t>(triples.size());
    writer->write_pod(size);
    for (const auto& triple : triples)
    {
        write_ring_share(writer, triple.a);
        write_ring_share(writer, triple.b);
        write_ring_share(writer, triple.c);
    }
}

bool read_triple_share_vector(BinaryReader* reader, std::vector<algebra::RingTripleShare>* triples)
{
    if (triples == nullptr)
    {
        return false;
    }
    uint64_t size = 0;
    if (!reader->read_pod(&size))
    {
        return false;
    }
    triples->assign(static_cast<size_t>(size), algebra::RingTripleShare{});
    for (auto& triple : *triples)
    {
        if (!read_ring_share(reader, &triple.a) ||
            !read_ring_share(reader, &triple.b) ||
            !read_ring_share(reader, &triple.c))
        {
            return false;
        }
    }
    return true;
}

void write_noise_kind(BinaryWriter* writer, NoiseKind kind)
{
    writer->write_pod(static_cast<uint32_t>(kind));
}

bool read_noise_kind(BinaryReader* reader, NoiseKind* kind)
{
    if (kind == nullptr)
    {
        return false;
    }
    uint32_t raw = 0;
    if (!reader->read_pod(&raw))
    {
        return false;
    }
    *kind = static_cast<NoiseKind>(raw);
    return true;
}

void write_keyset_mode(BinaryWriter* writer, KeysetMode mode)
{
    writer->write_pod(static_cast<uint32_t>(mode));
}

bool read_keyset_mode(BinaryReader* reader, KeysetMode* mode)
{
    if (mode == nullptr)
    {
        return false;
    }
    uint32_t raw = 0;
    if (!reader->read_pod(&raw))
    {
        return false;
    }
    *mode = static_cast<KeysetMode>(raw);
    return true;
}

void write_pksk_destination(BinaryWriter* writer, PkskDestination destination)
{
    writer->write_pod(static_cast<uint32_t>(destination));
}

bool read_pksk_destination(BinaryReader* reader, PkskDestination* destination)
{
    if (destination == nullptr)
    {
        return false;
    }
    uint32_t raw = 0;
    if (!reader->read_pod(&raw))
    {
        return false;
    }
    *destination = static_cast<PkskDestination>(raw);
    return true;
}

void write_encryption_key_choice(BinaryWriter* writer, EncryptionKeyChoice choice)
{
    writer->write_pod(static_cast<uint32_t>(choice));
}

bool read_encryption_key_choice(BinaryReader* reader, EncryptionKeyChoice* choice)
{
    if (choice == nullptr)
    {
        return false;
    }
    uint32_t raw = 0;
    if (!reader->read_pod(&raw))
    {
        return false;
    }
    *choice = static_cast<EncryptionKeyChoice>(raw);
    return true;
}

void write_compression_params(BinaryWriter* writer, const CompressionParams& params)
{
    writer->write_pod(params.enabled);
    writer->write_pod(static_cast<uint64_t>(params.br_level));
    writer->write_pod(static_cast<uint64_t>(params.br_base_log));
    writer->write_pod(static_cast<uint64_t>(params.packing_ks_level));
    writer->write_pod(static_cast<uint64_t>(params.packing_ks_base_log));
    writer->write_pod(static_cast<uint64_t>(params.packing_ks_glwe_dimension));
    writer->write_pod(static_cast<uint64_t>(params.packing_ks_polynomial_size));
    writer->write_pod(params.noise_bound_bits);
}

bool read_compression_params(BinaryReader* reader, CompressionParams* params)
{
    if (params == nullptr)
    {
        return false;
    }
    uint64_t tmp = 0;
    return reader->read_pod(&params->enabled) &&
        reader->read_pod(&tmp) && ((params->br_level = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->br_base_log = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->packing_ks_level = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->packing_ks_base_log = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->packing_ks_glwe_dimension = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->packing_ks_polynomial_size = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&params->noise_bound_bits);
}

void write_params(BinaryWriter* writer, const DkgParams& params)
{
    // Persist the full parameter set so a key/preprocessing artifact remains
    // self-describing even when the external config file changes later.
    writer->write_string(params.preset_name);
    write_keyset_mode(writer, params.keyset_mode);

    writer->write_pod(params.regular.sec);
    writer->write_pod(static_cast<uint64_t>(params.regular.lwe_dimension));
    writer->write_pod(static_cast<uint64_t>(params.regular.lwe_hat_dimension));
    writer->write_pod(static_cast<uint64_t>(params.regular.glwe_dimension));
    writer->write_pod(static_cast<uint64_t>(params.regular.polynomial_size));
    writer->write_pod(params.regular.lwe_noise_bound_bits);
    writer->write_pod(params.regular.lwe_hat_noise_bound_bits);
    writer->write_pod(params.regular.glwe_noise_bound_bits);
    writer->write_pod(static_cast<uint64_t>(params.regular.ks_base_log));
    writer->write_pod(static_cast<uint64_t>(params.regular.ks_level));
    writer->write_pod(static_cast<uint64_t>(params.regular.pksk_base_log));
    writer->write_pod(static_cast<uint64_t>(params.regular.pksk_level));
    writer->write_pod(static_cast<uint64_t>(params.regular.bk_base_log));
    writer->write_pod(static_cast<uint64_t>(params.regular.bk_level));
    writer->write_pod(static_cast<uint64_t>(params.regular.msnrk_zeros_count));
    writer->write_pod(static_cast<uint64_t>(params.regular.message_modulus));
    writer->write_pod(static_cast<uint64_t>(params.regular.carry_modulus));
    writer->write_pod(params.regular.log2_p_fail);
    write_encryption_key_choice(writer, params.regular.encryption_key_choice);
    writer->write_pod(params.regular.has_dedicated_pk);
    write_pksk_destination(writer, params.regular.pksk_destination);
    write_compression_params(writer, params.regular.compression);

    writer->write_pod(params.sns.enabled);
    writer->write_pod(static_cast<uint64_t>(params.sns.glwe_dimension));
    writer->write_pod(static_cast<uint64_t>(params.sns.polynomial_size));
    writer->write_pod(params.sns.glwe_noise_bound_bits);
    writer->write_pod(static_cast<uint64_t>(params.sns.bk_base_log));
    writer->write_pod(static_cast<uint64_t>(params.sns.bk_level));
    writer->write_pod(static_cast<uint64_t>(params.sns.message_modulus));
    writer->write_pod(static_cast<uint64_t>(params.sns.carry_modulus));
    write_compression_params(writer, params.sns.compression);
}

bool read_params(BinaryReader* reader, DkgParams* params)
{
    if (params == nullptr)
    {
        return false;
    }
    uint64_t tmp = 0;
    return reader->read_string(&params->preset_name) &&
        read_keyset_mode(reader, &params->keyset_mode) &&
        reader->read_pod(&params->regular.sec) &&
        reader->read_pod(&tmp) && ((params->regular.lwe_dimension = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->regular.lwe_hat_dimension = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->regular.glwe_dimension = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->regular.polynomial_size = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&params->regular.lwe_noise_bound_bits) &&
        reader->read_pod(&params->regular.lwe_hat_noise_bound_bits) &&
        reader->read_pod(&params->regular.glwe_noise_bound_bits) &&
        reader->read_pod(&tmp) && ((params->regular.ks_base_log = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->regular.ks_level = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->regular.pksk_base_log = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->regular.pksk_level = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->regular.bk_base_log = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->regular.bk_level = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->regular.msnrk_zeros_count = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->regular.message_modulus = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->regular.carry_modulus = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&params->regular.log2_p_fail) &&
        read_encryption_key_choice(reader, &params->regular.encryption_key_choice) &&
        reader->read_pod(&params->regular.has_dedicated_pk) &&
        read_pksk_destination(reader, &params->regular.pksk_destination) &&
        read_compression_params(reader, &params->regular.compression) &&
        reader->read_pod(&params->sns.enabled) &&
        reader->read_pod(&tmp) && ((params->sns.glwe_dimension = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->sns.polynomial_size = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&params->sns.glwe_noise_bound_bits) &&
        reader->read_pod(&tmp) && ((params->sns.bk_base_log = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->sns.bk_level = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->sns.message_modulus = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((params->sns.carry_modulus = static_cast<size_t>(tmp)), true) &&
        read_compression_params(reader, &params->sns.compression);
}

void write_preprocessing_requirements(BinaryWriter* writer, const PreprocessingRequirements& requirements)
{
    writer->write_pod(static_cast<uint64_t>(requirements.total_bits));
    writer->write_pod(static_cast<uint64_t>(requirements.total_triples));
    writer->write_pod(static_cast<uint64_t>(requirements.total_randomness));
    writer->write_pod(static_cast<uint64_t>(requirements.raw_secret_bits));
    const uint64_t noise_count = static_cast<uint64_t>(requirements.noise_batches.size());
    writer->write_pod(noise_count);
    for (const auto& noise : requirements.noise_batches)
    {
        write_noise_kind(writer, noise.kind);
        writer->write_pod(static_cast<uint64_t>(noise.amount));
        writer->write_pod(noise.bound_bits);
    }
}

bool read_preprocessing_requirements(BinaryReader* reader, PreprocessingRequirements* requirements)
{
    if (requirements == nullptr)
    {
        return false;
    }
    uint64_t tmp = 0;
    uint64_t noise_count = 0;
    if (!reader->read_pod(&tmp))
    {
        return false;
    }
    requirements->total_bits = static_cast<size_t>(tmp);
    if (!reader->read_pod(&tmp))
    {
        return false;
    }
    requirements->total_triples = static_cast<size_t>(tmp);
    if (!reader->read_pod(&tmp))
    {
        return false;
    }
    requirements->total_randomness = static_cast<size_t>(tmp);
    if (!reader->read_pod(&tmp))
    {
        return false;
    }
    requirements->raw_secret_bits = static_cast<size_t>(tmp);
    if (!reader->read_pod(&noise_count))
    {
        return false;
    }
    requirements->noise_batches.assign(static_cast<size_t>(noise_count), NoiseInfo{});
    for (auto& noise : requirements->noise_batches)
    {
        if (!read_noise_kind(reader, &noise.kind))
        {
            return false;
        }
        if (!reader->read_pod(&tmp))
        {
            return false;
        }
        noise.amount = static_cast<size_t>(tmp);
        if (!reader->read_pod(&noise.bound_bits))
        {
            return false;
        }
    }
    return true;
}

void write_shape(BinaryWriter* writer, const KeyMaterialShape& shape)
{
    writer->write_pod(static_cast<uint64_t>(shape.lwe_secret_bits));
    writer->write_pod(static_cast<uint64_t>(shape.lwe_hat_secret_bits));
    writer->write_pod(static_cast<uint64_t>(shape.glwe_secret_bits));
    writer->write_pod(static_cast<uint64_t>(shape.compression_secret_bits));
    writer->write_pod(static_cast<uint64_t>(shape.sns_glwe_secret_bits));
    writer->write_pod(static_cast<uint64_t>(shape.sns_compression_secret_bits));
    writer->write_pod(static_cast<uint64_t>(shape.bootstrap_ciphertexts));
    writer->write_pod(static_cast<uint64_t>(shape.keyswitch_ciphertexts));
    writer->write_pod(static_cast<uint64_t>(shape.public_key_ciphertexts));
}

bool read_shape(BinaryReader* reader, KeyMaterialShape* shape)
{
    if (shape == nullptr)
    {
        return false;
    }
    uint64_t tmp = 0;
    return reader->read_pod(&tmp) && ((shape->lwe_secret_bits = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((shape->lwe_hat_secret_bits = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((shape->glwe_secret_bits = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((shape->compression_secret_bits = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((shape->sns_glwe_secret_bits = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((shape->sns_compression_secret_bits = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((shape->bootstrap_ciphertexts = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((shape->keyswitch_ciphertexts = static_cast<size_t>(tmp)), true) &&
        reader->read_pod(&tmp) && ((shape->public_key_ciphertexts = static_cast<size_t>(tmp)), true);
}

void write_plan(BinaryWriter* writer, const DkgPlan& plan)
{
    write_params(writer, plan.params);
    write_preprocessing_requirements(writer, plan.preprocessing);
    write_shape(writer, plan.shape);
}

bool read_plan(BinaryReader* reader, DkgPlan* plan)
{
    return plan != nullptr &&
        read_params(reader, &plan->params) &&
        read_preprocessing_requirements(reader, &plan->preprocessing) &&
        read_shape(reader, &plan->shape);
}


bool skip_ring_share_vector(BinaryReader* reader)
{
    uint64_t size = 0;
    if (!reader->read_pod(&size))
    {
        return false;
    }
    for (uint64_t i = 0; i < size; ++i)
    {
        uint64_t owner = 0;
        noise::RingElementRaw raw{};
        if (!reader->read_pod(&owner) || !reader->read_pod(&raw))
        {
            return false;
        }
    }
    return true;
}

bool skip_triple_share_vector(BinaryReader* reader)
{
    uint64_t size = 0;
    if (!reader->read_pod(&size))
    {
        return false;
    }
    for (uint64_t i = 0; i < size; ++i)
    {
        for (size_t j = 0; j < 3; ++j)
        {
            uint64_t owner = 0;
            noise::RingElementRaw raw{};
            if (!reader->read_pod(&owner) || !reader->read_pod(&raw))
            {
                return false;
            }
        }
    }
    return true;
}

bool skip_bit_record(BinaryReader* reader)
{
    uint64_t tmp = 0;
    return reader->read_pod(&tmp) &&
        reader->read_pod(&tmp) &&
        skip_ring_share_vector(reader);
}

bool skip_noise_record(BinaryReader* reader, NoiseKind* kind, uint32_t* bound_bits)
{
    uint64_t tmp = 0;
    return read_noise_kind(reader, kind) &&
        reader->read_pod(bound_bits) &&
        reader->read_pod(&tmp) &&
        reader->read_pod(&tmp) &&
        skip_ring_share_vector(reader);
}

bool skip_triple_record(BinaryReader* reader)
{
    uint64_t tmp = 0;
    return reader->read_pod(&tmp) &&
        reader->read_pod(&tmp) &&
        skip_triple_share_vector(reader);
}

bool read_bit_record(BinaryReader* reader, SharedBitVector* bit)
{
    return bit != nullptr &&
        reader->read_pod(&bit->round_id) &&
        reader->read_pod(&bit->sigma) &&
        read_ring_share_vector(reader, &bit->shares);
}

bool read_noise_record(BinaryReader* reader, SharedNoiseVector* noise)
{
    return noise != nullptr &&
        read_noise_kind(reader, &noise->kind) &&
        reader->read_pod(&noise->bound_bits) &&
        reader->read_pod(&noise->round_id) &&
        reader->read_pod(&noise->sigma) &&
        read_ring_share_vector(reader, &noise->shares);
}

bool read_triple_record(BinaryReader* reader, SharedTripleVector* triple)
{
    return triple != nullptr &&
        reader->read_pod(&triple->round_id) &&
        reader->read_pod(&triple->sigma) &&
        read_triple_share_vector(reader, &triple->triples);
}

void write_lwe_ciphertext(BinaryWriter* writer, const SharedLweCiphertext& ciphertext)
{
    writer->write_pod(static_cast<uint64_t>(ciphertext.a.size()));
    for (const auto& mask : ciphertext.a)
    {
        write_ring_raw(writer, mask);
    }
    write_ring_share(writer, ciphertext.b);
}

bool read_lwe_ciphertext(BinaryReader* reader, SharedLweCiphertext* ciphertext)
{
    if (ciphertext == nullptr)
    {
        return false;
    }
    uint64_t size = 0;
    if (!reader->read_pod(&size))
    {
        return false;
    }
    ciphertext->a.assign(static_cast<size_t>(size), noise::RingElementRaw{});
    for (auto& mask : ciphertext->a)
    {
        if (!read_ring_raw(reader, &mask))
        {
            return false;
        }
    }
    return read_ring_share(reader, &ciphertext->b);
}

void write_glwe_ciphertext(BinaryWriter* writer, const SharedGlweCiphertext& ciphertext)
{
    writer->write_pod(static_cast<uint64_t>(ciphertext.a.size()));
    for (const auto& mask : ciphertext.a)
    {
        write_ring_raw(writer, mask);
    }
    write_ring_share(writer, ciphertext.b);
}

bool read_glwe_ciphertext(BinaryReader* reader, SharedGlweCiphertext* ciphertext)
{
    if (ciphertext == nullptr)
    {
        return false;
    }
    uint64_t size = 0;
    if (!reader->read_pod(&size))
    {
        return false;
    }
    ciphertext->a.assign(static_cast<size_t>(size), noise::RingElementRaw{});
    for (auto& mask : ciphertext->a)
    {
        if (!read_ring_raw(reader, &mask))
        {
            return false;
        }
    }
    return read_ring_share(reader, &ciphertext->b);
}

void write_lev_ciphertext(BinaryWriter* writer, const SharedLevCiphertext& ciphertext)
{
    writer->write_pod(static_cast<uint64_t>(ciphertext.levels.size()));
    for (const auto& level : ciphertext.levels)
    {
        write_lwe_ciphertext(writer, level);
    }
}

bool read_lev_ciphertext(BinaryReader* reader, SharedLevCiphertext* ciphertext)
{
    if (ciphertext == nullptr)
    {
        return false;
    }
    uint64_t size = 0;
    if (!reader->read_pod(&size))
    {
        return false;
    }
    ciphertext->levels.assign(static_cast<size_t>(size), SharedLweCiphertext{});
    for (auto& level : ciphertext->levels)
    {
        if (!read_lwe_ciphertext(reader, &level))
        {
            return false;
        }
    }
    return true;
}

void write_glev_ciphertext(BinaryWriter* writer, const SharedGlevCiphertext& ciphertext)
{
    writer->write_pod(static_cast<uint64_t>(ciphertext.levels.size()));
    for (const auto& level : ciphertext.levels)
    {
        write_glwe_ciphertext(writer, level);
    }
}

bool read_glev_ciphertext(BinaryReader* reader, SharedGlevCiphertext* ciphertext)
{
    if (ciphertext == nullptr)
    {
        return false;
    }
    uint64_t size = 0;
    if (!reader->read_pod(&size))
    {
        return false;
    }
    ciphertext->levels.assign(static_cast<size_t>(size), SharedGlweCiphertext{});
    for (auto& level : ciphertext->levels)
    {
        if (!read_glwe_ciphertext(reader, &level))
        {
            return false;
        }
    }
    return true;
}

void write_ggsw_ciphertext(BinaryWriter* writer, const SharedGgswCiphertext& ciphertext)
{
    writer->write_pod(static_cast<uint64_t>(ciphertext.rows.size()));
    for (const auto& row : ciphertext.rows)
    {
        write_glev_ciphertext(writer, row);
    }
}

bool read_ggsw_ciphertext(BinaryReader* reader, SharedGgswCiphertext* ciphertext)
{
    if (ciphertext == nullptr)
    {
        return false;
    }
    uint64_t size = 0;
    if (!reader->read_pod(&size))
    {
        return false;
    }
    ciphertext->rows.assign(static_cast<size_t>(size), SharedGlevCiphertext{});
    for (auto& row : ciphertext->rows)
    {
        if (!read_glev_ciphertext(reader, &row))
        {
            return false;
        }
    }
    return true;
}

template <typename T, typename WriteFn>
void write_vector(BinaryWriter* writer, const std::vector<T>& values, WriteFn write_fn);

template <typename T, typename ReadFn>
bool read_vector(BinaryReader* reader, std::vector<T>* values, ReadFn read_fn);

void write_packing_keyswitch_block(BinaryWriter* writer, const SharedPackingKeyswitchBlock& block)
{
    write_vector(writer, block.polynomial_entries, write_glev_ciphertext);
}

bool read_packing_keyswitch_block(BinaryReader* reader, SharedPackingKeyswitchBlock* block)
{
    return block != nullptr &&
        read_vector(reader, &block->polynomial_entries, read_glev_ciphertext);
}

void write_lwe_packing_keyswitch_key(BinaryWriter* writer, const SharedLwePackingKeyswitchKey& key)
{
    writer->write_pod(static_cast<uint64_t>(key.input_lwe_dimension));
    writer->write_pod(static_cast<uint64_t>(key.output_glwe_dimension));
    writer->write_pod(static_cast<uint64_t>(key.output_polynomial_size));
    writer->write_pod(static_cast<uint64_t>(key.base_log));
    writer->write_pod(static_cast<uint64_t>(key.level_count));
    write_vector(writer, key.blocks, write_packing_keyswitch_block);
}

bool read_lwe_packing_keyswitch_key(BinaryReader* reader, SharedLwePackingKeyswitchKey* key)
{
    if (key == nullptr)
    {
        return false;
    }
    uint64_t input_lwe_dimension = 0;
    uint64_t output_glwe_dimension = 0;
    uint64_t output_polynomial_size = 0;
    uint64_t base_log = 0;
    uint64_t level_count = 0;
    if (!reader->read_pod(&input_lwe_dimension) ||
        !reader->read_pod(&output_glwe_dimension) ||
        !reader->read_pod(&output_polynomial_size) ||
        !reader->read_pod(&base_log) ||
        !reader->read_pod(&level_count))
    {
        return false;
    }

    key->input_lwe_dimension = static_cast<size_t>(input_lwe_dimension);
    key->output_glwe_dimension = static_cast<size_t>(output_glwe_dimension);
    key->output_polynomial_size = static_cast<size_t>(output_polynomial_size);
    key->base_log = static_cast<size_t>(base_log);
    key->level_count = static_cast<size_t>(level_count);
    return read_vector(reader, &key->blocks, read_packing_keyswitch_block);
}

template <typename T, typename WriteFn>
void write_vector(BinaryWriter* writer, const std::vector<T>& values, WriteFn write_fn)
{
    writer->write_pod(static_cast<uint64_t>(values.size()));
    for (const auto& value : values)
    {
        write_fn(writer, value);
    }
}

template <typename T, typename ReadFn>
bool read_vector(BinaryReader* reader, std::vector<T>* values, ReadFn read_fn)
{
    if (values == nullptr)
    {
        return false;
    }
    uint64_t size = 0;
    if (!reader->read_pod(&size))
    {
        return false;
    }
    values->assign(static_cast<size_t>(size), T{});
    for (auto& value : *values)
    {
        if (!read_fn(reader, &value))
        {
            return false;
        }
    }
    return true;
}


void write_secret_key_bundle(BinaryWriter* writer, const SecretKeyBundle& bundle)
{
    write_plan(writer, bundle.plan);
    writer->write_pod(bundle.public_seed.low);
    writer->write_pod(bundle.public_seed.high);
    write_ring_share_vector(writer, bundle.secret_shares.lwe);
    write_ring_share_vector(writer, bundle.secret_shares.lwe_hat);
    write_ring_share_vector(writer, bundle.secret_shares.glwe);
    write_ring_share_vector(writer, bundle.secret_shares.compression_glwe);
    write_ring_share_vector(writer, bundle.secret_shares.sns_glwe);
    write_ring_share_vector(writer, bundle.secret_shares.sns_compression_glwe);
}

bool read_secret_key_bundle(BinaryReader* reader, SecretKeyBundle* bundle)
{
    return bundle != nullptr &&
        read_plan(reader, &bundle->plan) &&
        reader->read_pod(&bundle->public_seed.low) &&
        reader->read_pod(&bundle->public_seed.high) &&
        read_ring_share_vector(reader, &bundle->secret_shares.lwe) &&
        read_ring_share_vector(reader, &bundle->secret_shares.lwe_hat) &&
        read_ring_share_vector(reader, &bundle->secret_shares.glwe) &&
        read_ring_share_vector(reader, &bundle->secret_shares.compression_glwe) &&
        read_ring_share_vector(reader, &bundle->secret_shares.sns_glwe) &&
        read_ring_share_vector(reader, &bundle->secret_shares.sns_compression_glwe);
}

void write_public_key_bundle(BinaryWriter* writer, const PublicKeyBundle& bundle)
{
    write_plan(writer, bundle.plan);
    writer->write_pod(bundle.public_seed.low);
    writer->write_pod(bundle.public_seed.high);
    write_vector(writer, bundle.public_material.pk, write_lwe_ciphertext);
    write_vector(writer, bundle.public_material.pksk_lwe, write_lev_ciphertext);
    write_vector(writer, bundle.public_material.pksk_glwe, write_glev_ciphertext);
    write_vector(writer, bundle.public_material.ksk, write_lev_ciphertext);
    write_vector(writer, bundle.public_material.bk, write_ggsw_ciphertext);
    write_vector(writer, bundle.public_material.bk_sns, write_ggsw_ciphertext);
    write_vector(writer, bundle.public_material.compression_key, write_ggsw_ciphertext);
    write_vector(writer, bundle.public_material.decompression_key, write_glev_ciphertext);
    write_lwe_packing_keyswitch_key(writer, bundle.public_material.sns_compression_key);
}

bool read_public_key_bundle(BinaryReader* reader, PublicKeyBundle* bundle)
{
    return bundle != nullptr &&
        read_plan(reader, &bundle->plan) &&
        reader->read_pod(&bundle->public_seed.low) &&
        reader->read_pod(&bundle->public_seed.high) &&
        read_vector(reader, &bundle->public_material.pk, read_lwe_ciphertext) &&
        read_vector(reader, &bundle->public_material.pksk_lwe, read_lev_ciphertext) &&
        read_vector(reader, &bundle->public_material.pksk_glwe, read_glev_ciphertext) &&
        read_vector(reader, &bundle->public_material.ksk, read_lev_ciphertext) &&
        read_vector(reader, &bundle->public_material.bk, read_ggsw_ciphertext) &&
        read_vector(reader, &bundle->public_material.bk_sns, read_ggsw_ciphertext) &&
        read_vector(reader, &bundle->public_material.compression_key, read_ggsw_ciphertext) &&
        read_vector(reader, &bundle->public_material.decompression_key, read_glev_ciphertext) &&
        read_lwe_packing_keyswitch_key(reader, &bundle->public_material.sns_compression_key);
}

size_t expected_for_section(const PublicKeyStreamCounts& counts, PublicKeyStreamWriter::Section section)
{
    switch (section)
    {
    case PublicKeyStreamWriter::Section::kPk:
        return counts.pk;
    case PublicKeyStreamWriter::Section::kPkskLwe:
        return counts.pksk_lwe;
    case PublicKeyStreamWriter::Section::kPkskGlwe:
        return counts.pksk_glwe;
    case PublicKeyStreamWriter::Section::kKsk:
        return counts.ksk;
    case PublicKeyStreamWriter::Section::kBk:
        return counts.bk;
    case PublicKeyStreamWriter::Section::kBkSns:
        return counts.bk_sns;
    case PublicKeyStreamWriter::Section::kCompressionKey:
        return counts.compression_key;
    case PublicKeyStreamWriter::Section::kDecompressionKey:
        return counts.decompression_key;
    default:
        return 0;
    }
}

PublicKeyStreamWriter::Section next_section(PublicKeyStreamWriter::Section section)
{
    switch (section)
    {
    case PublicKeyStreamWriter::Section::kPk:
        return PublicKeyStreamWriter::Section::kPkskLwe;
    case PublicKeyStreamWriter::Section::kPkskLwe:
        return PublicKeyStreamWriter::Section::kPkskGlwe;
    case PublicKeyStreamWriter::Section::kPkskGlwe:
        return PublicKeyStreamWriter::Section::kKsk;
    case PublicKeyStreamWriter::Section::kKsk:
        return PublicKeyStreamWriter::Section::kBk;
    case PublicKeyStreamWriter::Section::kBk:
        return PublicKeyStreamWriter::Section::kBkSns;
    case PublicKeyStreamWriter::Section::kBkSns:
        return PublicKeyStreamWriter::Section::kCompressionKey;
    case PublicKeyStreamWriter::Section::kCompressionKey:
        return PublicKeyStreamWriter::Section::kDecompressionKey;
    case PublicKeyStreamWriter::Section::kDecompressionKey:
        return PublicKeyStreamWriter::Section::kSnsCompressionKey;
    case PublicKeyStreamWriter::Section::kSnsCompressionKey:
        return PublicKeyStreamWriter::Section::kDone;
    default:
        return PublicKeyStreamWriter::Section::kDone;
    }
}

void write_section_count(BinaryWriter* writer, const PublicKeyStreamCounts& counts, PublicKeyStreamWriter::Section section)
{
    writer->write_pod(static_cast<uint64_t>(expected_for_section(counts, section)));
}

template <typename SaveFn>
bool save_file(
    const std::string& path,
    uint32_t magic,
    SaveFn save_fn,
    std::string* error_message)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        return set_error(error_message, "Failed to open file for writing: " + path);
    }
    BinaryWriter writer(&out);
    writer.write_pod(magic);
    writer.write_pod(kFormatVersion);
    save_fn(&writer);
    if (!writer.ok())
    {
        return set_error(error_message, "Failed to write serialized file: " + path);
    }
    return true;
}

template <typename LoadFn>
bool load_file(
    const std::string& path,
    uint32_t expected_magic,
    LoadFn load_fn,
    std::string* error_message)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        return set_error(error_message, "Failed to open file for reading: " + path);
    }
    BinaryReader reader(&in);
    uint32_t magic = 0;
    uint32_t version = 0;
    if (!reader.read_pod(&magic) || !reader.read_pod(&version))
    {
        return set_error(error_message, "Failed to read serialized file header: " + path);
    }
    if (magic != expected_magic)
    {
        return set_error(error_message, "Unexpected serialized file type: " + path);
    }
    if (version != kFormatVersion)
    {
        return set_error(error_message, "Unsupported serialized file version: " + path);
    }
    if (!load_fn(&reader) || !reader.ok())
    {
        return set_error(error_message, "Failed to deserialize file: " + path);
    }
    return true;
}
} // namespace



bool PreprocessingStreamWriter::open(
    const std::string& path,
    const DkgPlan& plan,
    const PublicSeed& seed,
    size_t raw_bit_count,
    size_t noise_count,
    size_t triple_count,
    std::string* error_message)
{
    // Write a fixed header first, then append records section-by-section. This
    // lets controller persist preprocessing output incrementally after each round.
    out_.open(path, std::ios::binary | std::ios::trunc);
    if (!out_)
    {
        return set_error(error_message, "Failed to open preprocessing file for streaming: " + path);
    }

    bit_count_ = raw_bit_count;
    noise_count_ = noise_count;
    triple_count_ = triple_count;
    section_ = Section::kBits;
    written_ = 0;

    BinaryWriter writer(&out_);
    writer.write_pod(kPreprocMagic);
    writer.write_pod(kFormatVersion);
    write_plan(&writer, plan);
    writer.write_pod(seed.low);
    writer.write_pod(seed.high);
    writer.write_pod(static_cast<uint64_t>(bit_count_));
    if (!writer.ok())
    {
        section_ = Section::kClosed;
        out_.close();
        return set_error(error_message, "Failed to write preprocessing stream header: " + path);
    }
    return true;
}

bool PreprocessingStreamWriter::ensure_section(Section section, std::string* error_message) const
{
    if (!out_.is_open() || section_ == Section::kClosed || section_ == Section::kDone)
    {
        return set_error(error_message, "Preprocessing stream is not open");
    }
    if (section_ != section)
    {
        return set_error(error_message, "Preprocessing stream section order violation");
    }
    const size_t expected = section == Section::kBits ? bit_count_ :
        (section == Section::kNoises ? noise_count_ : triple_count_);
    if (written_ >= expected)
    {
        return set_error(error_message, "Preprocessing stream section has too many entries");
    }
    return true;
}

bool PreprocessingStreamWriter::advance_to(Section target, std::string* error_message)
{
    if (!out_.is_open())
    {
        return set_error(error_message, "Preprocessing stream is not open");
    }
    BinaryWriter writer(&out_);
    while (section_ != target)
    {
        if (section_ == Section::kClosed || section_ == Section::kDone)
        {
            return set_error(error_message, "Preprocessing stream cannot advance section");
        }
        const size_t expected = section_ == Section::kBits ? bit_count_ :
            (section_ == Section::kNoises ? noise_count_ : triple_count_);
        if (written_ != expected)
        {
            return set_error(error_message, "Preprocessing stream section closed before all entries were written");
        }
        if (section_ == Section::kBits)
        {
            section_ = Section::kNoises;
            written_ = 0;
            writer.write_pod(static_cast<uint64_t>(noise_count_));
        }
        else if (section_ == Section::kNoises)
        {
            section_ = Section::kTriples;
            written_ = 0;
            writer.write_pod(static_cast<uint64_t>(triple_count_));
        }
        else
        {
            section_ = Section::kDone;
            written_ = 0;
        }
    }
    return writer.ok() ? true : set_error(error_message, "Failed to advance preprocessing stream section");
}

bool PreprocessingStreamWriter::write_raw_bit(const SharedBitVector& bit, std::string* error_message)
{
    if (!advance_to(Section::kBits, error_message) || !ensure_section(Section::kBits, error_message))
    {
        return false;
    }
    BinaryWriter writer(&out_);
    writer.write_pod(bit.round_id);
    writer.write_pod(bit.sigma);
    write_ring_share_vector(&writer, bit.shares);
    ++written_;
    return writer.ok() ? true : set_error(error_message, "Failed to write preprocessing bit");
}

bool PreprocessingStreamWriter::write_noise(const SharedNoiseVector& noise, std::string* error_message)
{
    if (!advance_to(Section::kNoises, error_message) || !ensure_section(Section::kNoises, error_message))
    {
        return false;
    }
    BinaryWriter writer(&out_);
    write_noise_kind(&writer, noise.kind);
    writer.write_pod(noise.bound_bits);
    writer.write_pod(noise.round_id);
    writer.write_pod(noise.sigma);
    write_ring_share_vector(&writer, noise.shares);
    ++written_;
    return writer.ok() ? true : set_error(error_message, "Failed to write preprocessing noise");
}

bool PreprocessingStreamWriter::write_triple(const SharedTripleVector& triple, std::string* error_message)
{
    if (!advance_to(Section::kTriples, error_message) || !ensure_section(Section::kTriples, error_message))
    {
        return false;
    }
    BinaryWriter writer(&out_);
    writer.write_pod(triple.round_id);
    writer.write_pod(triple.sigma);
    write_triple_share_vector(&writer, triple.triples);
    ++written_;
    return writer.ok() ? true : set_error(error_message, "Failed to write preprocessing triple");
}

bool PreprocessingStreamWriter::close(std::string* error_message)
{
    if (!out_.is_open())
    {
        return true;
    }
    if (!advance_to(Section::kDone, error_message))
    {
        return false;
    }
    out_.close();
    section_ = Section::kClosed;
    return true;
}

size_t PreprocessingStreamReader::noise_count(NoiseKind kind, uint32_t bound_bits) const
{
    const PreprocessingNoiseKey key{kind, bound_bits};
    const auto it = noise_total_counts_.find(key);
    return it == noise_total_counts_.end() ? 0 : it->second;
}

bool PreprocessingStreamReader::open(const std::string& path, std::string* error_message)
{
    // Build lightweight cursors for each section/noise bucket in a single scan.
    // Subsequent reads only touch the requested stream of records.
    path_ = path;
    noise_segments_.clear();
    noise_total_counts_.clear();
    raw_bit_count_ = 0;
    raw_bits_remaining_ = 0;
    triple_count_ = 0;
    triples_remaining_ = 0;
    bit_in_.close();
    noise_in_.close();
    triple_in_.close();

    std::ifstream scan(path, std::ios::binary);
    if (!scan)
    {
        return set_error(error_message, "Failed to open preprocessing stream: " + path);
    }
    BinaryReader reader(&scan);
    uint32_t magic = 0;
    uint32_t version = 0;
    if (!reader.read_pod(&magic) || !reader.read_pod(&version))
    {
        return set_error(error_message, "Failed to read preprocessing stream header: " + path);
    }
    if (magic != kPreprocMagic)
    {
        return set_error(error_message, "Unexpected preprocessing stream file type: " + path);
    }
    if (version != kFormatVersion)
    {
        return set_error(error_message, "Unsupported preprocessing stream version: " + path);
    }
    if (!read_plan(&reader, &plan_) ||
        !reader.read_pod(&seed_.low) ||
        !reader.read_pod(&seed_.high))
    {
        return set_error(error_message, "Failed to read preprocessing stream metadata: " + path);
    }

    uint64_t size = 0;
    if (!reader.read_pod(&size))
    {
        return set_error(error_message, "Failed to read preprocessing bit count: " + path);
    }
    raw_bit_count_ = static_cast<size_t>(size);
    raw_bits_remaining_ = raw_bit_count_;
    raw_bits_offset_ = scan.tellg();
    for (uint64_t i = 0; i < size; ++i)
    {
        if (!skip_bit_record(&reader))
        {
            return set_error(error_message, "Failed to scan preprocessing bits: " + path);
        }
    }

    if (!reader.read_pod(&size))
    {
        return set_error(error_message, "Failed to read preprocessing noise count: " + path);
    }
    std::map<PreprocessingNoiseKey, std::streampos> last_noise_end;
    for (uint64_t i = 0; i < size; ++i)
    {
        const std::streampos record_offset = scan.tellg();
        NoiseKind kind = NoiseKind::kLwe;
        uint32_t bound_bits = 0;
        if (!skip_noise_record(&reader, &kind, &bound_bits))
        {
            return set_error(error_message, "Failed to scan preprocessing noises: " + path);
        }
        const std::streampos record_end = scan.tellg();
        const PreprocessingNoiseKey key{kind, bound_bits};
        auto& segments = noise_segments_[key];
        const auto last_it = last_noise_end.find(key);
        if (!segments.empty() && last_it != last_noise_end.end() && last_it->second == record_offset)
        {
            ++segments.back().remaining;
        }
        else
        {
            segments.push_back(Segment{record_offset, 1});
        }
        last_noise_end[key] = record_end;
        ++noise_total_counts_[key];
    }

    if (!reader.read_pod(&size))
    {
        return set_error(error_message, "Failed to read preprocessing triple count: " + path);
    }
    triple_count_ = static_cast<size_t>(size);
    triples_remaining_ = triple_count_;
    triple_offset_ = scan.tellg();

    bit_in_.open(path, std::ios::binary);
    noise_in_.open(path, std::ios::binary);
    triple_in_.open(path, std::ios::binary);
    if (!bit_in_ || !noise_in_ || !triple_in_)
    {
        return set_error(error_message, "Failed to open preprocessing stream cursors: " + path);
    }
    bit_in_.seekg(raw_bits_offset_);
    triple_in_.seekg(triple_offset_);
    if (!bit_in_.good() || !triple_in_.good())
    {
        return set_error(error_message, "Failed to seek preprocessing stream cursors: " + path);
    }
    return true;
}

bool PreprocessingStreamReader::next_raw_bit(SharedBitVector* bit, std::string* error_message)
{
    if (raw_bits_remaining_ == 0)
    {
        return set_error(error_message, "Exhausted preprocessing raw bits");
    }
    BinaryReader reader(&bit_in_);
    if (!read_bit_record(&reader, bit))
    {
        return set_error(error_message, "Failed to read preprocessing raw bit");
    }
    --raw_bits_remaining_;
    return true;
}

bool PreprocessingStreamReader::next_noise(
    NoiseKind kind,
    uint32_t bound_bits,
    SharedNoiseVector* noise,
    std::string* error_message)
{
    const PreprocessingNoiseKey key{kind, bound_bits};
    auto it = noise_segments_.find(key);
    if (it == noise_segments_.end() || it->second.empty())
    {
        return set_error(error_message, "Exhausted preprocessing noise pool");
    }
    auto& segment = it->second.front();
    noise_in_.clear();
    noise_in_.seekg(segment.offset);
    BinaryReader reader(&noise_in_);
    if (!read_noise_record(&reader, noise))
    {
        return set_error(error_message, "Failed to read preprocessing noise");
    }
    if (noise->kind != kind || noise->bound_bits != bound_bits)
    {
        return set_error(error_message, "Preprocessing noise cursor read wrong kind/bound");
    }
    segment.offset = noise_in_.tellg();
    --segment.remaining;
    if (segment.remaining == 0)
    {
        it->second.erase(it->second.begin());
    }
    return true;
}

bool PreprocessingStreamReader::next_triple(SharedTripleVector* triple, std::string* error_message)
{
    if (triples_remaining_ == 0)
    {
        return set_error(error_message, "Exhausted preprocessing triples");
    }
    BinaryReader reader(&triple_in_);
    if (!read_triple_record(&reader, triple))
    {
        return set_error(error_message, "Failed to read preprocessing triple");
    }
    --triples_remaining_;
    return true;
}

bool PublicKeyStreamWriter::open(
    const std::string& path,
    const DkgPlan& plan,
    const PublicSeed& public_seed,
    const PublicKeyStreamCounts& counts,
    std::string* error_message)
{
    // The public key is emitted once in a deterministic section order so large
    // structures (BK, BK_SNS, SnS compression) never need to coexist in memory.
    out_.open(path, std::ios::binary | std::ios::trunc);
    if (!out_)
    {
        return set_error(error_message, "Failed to open public key file for streaming: " + path);
    }

    counts_ = counts;
    section_ = Section::kPk;
    written_ = 0;
    wrote_sns_compression_key_ = false;
    streaming_sns_compression_key_ = false;
    sns_blocks_expected_ = 0;
    sns_blocks_written_ = 0;

    BinaryWriter writer(&out_);
    writer.write_pod(kPublicKeyMagic);
    writer.write_pod(kFormatVersion);
    write_plan(&writer, plan);
    writer.write_pod(public_seed.low);
    writer.write_pod(public_seed.high);
    write_section_count(&writer, counts_, Section::kPk);
    if (!writer.ok())
    {
        section_ = Section::kClosed;
        out_.close();
        return set_error(error_message, "Failed to write public key stream header: " + path);
    }
    return true;
}

bool PublicKeyStreamWriter::ensure_section(Section section, std::string* error_message) const
{
    if (!out_.is_open() || section_ == Section::kClosed || section_ == Section::kDone)
    {
        return set_error(error_message, "Public key stream is not open");
    }
    if (section_ != section)
    {
        return set_error(error_message, "Public key stream section order violation");
    }
    if (written_ >= expected_for_section(counts_, section))
    {
        return set_error(error_message, "Public key stream section has too many entries");
    }
    return true;
}

bool PublicKeyStreamWriter::advance_to(Section target, std::string* error_message)
{
    if (!out_.is_open())
    {
        return set_error(error_message, "Public key stream is not open");
    }

    BinaryWriter writer(&out_);
    while (section_ != target)
    {
        if (section_ == Section::kClosed || section_ == Section::kDone)
        {
            return set_error(error_message, "Public key stream cannot advance section");
        }
        if (section_ == Section::kSnsCompressionKey)
        {
            if (!wrote_sns_compression_key_)
            {
                SharedLwePackingKeyswitchKey empty_key;
                write_lwe_packing_keyswitch_key(&writer, empty_key);
                wrote_sns_compression_key_ = true;
            }
            section_ = Section::kDone;
            written_ = 0;
            break;
        }
        const size_t expected = expected_for_section(counts_, section_);
        if (written_ != expected)
        {
            return set_error(error_message, "Public key stream section closed before all entries were written");
        }
        section_ = next_section(section_);
        written_ = 0;
        if (section_ != Section::kSnsCompressionKey && section_ != Section::kDone)
        {
            write_section_count(&writer, counts_, section_);
        }
    }
    return writer.ok() ? true : set_error(error_message, "Failed to advance public key stream section");
}

bool PublicKeyStreamWriter::write_pk(const SharedLweCiphertext& ciphertext, std::string* error_message)
{
    if (!advance_to(Section::kPk, error_message) || !ensure_section(Section::kPk, error_message))
    {
        return false;
    }
    BinaryWriter writer(&out_);
    write_lwe_ciphertext(&writer, ciphertext);
    ++written_;
    return writer.ok() ? true : set_error(error_message, "Failed to write pk ciphertext");
}

bool PublicKeyStreamWriter::write_pksk_lwe(const SharedLevCiphertext& ciphertext, std::string* error_message)
{
    if (!advance_to(Section::kPkskLwe, error_message) || !ensure_section(Section::kPkskLwe, error_message))
    {
        return false;
    }
    BinaryWriter writer(&out_);
    write_lev_ciphertext(&writer, ciphertext);
    ++written_;
    return writer.ok() ? true : set_error(error_message, "Failed to write pksk_lwe ciphertext");
}

bool PublicKeyStreamWriter::write_pksk_glwe(const SharedGlevCiphertext& ciphertext, std::string* error_message)
{
    if (!advance_to(Section::kPkskGlwe, error_message) || !ensure_section(Section::kPkskGlwe, error_message))
    {
        return false;
    }
    BinaryWriter writer(&out_);
    write_glev_ciphertext(&writer, ciphertext);
    ++written_;
    return writer.ok() ? true : set_error(error_message, "Failed to write pksk_glwe ciphertext");
}

bool PublicKeyStreamWriter::write_ksk(const SharedLevCiphertext& ciphertext, std::string* error_message)
{
    if (!advance_to(Section::kKsk, error_message) || !ensure_section(Section::kKsk, error_message))
    {
        return false;
    }
    BinaryWriter writer(&out_);
    write_lev_ciphertext(&writer, ciphertext);
    ++written_;
    return writer.ok() ? true : set_error(error_message, "Failed to write ksk ciphertext");
}

bool PublicKeyStreamWriter::write_bk(const SharedGgswCiphertext& ciphertext, std::string* error_message)
{
    if (!advance_to(Section::kBk, error_message) || !ensure_section(Section::kBk, error_message))
    {
        return false;
    }
    BinaryWriter writer(&out_);
    write_ggsw_ciphertext(&writer, ciphertext);
    ++written_;
    return writer.ok() ? true : set_error(error_message, "Failed to write bk ciphertext");
}

bool PublicKeyStreamWriter::write_bk_sns(const SharedGgswCiphertext& ciphertext, std::string* error_message)
{
    if (!advance_to(Section::kBkSns, error_message) || !ensure_section(Section::kBkSns, error_message))
    {
        return false;
    }
    BinaryWriter writer(&out_);
    write_ggsw_ciphertext(&writer, ciphertext);
    ++written_;
    return writer.ok() ? true : set_error(error_message, "Failed to write bk_sns ciphertext");
}

bool PublicKeyStreamWriter::write_compression_key(const SharedGgswCiphertext& ciphertext, std::string* error_message)
{
    if (!advance_to(Section::kCompressionKey, error_message) || !ensure_section(Section::kCompressionKey, error_message))
    {
        return false;
    }
    BinaryWriter writer(&out_);
    write_ggsw_ciphertext(&writer, ciphertext);
    ++written_;
    return writer.ok() ? true : set_error(error_message, "Failed to write compression key ciphertext");
}

bool PublicKeyStreamWriter::write_decompression_key(const SharedGlevCiphertext& ciphertext, std::string* error_message)
{
    if (!advance_to(Section::kDecompressionKey, error_message) || !ensure_section(Section::kDecompressionKey, error_message))
    {
        return false;
    }
    BinaryWriter writer(&out_);
    write_glev_ciphertext(&writer, ciphertext);
    ++written_;
    return writer.ok() ? true : set_error(error_message, "Failed to write decompression key ciphertext");
}

bool PublicKeyStreamWriter::write_sns_compression_key(
    const SharedLwePackingKeyswitchKey& key,
    std::string* error_message)
{
    if (!begin_sns_compression_key(
            key.input_lwe_dimension,
            key.output_glwe_dimension,
            key.output_polynomial_size,
            key.base_log,
            key.level_count,
            error_message))
    {
        return false;
    }
    for (const auto& block : key.blocks)
    {
        if (!write_sns_compression_block(block, error_message))
        {
            return false;
        }
    }
    return true;
}

bool PublicKeyStreamWriter::begin_sns_compression_key(
    size_t input_lwe_dimension,
    size_t output_glwe_dimension,
    size_t output_polynomial_size,
    size_t base_log,
    size_t level_count,
    std::string* error_message)
{
    if (!advance_to(Section::kSnsCompressionKey, error_message))
    {
        return false;
    }
    if (wrote_sns_compression_key_ || streaming_sns_compression_key_)
    {
        return set_error(error_message, "Public key stream sns compression key was already started");
    }
    BinaryWriter writer(&out_);
    writer.write_pod(static_cast<uint64_t>(input_lwe_dimension));
    writer.write_pod(static_cast<uint64_t>(output_glwe_dimension));
    writer.write_pod(static_cast<uint64_t>(output_polynomial_size));
    writer.write_pod(static_cast<uint64_t>(base_log));
    writer.write_pod(static_cast<uint64_t>(level_count));
    writer.write_pod(static_cast<uint64_t>(input_lwe_dimension));
    streaming_sns_compression_key_ = true;
    sns_blocks_expected_ = input_lwe_dimension;
    sns_blocks_written_ = 0;
    return writer.ok() ? true : set_error(error_message, "Failed to begin sns compression key stream");
}

bool PublicKeyStreamWriter::write_sns_compression_block(
    const SharedPackingKeyswitchBlock& block,
    std::string* error_message)
{
    // SnS compression is written block-by-block because it is the largest key
    // component in the BC_PARAMS_SNS pipeline.
    if (section_ != Section::kSnsCompressionKey || !streaming_sns_compression_key_)
    {
        return set_error(error_message, "Public key stream sns compression key was not started");
    }
    if (sns_blocks_written_ >= sns_blocks_expected_)
    {
        return set_error(error_message, "Public key stream has too many sns compression blocks");
    }
    BinaryWriter writer(&out_);
    write_vector(&writer, block.polynomial_entries, write_glev_ciphertext);
    ++sns_blocks_written_;
    if (sns_blocks_written_ == sns_blocks_expected_)
    {
        wrote_sns_compression_key_ = true;
        streaming_sns_compression_key_ = false;
        section_ = Section::kDone;
    }
    return writer.ok() ? true : set_error(error_message, "Failed to write sns compression block");
}

bool PublicKeyStreamWriter::close(std::string* error_message)
{
    if (!out_.is_open())
    {
        return true;
    }
    if (streaming_sns_compression_key_)
    {
        return set_error(error_message, "Public key stream sns compression key closed before all blocks were written");
    }
    if (section_ == Section::kDone)
    {
        out_.close();
        return true;
    }
    if (!advance_to(Section::kSnsCompressionKey, error_message))
    {
        return false;
    }
    if (!wrote_sns_compression_key_)
    {
        BinaryWriter writer(&out_);
        SharedLwePackingKeyswitchKey empty_key;
        write_lwe_packing_keyswitch_key(&writer, empty_key);
        wrote_sns_compression_key_ = true;
        if (!writer.ok())
        {
            return set_error(error_message, "Failed to write default sns compression key");
        }
    }
    section_ = Section::kDone;
    out_.close();
    return true;
}

bool PublicKeyStreamWriter::ok() const
{
    return out_.is_open() && out_.good();
}

bool save_secret_key_file(
    const std::string& path,
    const SecretKeyBundle& bundle,
    std::string* error_message)
{
    return save_file(
        path,
        kSecretKeyMagic,
        [&](BinaryWriter* writer) { write_secret_key_bundle(writer, bundle); },
        error_message);
}

bool load_secret_key_file(
    const std::string& path,
    SecretKeyBundle* bundle,
    std::string* error_message)
{
    if (bundle == nullptr)
    {
        return set_error(error_message, "Null output passed to load_secret_key_file");
    }
    return load_file(
        path,
        kSecretKeyMagic,
        [&](BinaryReader* reader) { return read_secret_key_bundle(reader, bundle); },
        error_message);
}

bool save_public_key_file(
    const std::string& path,
    const PublicKeyBundle& bundle,
    std::string* error_message)
{
    return save_file(
        path,
        kPublicKeyMagic,
        [&](BinaryWriter* writer) { write_public_key_bundle(writer, bundle); },
        error_message);
}

bool load_public_key_file(
    const std::string& path,
    PublicKeyBundle* bundle,
    std::string* error_message)
{
    if (bundle == nullptr)
    {
        return set_error(error_message, "Null output passed to load_public_key_file");
    }
    return load_file(
        path,
        kPublicKeyMagic,
        [&](BinaryReader* reader) { return read_public_key_bundle(reader, bundle); },
        error_message);
}
} // namespace dkg
} // namespace host
