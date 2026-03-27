#include "serialization.hpp"

#include <cstdint>
#include <fstream>
#include <type_traits>

namespace host
{
namespace dkg
{
namespace
{
constexpr uint32_t kFormatVersion = 1;
constexpr uint32_t kPreprocMagic = 0x50525043; // PRPC
constexpr uint32_t kKeygenMagic = 0x4b455947;  // KEYG
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

void write_preprocessed_material(BinaryWriter* writer, const PreprocessedKeygenMaterial& material)
{
    writer->write_pod(material.seed.low);
    writer->write_pod(material.seed.high);

    writer->write_pod(static_cast<uint64_t>(material.raw_bits.size()));
    for (const auto& bit : material.raw_bits)
    {
        writer->write_pod(bit.round_id);
        writer->write_pod(bit.sigma);
        write_ring_share_vector(writer, bit.shares);
    }

    writer->write_pod(static_cast<uint64_t>(material.noises.size()));
    for (const auto& noise : material.noises)
    {
        write_noise_kind(writer, noise.kind);
        writer->write_pod(noise.bound_bits);
        writer->write_pod(noise.round_id);
        writer->write_pod(noise.sigma);
        write_ring_share_vector(writer, noise.shares);
    }

    writer->write_pod(static_cast<uint64_t>(material.triples.size()));
    for (const auto& triple : material.triples)
    {
        writer->write_pod(triple.round_id);
        writer->write_pod(triple.sigma);
        write_triple_share_vector(writer, triple.triples);
    }
}

bool read_preprocessed_material(BinaryReader* reader, PreprocessedKeygenMaterial* material)
{
    if (material == nullptr)
    {
        return false;
    }
    uint64_t size = 0;
    if (!reader->read_pod(&material->seed.low) || !reader->read_pod(&material->seed.high))
    {
        return false;
    }

    if (!reader->read_pod(&size))
    {
        return false;
    }
    material->raw_bits.assign(static_cast<size_t>(size), SharedBitVector{});
    for (auto& bit : material->raw_bits)
    {
        if (!reader->read_pod(&bit.round_id) ||
            !reader->read_pod(&bit.sigma) ||
            !read_ring_share_vector(reader, &bit.shares))
        {
            return false;
        }
    }

    if (!reader->read_pod(&size))
    {
        return false;
    }
    material->noises.assign(static_cast<size_t>(size), SharedNoiseVector{});
    for (auto& noise : material->noises)
    {
        if (!read_noise_kind(reader, &noise.kind) ||
            !reader->read_pod(&noise.bound_bits) ||
            !reader->read_pod(&noise.round_id) ||
            !reader->read_pod(&noise.sigma) ||
            !read_ring_share_vector(reader, &noise.shares))
        {
            return false;
        }
    }

    if (!reader->read_pod(&size))
    {
        return false;
    }
    material->triples.assign(static_cast<size_t>(size), SharedTripleVector{});
    for (auto& triple : material->triples)
    {
        if (!reader->read_pod(&triple.round_id) ||
            !reader->read_pod(&triple.sigma) ||
            !read_triple_share_vector(reader, &triple.triples))
        {
            return false;
        }
    }
    return true;
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

void write_keygen_output(BinaryWriter* writer, const KeygenOutput& output)
{
    write_plan(writer, output.plan);
    writer->write_pod(output.public_seed.low);
    writer->write_pod(output.public_seed.high);
    write_ring_share_vector(writer, output.secret_shares.lwe);
    write_ring_share_vector(writer, output.secret_shares.lwe_hat);
    write_ring_share_vector(writer, output.secret_shares.glwe);
    write_ring_share_vector(writer, output.secret_shares.compression_glwe);
    write_ring_share_vector(writer, output.secret_shares.sns_glwe);
    write_ring_share_vector(writer, output.secret_shares.sns_compression_glwe);

    write_vector(writer, output.public_material.pk, write_lwe_ciphertext);
    write_vector(writer, output.public_material.pksk_lwe, write_lev_ciphertext);
    write_vector(writer, output.public_material.pksk_glwe, write_glev_ciphertext);
    write_vector(writer, output.public_material.ksk, write_lev_ciphertext);
    write_vector(writer, output.public_material.bk, write_ggsw_ciphertext);
    write_vector(writer, output.public_material.bk_sns, write_ggsw_ciphertext);
    write_vector(writer, output.public_material.compression_key, write_ggsw_ciphertext);
    write_vector(writer, output.public_material.decompression_key, write_glev_ciphertext);
    write_vector(writer, output.public_material.sns_compression_key, write_ggsw_ciphertext);
}

bool read_keygen_output(BinaryReader* reader, KeygenOutput* output)
{
    return output != nullptr &&
        read_plan(reader, &output->plan) &&
        reader->read_pod(&output->public_seed.low) &&
        reader->read_pod(&output->public_seed.high) &&
        read_ring_share_vector(reader, &output->secret_shares.lwe) &&
        read_ring_share_vector(reader, &output->secret_shares.lwe_hat) &&
        read_ring_share_vector(reader, &output->secret_shares.glwe) &&
        read_ring_share_vector(reader, &output->secret_shares.compression_glwe) &&
        read_ring_share_vector(reader, &output->secret_shares.sns_glwe) &&
        read_ring_share_vector(reader, &output->secret_shares.sns_compression_glwe) &&
        read_vector(reader, &output->public_material.pk, read_lwe_ciphertext) &&
        read_vector(reader, &output->public_material.pksk_lwe, read_lev_ciphertext) &&
        read_vector(reader, &output->public_material.pksk_glwe, read_glev_ciphertext) &&
        read_vector(reader, &output->public_material.ksk, read_lev_ciphertext) &&
        read_vector(reader, &output->public_material.bk, read_ggsw_ciphertext) &&
        read_vector(reader, &output->public_material.bk_sns, read_ggsw_ciphertext) &&
        read_vector(reader, &output->public_material.compression_key, read_ggsw_ciphertext) &&
        read_vector(reader, &output->public_material.decompression_key, read_glev_ciphertext) &&
        read_vector(reader, &output->public_material.sns_compression_key, read_ggsw_ciphertext);
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
    write_vector(writer, bundle.public_material.sns_compression_key, write_ggsw_ciphertext);
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
        read_vector(reader, &bundle->public_material.sns_compression_key, read_ggsw_ciphertext);
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

bool save_preprocessing_bundle(
    const std::string& path,
    const DkgPlan& plan,
    const PreprocessedKeygenMaterial& material,
    std::string* error_message)
{
    return save_file(
        path,
        kPreprocMagic,
        [&](BinaryWriter* writer) {
            write_plan(writer, plan);
            write_preprocessed_material(writer, material);
        },
        error_message);
}

bool load_preprocessing_bundle(
    const std::string& path,
    DkgPlan* plan,
    PreprocessedKeygenMaterial* material,
    std::string* error_message)
{
    if (plan == nullptr || material == nullptr)
    {
        return set_error(error_message, "Null output passed to load_preprocessing_bundle");
    }
    return load_file(
        path,
        kPreprocMagic,
        [&](BinaryReader* reader) {
            return read_plan(reader, plan) &&
                read_preprocessed_material(reader, material);
        },
        error_message);
}

bool save_keygen_output_file(
    const std::string& path,
    const KeygenOutput& output,
    std::string* error_message)
{
    return save_file(
        path,
        kKeygenMagic,
        [&](BinaryWriter* writer) { write_keygen_output(writer, output); },
        error_message);
}

bool load_keygen_output_file(
    const std::string& path,
    KeygenOutput* output,
    std::string* error_message)
{
    if (output == nullptr)
    {
        return set_error(error_message, "Null output passed to load_keygen_output_file");
    }
    return load_file(
        path,
        kKeygenMagic,
        [&](BinaryReader* reader) { return read_keygen_output(reader, output); },
        error_message);
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
