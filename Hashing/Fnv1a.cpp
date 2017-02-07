#include "Fnv1a.hpp"
#include <cstdint>

namespace JMlib
{
    namespace hashing
    {
        namespace detail
        {
            template<std::size_t N>
            struct FnvParams
            {

            };
            template<>
            struct FnvParams<4>
            {
                static const constexpr std::uint32_t prime = 16777619ul;
                static const constexpr std::uint32_t offset = 2166136261ul;
            };
            template<>
            struct FnvParams<8>
            {
                static const constexpr std::uint64_t prime = 1099511628211ull;
                static const constexpr std::uint64_t offset = 14695981039346656037ull;
            };
            using fnv_params = FnvParams<sizeof(std::size_t)>;
        }

        constexpr std::size_t offsetBasis() noexcept
        {
            return detail::fnv_params::offset;
        }

        fnv1a::operator result_type() noexcept
        {
            return hashState;
        }

        void fnv1a::operator()(const void* d, std::size_t s) noexcept
        {
            auto rawBytes = reinterpret_cast<const unsigned char*>(d);
            auto state = hashState;

            for (auto first = rawBytes; first != (rawBytes + s); ++first)
            {
                state ^= static_cast<std::size_t>(*first);
                state *= detail::fnv_params::prime;
            }

            hashState = state;
        }

        void fnv1a::Reset() noexcept
        {
            hashState = detail::fnv_params::offset;
        }
    }
}