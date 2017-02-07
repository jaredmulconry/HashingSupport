#pragma once
#include <cstddef>

namespace JMlib
{
    namespace hashing
    {
        class fnv1a
        {
            friend constexpr std::size_t offsetBasis() noexcept;
            std::size_t hashState = offsetBasis();
        public:
            using result_type = std::size_t;

            explicit operator result_type() noexcept;

            void operator()(const void*, std::size_t) noexcept;
            void Reset() noexcept;
        };
    }
}