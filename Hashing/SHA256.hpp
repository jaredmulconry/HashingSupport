#pragma once
#include <cstddef>
#include <cstdint>

namespace JMlib
{
    namespace hashing
    {
        class sha256
        {
            static const constexpr int stateSize = 8;
            static const constexpr int message_len = 64;
            static const constexpr int message_bit_len = message_len * 8;

            unsigned char messageCache[message_len];
            std::uint32_t hashState[stateSize]
            {
                0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul,
                0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul
            };
            std::uint64_t totalMsgBitLen = 0u;
            int cacheMsgLen = 0;

            void Transform(const unsigned char* d) noexcept;
        public:
            using result_type = std::size_t;
            static const constexpr std::size_t digest_size = 32ul;

            explicit operator result_type() noexcept;

            void operator()(const void*, std::size_t) noexcept;
            void Reset() noexcept;
        };
    }
}