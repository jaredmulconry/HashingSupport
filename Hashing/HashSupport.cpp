#include "HashSupport.hpp"
#include <algorithm>
#include <cstdlib>
#include <functional>

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

            template<typename T>
            T ReverseBytes(T d) noexcept
            {
                static_assert(std::is_unsigned<T>::value, "Unsigned integral types only");
                if (sizeof(T) == 1) return d;
                T result;
                static const constexpr T lowBitMask = 0xFFu;
                static const constexpr int sizeOffset = sizeof(T) - 1;
                uint8_t* rawBytes = reinterpret_cast<uint8_t*>(&result);
                for (unsigned long i = 0; i < sizeof(T); ++i)
                {
                    int outPos = sizeOffset - i;
                    int inPos = i * 8;
                    rawBytes[outPos] = static_cast<std::uint8_t>((d >> inPos) & lowBitMask);
                }
                return result;
            }

            template<typename T>
            constexpr T RotateRight(T d, unsigned long int n) noexcept
            {
                return (d >> n) | (d << (sizeof(T) * 8 - n));
            }
            template<typename T>
            constexpr T RotateLeft(T d, unsigned long int n) noexcept
            {
                return (d << n) | (d >> (sizeof(T) * 8 - n));
            }
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

        using state_type = std::uint32_t;
        static const constexpr state_type K[64]
        {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

        constexpr std::uint32_t Ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
        {
            return (x & y) ^ ((~x) & z);
        }
        constexpr std::uint32_t Maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }
        constexpr std::uint32_t USig0(std::uint32_t x) noexcept
        {
            return detail::RotateRight(x, 2) ^ detail::RotateRight(x, 13) ^ detail::RotateRight(x, 22);
        }
        constexpr std::uint32_t USig1(std::uint32_t x) noexcept
        {
            return detail::RotateRight(x, 6) ^ detail::RotateRight(x, 11) ^ detail::RotateRight(x, 25);
        }
        constexpr std::uint32_t LSig0(std::uint32_t x) noexcept
        {
            return detail::RotateRight(x, 7) ^ detail::RotateRight(x, 18) ^ (x >> 3u);
        }
        constexpr std::uint32_t LSig1(std::uint32_t x) noexcept
        {
            return detail::RotateRight(x, 17) ^ detail::RotateRight(x, 19) ^ (x >> 10u);
        }
        void sha256::Transform(const unsigned char* data) noexcept
        {
            enum MixNames : int
            {
                a = 0,
                b,
                c,
                d,
                e,
                f,
                g,
                h,
            };
            state_type m[message_len];

            static const constexpr int prepPoint = 16;
            for (int i = 0; i < prepPoint; )
            {
#define M_INIT(I1) \
                m[(I1)] = (state_type(data[(I1) * 4]) << 24) \
                    | (state_type(data[((I1) * 4) + 1]) << 16) \
                    | (state_type(data[((I1) * 4) + 2]) << 8) \
                    | state_type(data[((I1) * 4) + 3])

                M_INIT(i);
                M_INIT(i + 1);
                M_INIT(i + 2);
                M_INIT(i + 3);

                i += 4;
#undef M_INIT
            }

            for (int i = prepPoint; i < message_len; i += 2)
            {
                auto v1 = LSig0(m[(i)-15]);
                auto v2 = m[(i)-16];
                auto s1 = v1 + v2;

                auto v3 = LSig1(m[(i)-2]);
                auto v4 = m[(i)-7];
                auto s2 = v3 + v4;

                m[(i)] = s1 + s2;
            }
            
            state_type stateMix[stateSize];

            std::memcpy(stateMix, hashState, sizeof(stateMix));

            for (int i = 0; i < message_len; ++i)
            {
                auto t1 = stateMix[h] + USig1(stateMix[e])
                    + Ch(stateMix[e], stateMix[f], stateMix[g])
                    + K[i] + m[i];
                auto t2 = USig0(stateMix[a])
                    + Maj(stateMix[a], stateMix[b], stateMix[c]);

                stateMix[h] = stateMix[g];
                stateMix[g] = stateMix[f];
                stateMix[f] = stateMix[e];
                stateMix[e] = stateMix[d] + t1;
                stateMix[d] = stateMix[c];
                stateMix[c] = stateMix[b];
                stateMix[b] = stateMix[a];
                stateMix[a] = t1 + t2;
            }
            for (int i = 0; i < stateSize; ++i)
            {
                hashState[i] += stateMix[i];
            }
        }
        sha256::operator result_type() noexcept
        {
            static const constexpr int cacheCutoff = 56;
            static const constexpr unsigned long long lowBitsMask = 0xFFu;

            auto finalLength = cacheMsgLen;
            messageCache[finalLength] = 0b1000'0000u;
            if (finalLength++ < cacheCutoff)
            {
                auto zeroSpace = cacheCutoff - finalLength;
                std::memset(messageCache + finalLength, 0, zeroSpace);
            }
            else
            {
                auto zeroSpace = message_len - finalLength;
                std::memset(messageCache + finalLength, 0, zeroSpace);
                Transform(messageCache);
                std::memset(messageCache, 0, cacheCutoff);
            }

            totalMsgBitLen += cacheMsgLen * 8;

            messageCache[63] = static_cast<unsigned char>(totalMsgBitLen);
            messageCache[62] = static_cast<unsigned char>(totalMsgBitLen >> 8);
            messageCache[61] = static_cast<unsigned char>(totalMsgBitLen >> 16);
            messageCache[60] = static_cast<unsigned char>(totalMsgBitLen >> 24);
            messageCache[59] = static_cast<unsigned char>(totalMsgBitLen >> 32);
            messageCache[58] = static_cast<unsigned char>(totalMsgBitLen >> 40);
            messageCache[57] = static_cast<unsigned char>(totalMsgBitLen >> 48);
            messageCache[56] = static_cast<unsigned char>(totalMsgBitLen >> 56);
            Transform(messageCache);

            state_type resultHash[stateSize];

            for (int i = 0; i < stateSize; ++i)
            {
                resultHash[i] = detail::ReverseBytes(hashState[i]);
            }

            result_type output;
            std::memcpy(&output, resultHash, sizeof(result_type));
            return output;
        }
        void sha256::operator()(const void* d, std::size_t n) noexcept
        {
            auto rawBytes = reinterpret_cast<const unsigned char*>(d);

            if (long long(n) - long long(cacheMsgLen) >= long long(message_len))
            {
                auto freeSpace = message_len - cacheMsgLen;
                std::memcpy(messageCache + cacheMsgLen, rawBytes, freeSpace);
                rawBytes += freeSpace;
                n -= freeSpace;
                totalMsgBitLen += message_bit_len;
                cacheMsgLen = 0;

                Transform(messageCache);
            }

            auto fullChunks = n / message_len;
            for (long long i = 0; i < long long(fullChunks); ++i)
            {
                std::memcpy(messageCache, rawBytes, message_len);
                rawBytes += message_len;
                n -= message_len;
                totalMsgBitLen += message_bit_len;

                Transform(messageCache);
            }

            std::memcpy(messageCache, rawBytes, n);
            cacheMsgLen += static_cast<int>(n);
        }
        void sha256::Reset() noexcept
        {
            hashState[0] = 0x6a09e667;
            hashState[1] = 0xbb67ae85;
            hashState[2] = 0x3c6ef372;
            hashState[3] = 0xa54ff53a;
            hashState[4] = 0x510e527f;
            hashState[5] = 0x9b05688c;
            hashState[6] = 0x1f83d9ab;
            hashState[7] = 0x5be0cd19;

            cacheMsgLen = 0;
            std::memset(messageCache, 0, sizeof(messageCache));
        }
    }
}
