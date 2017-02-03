#pragma once
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <utility>

namespace HashSupport
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
			static const constexpr unsigned long prime = 16777619ul;
			static const constexpr unsigned long offset = 2166136261ul;
		};
		template<>
		struct FnvParams<8>
		{
			static const constexpr unsigned long long prime = 1099511628211ull;
			static const constexpr unsigned long long offset = 14695981039346656037ull;
		};

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
				rawBytes[outPos] = static_cast<uint8_t>((d >> inPos) & lowBitMask);
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
	class fnv1a
	{
		static const constexpr std::size_t fnvPrime = detail::FnvParams<sizeof(std::size_t)>::prime;
		static const constexpr std::size_t offsetBasis = detail::FnvParams<sizeof(std::size_t)>::offset;
		std::size_t hashState = offsetBasis;
	public:
		using result_type = std::size_t;

		explicit operator result_type() noexcept;

		void operator()(const void*, std::size_t) noexcept;
		void Reset() noexcept;
	};

	class sha256
	{
		using state_type = unsigned long int;

		static const constexpr int stateSize = 8;
		static const constexpr int message_len = 64;
		static const constexpr int message_bit_len = message_len * 8;

		unsigned char messageCache[message_len];
		state_type hashState[stateSize]
		{	
			0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
		};
		unsigned long long int totalMsgBitLen = 0;
		int cacheMsgLen = 0;
		

		static constexpr state_type Ch(state_type a, state_type b, state_type c) noexcept;
		static constexpr state_type Maj(state_type a, state_type b, state_type c) noexcept;
		static constexpr state_type USig0(state_type x) noexcept;
		static constexpr state_type USig1(state_type x) noexcept;
		static constexpr state_type LSig0(state_type x) noexcept;
		static constexpr state_type LSig1(state_type x) noexcept;

		void Transform(const unsigned char* d) noexcept;
	public:
		using result_type = std::size_t;
		static const constexpr std::size_t digest_size = 32;

		explicit operator result_type() noexcept;

		void operator()(const void*, std::size_t) noexcept;
		void Reset() noexcept;
	};

	template<typename H>
	struct hash_functor
	{
		using result_type = std::size_t;

		template<typename U>
		std::size_t operator()(const U& d) const noexcept
		{
			H hasher;

			hash_append(hasher, d);

			return static_cast<std::size_t>(hasher);
		}
	};

	template<typename T>
	using is_contiguously_hashable = std::integral_constant<bool, std::is_integral<T>::value
		|| std::is_pointer<T>::value>;

	template<typename H>
	void hash_append(H&& hFunc, const void* p, std::size_t s)
	{
		std::forward<H>(hFunc)(p, s);
	}

	template<typename H, typename T>
	std::enable_if_t<is_contiguously_hashable<T>::value>
		hash_append(H&& hFunc, T i)
	{
		hash_append(std::forward<H>(hFunc), &i, sizeof(T));
	}

	template<typename H, typename T>
	std::enable_if_t<std::is_enum<T>::value>
		hash_append(H&& hFunc, T i)
	{
		using internal_t = std::underlying_type_t<T>;
		hash_append(std::forward<H>(hFunc), static_cast<internal_t>(i));
	}
}