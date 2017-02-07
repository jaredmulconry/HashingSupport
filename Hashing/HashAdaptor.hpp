#pragma once
#include <cstddef>
#include <type_traits>
#include <utility>

namespace JMlib
{
    namespace hashing
    {
        namespace detail
        {
            template<typename T>
            constexpr bool is_trivially_hashable() noexcept
            {
                return std::is_integral<T>::value
                    || std::is_pointer<T>::value || std::is_enum<T>::value;
            }
        }
        template<typename T>
        struct is_contiguously_hashable_helper : public std::bool_constant<detail::is_trivially_hashable<T>()>
        {

        };

        template<typename T>
        struct is_contiguously_hashable : public is_contiguously_hashable_helper<std::remove_cv_t<std::remove_reference_t<T>>>
        {

        };
        template<typename T, std::size_t N>
        struct is_contiguously_hashable<T[N]> : public is_contiguously_hashable_helper<std::remove_cv_t<std::remove_reference_t<T>>>
        {

        };
        template<typename T>
        struct is_contiguously_hashable<T[]> : public is_contiguously_hashable_helper<std::remove_cv_t<std::remove_reference_t<T>>>
        {

        };

        template<typename H>
        void hash_append(H& hFunc, const void* p, std::size_t s)
        {
            hFunc(p, s);
        }

        template<typename H, typename T>
        std::enable_if_t < is_contiguously_hashable<T>::value >
            hash_append(H& hFunc, const T& i)
        {
            hash_append(hFunc, &i, sizeof(T));
        }

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
    }
}