#include "HashAdaptor.hpp"
#include "HashSupport.hpp"
#include <algorithm>
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <random>
#include <unordered_set>
#include <utility>
#include <vector>

template<typename I, typename P>
auto FindLongestSequence(I first, I last, P pred)
{
	if (first == last) return std::make_pair(last, last);

	auto seqBeg = first;
	auto seqEnd = ++first;
	std::size_t currentLen = 1u;

	std::size_t longestLen = 1u;
	auto longest = std::make_pair(first, seqEnd);
	while (seqEnd != last)
	{
		if (!pred(*seqBeg, *seqEnd))
		{
			if (currentLen > longestLen)
			{
				longestLen = currentLen;
				longest.first = seqBeg;
				longest.second = seqEnd;
			}
			seqBeg = seqEnd;
			currentLen = 0;
		}

		++seqEnd;
		++currentLen;
	}

	if (currentLen > longestLen)
	{
		longest.first = seqBeg;
		longest.second = seqEnd;
	}

	return longest;
}

int main()
{
	using namespace std;
    using namespace JMlib::hashing;
	
	int bound = 0x110000l;

	unordered_set<int, hash_functor<sha256>> specialSet;
	std::vector<int> collisions;
	collisions.reserve(0x10000);

	std::size_t runs = 0;
	std::size_t runLimit = 1;
	while (runs < runLimit)
	{
		++runs;
		collisions.clear();
		specialSet.clear();
		for (int i = 0; i < bound; ++i)
		{
			auto nextRN = i;
			auto insertRes = specialSet.insert(nextRN);
			if (!insertRes.second)
			{
				collisions.push_back(nextRN);
			}
		}

		std::sort(collisions.begin(), collisions.end());

		auto colSeq = FindLongestSequence(collisions.begin(), collisions.end(), std::equal_to<>{});

		if (colSeq.first != colSeq.second)
		{
			break;
		}
	}

	std::cout << "After " << runs << " runs of " << bound << " iterations, Total collisions = " << collisions.size() << std::endl;
	std::cout << "Container load factor: " << specialSet.load_factor() << std::endl;

	auto colSeq = FindLongestSequence(collisions.begin(), collisions.end(), std::equal_to<>{});
	if (colSeq.first != colSeq.second)
	{
		std::cout << "Most common collision with value " << *colSeq.first
			<< ". Collision count: " << std::distance(colSeq.first, colSeq.second) << std::endl;
	}

	auto bucketCount = specialSet.bucket_count();
	long long overflowingBucketCount = 0;
	long long maxOverflowingBucket = 0;

	for (int i = 0; i < int(bucketCount); ++i)
	{
		auto bucketSize = static_cast<long long>(specialSet.bucket_size(i));
		if (bucketSize <= 1) continue;

		++overflowingBucketCount;
		if (bucketSize > maxOverflowingBucket)
		{
			maxOverflowingBucket = bucketSize;
		}
	}	

	std::cout << "Overflowed buckets: " << overflowingBucketCount << std::endl;
	std::cout << "Max overflow: " << maxOverflowingBucket << std::endl;

	return 0;
}