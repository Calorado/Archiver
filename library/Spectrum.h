/*
 * Spectrum Preprocessor v0.3
 * Copyright (c) 2022 Carlos de Diego
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef __SPECTRUM__

#define __SPECTRUM__

#include <cstdint>
#include <stdio.h> //size_t
#include <string>

namespace spectrum {

	struct EncoderOptions {
		//Used to determine whether a filter actually helps. Should return an estimated compressed size. 
		//Encoding is faster if none is used.
		size_t(*backendCompressor)(const uint8_t*, const size_t) = nullptr;
		//Size of the division to test delta filters
		size_t blockSize = 16384;
		//Size of compressed block with lpc order 1 filter (equivalent of delta filter)
		// must be at least this number of bytes smaller than the compressed version without lpc filter.
		size_t lpcO1Threshold = 512;
		size_t lpcO2Threshold = 256;
		size_t lpcO3Threshold = 0;
		//Brute force detection of some parameters. Slower, but can give better compression
		bool bruteForce = false;
	};
	//Encodes "size" bytes of data present in "input", and stores it in "output".
	size_t encode(const uint8_t* input, const size_t size, uint8_t* output, EncoderOptions options = EncoderOptions());
	//Decodes contents in "encoded" to "decoded".
	//Returns 0 on success or -1 on failure or corrupted data.
	int decode(const uint8_t* encoded, const size_t encodedSize, uint8_t* decoded, const size_t decodedSize);

	//For a given input size, returns a size for the output buffer that is big enough to
	// contain the processed stream.
	size_t bound(const size_t size);
}

#ifdef SPECTRUM_IMPLEMENTATION

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <bitset>
#include <memory>

#if defined(_MSC_VER)
	#define FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
	#define FORCE_INLINE inline __attribute__((always_inline))
#else
	#define FORCE_INLINE inline
#endif

#if defined(__GNUC__) || defined(__clang__)
	#define expect(expr,value)    (__builtin_expect ((expr),(value)) )
	#define likely(expr)     expect((expr) != 0, 1)
	#define unlikely(expr)   expect((expr) != 0, 0)
#else
	#define likely(expr)     (expr)
	#define unlikely(expr)   (expr)
#endif

//Probably not the correct way to do it but bleh
#define IS_64BIT (UINTPTR_MAX > UINT32_MAX)

#if defined(_MSC_VER)
	#if defined(_M_AMD64)
		#include <intrin.h>
		#define x64
	#endif
#elif defined(__GNUC__) || defined(__clang__)
	#if defined(__amd64__)
		#include <x86intrin.h>
		#define x64
	#endif
#endif

namespace spectrum {

	bool is_little_endian() {
		const union { uint16_t u; uint8_t c[2]; } LITTLE_ENDIAN_CHECK = { 1 };
		return LITTLE_ENDIAN_CHECK.c[0];
	}

//Undefined behaviour if value == 0
	FORCE_INLINE size_t unsafe_int_log2(size_t value) {
#if defined(_MSC_VER)
		unsigned long result;
	#if IS_64BIT
		_BitScanReverse64(&result, value);
	#else
		_BitScanReverse(&result, value);
	#endif
		return result;
#elif defined(__GNUC__) || defined(__clang__)
	#if IS_64BIT
		return 63 - __builtin_clzll(value);
	#else
		return 31 - __builtin_clz(value);
	#endif
#else
	#if IS_64BIT
		const uint8_t tab64[64] = {
			 0, 58,  1, 59, 47, 53,  2, 60,
			39, 48, 27, 54, 33, 42,  3, 61,
			51, 37, 40, 49, 18, 28, 20, 55,
			30, 34, 11, 43, 14, 22,  4, 62,
			57, 46, 52, 38, 26, 32, 41, 50,
			36, 17, 19, 29, 10, 13, 21, 56,
			45, 25, 31, 35, 16,  9, 12, 44,
			24, 15,  8, 23,  7,  6,  5, 63
		};
		value |= value >> 1;
		value |= value >> 2;
		value |= value >> 4;
		value |= value >> 8;
		value |= value >> 16;
		value |= value >> 32;
		return tab64[value * 0x03f6eaf2cd271461 >> 58];
	#else
		const uint8_t tab32[32] = {
			 0,  9,  1, 10, 13, 21,  2, 29,
			11, 14, 16, 18, 22, 25,  3, 30,
			 8, 12, 20, 28, 15, 17, 24,  7,
			19, 27, 23,  6, 26,  5,  4, 31
		};
		value |= value >> 1;
		value |= value >> 2;
		value |= value >> 4;
		value |= value >> 8;
		value |= value >> 16;
		return tab32[value * 0x07C4ACDDU >> 27];
	#endif
#endif
	}

	//Way faster than using log2(double), also returns 0 for a value of 0
	FORCE_INLINE size_t int_log2(const size_t value) {
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
		if (likely(value != 0))
			return unsafe_int_log2(value);
		return 0;
#endif  //Fallback already returns 0 when value == 0
		return unsafe_int_log2(value);
	}

	//Undefined behaviour when value == 0
	FORCE_INLINE size_t unsafe_bit_scan_forward(const size_t value) {
#if defined(_MSC_VER)
		unsigned long result;
	#if IS_64BIT
		_BitScanForward64(&result, value);
	#else
		_BitScanForward(&result, value);
	#endif
		return result;
#elif defined(__GNUC__) || defined(__clang__)
	#if IS_64BIT
		return __builtin_ctzll(value);
	#else
		return __builtin_ctz(value);
	#endif
#else
	#if IS_64BIT
		const unsigned int tab64[64] = {
			 0,  1,  2, 53,  3,  7, 54, 27,
			 4, 38, 41,  8, 34, 55, 48, 28,
			62,  5, 39, 46, 44, 42, 22,  9,
			24, 35, 59, 56, 49, 18, 29, 11,
			63, 52,  6, 26, 37, 40, 33, 47,
			61, 45, 43, 21, 23, 58, 17, 10,
			51, 25, 36, 32, 60, 20, 57, 16,
			50, 31, 19, 15, 30, 14, 13, 12
		};
		return tab64[(value & (0 - value)) * 0x022FDD63CC95386D >> 58];
	#else
		static uint8_t tab32[32] = {
			 0,  1, 28,  2, 29, 14, 24,  3,
			30, 22, 20, 15, 25, 17,  4,  8,
			31, 27, 13, 23, 21, 19, 16,  7,
			26, 12, 18,  6, 11,  5, 10,  9
		};
		return tab32[(value & (0 - value)) * 0x077CB531U >> 27];
	#endif
#endif
	}

	//Returns the index of the first set bit, starting from the least significant, or 0 if the input is null
	FORCE_INLINE size_t bit_scan_forward(const size_t value) {
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
		if (likely(value != 0))
			return unsafe_bit_scan_forward(value);
		return 0;
#endif  //Fallback already returns 0 when value == 0
		return unsafe_bit_scan_forward(value);
	}

	struct FastIntHash {
		//Use top bits
		size_t operator()(const size_t value) {
#if IS_64BIT
			return value * 0xff51afd7ed558ccd;
#else
			return value * 0x27d4eb2d;
#endif
		}
	};

	FORCE_INLINE size_t read_hash6(const uint8_t* const ptr) {
#if IS_64BIT
		uint64_t a;
		memcpy(&a, ptr, 8);
		if (is_little_endian())
			return a << 16;
		return a >> 16;
#else
		uint32_t a; uint16_t b;
		memcpy(&a, ptr, 4);
		memcpy(&b, ptr + 4, 2);
		return a ^ b;
#endif
	}

	FORCE_INLINE uint32_t read_uint32le(const uint8_t* const ptr) {
		if (is_little_endian()) {
			uint32_t value;
			memcpy(&value, ptr, 4);
			return value;
		}
		uint32_t value = 0;
		for (int i = 0; i < 4; i++)
			value |= (uint64_t)ptr[i] << i * 8;
		return value;
	}
	FORCE_INLINE void write_uint32le(uint8_t* const ptr, const uint32_t value) {
		if (is_little_endian())
			memcpy(ptr, &value, 4);
		else {
			for (int i = 0; i < 4; i++)
				ptr[i] = value >> i * 8;
		}
	}
	FORCE_INLINE uint16_t read_uint16le(const uint8_t* const ptr) {
		uint16_t value;
		if (is_little_endian())
			memcpy(&value, ptr, 2);
		else
			value = ptr[0] | (ptr[1] << 8);
		return value;
	}
	FORCE_INLINE void write_uint16le(uint8_t* const ptr, const uint16_t value) {
		if (is_little_endian())
			memcpy(ptr, &value, 2);
		else {
			for (int i = 0; i < 2; i++)
				ptr[i] = value >> i * 8;
		}
	}

	//Encodes the value, and advances the pointer
	void write_LEB128(uint8_t*& out, size_t value) {
		do {
			uint8_t byte = value & 0x7F;
			value >>= 7;
			byte |= (value > 0) << 7;
			*out++ = byte;
		} while (value);
	}
	//Decodes a value, advances the pointer, and determines whether an out of bounds or overflow has ocurred
	int read_LEB128(const uint8_t*& in, const uint8_t* const inEnd, size_t* value) {
		*value = 0;
		uint8_t byte;
		size_t iterations = 0;
		do {
			if (in == inEnd || iterations >= (IS_64BIT ? 10 : 5))
				return -1;
			byte = *in++;
			*value |= (size_t)(byte & 0x7F) << iterations * 7;
			iterations++;
		} while (byte & 0x80);
		return 0;
	}

	//A hash table which does not check for collisions
	template<class Value, class Hash>
	class HashTable {
		Value* arr = nullptr;
		int hashShift;
	public:
		//Use 2^x sizes to avoid the use of modulo operator
		HashTable() {}
		~HashTable() {
			delete[] arr;
		}
		void init(const int logSize) {
			arr = new Value[(size_t)1 << logSize]();
			hashShift = (IS_64BIT ? 64 : 32) - logSize;
		}
		Value& operator[](const size_t value) {
			return arr[Hash{}(value) >> hashShift];
		}
		void reset() {
			std::fill_n(arr, (size_t)1 << ((IS_64BIT ? 64 : 32) - hashShift), 0);
		}
	};

	//https://github.com/romeric/fastapprox/blob/master/fastapprox/src/fastlog.h
	FORCE_INLINE float fast_log2(float x) {
		union { float f; uint32_t i; } vx = { x };
		float y = vx.i;
		y *= 1.1920928955078125e-7f;
		return y - 126.94269504f;
	}

	void get_histogram8(const uint8_t* buf, const size_t bufSize, uint32_t histogram[8][256]) {
		std::fill_n(&histogram[0][0], 8 * 256, 0);
		const uint8_t* const fastLoopEnd = buf + (bufSize & ~0x7);
		const uint8_t* const bufEnd = buf + bufSize;

		for (; buf != fastLoopEnd; buf += 8) {
			if (IS_64BIT) {
				uint64_t w;
				memcpy(&w, buf, 8);
				histogram[0][w >> 0 & 0xFF]++;
				histogram[1][w >> 8 & 0xFF]++;
				histogram[2][w >> 16 & 0xFF]++;
				histogram[3][w >> 24 & 0xFF]++;
				histogram[4][w >> 32 & 0xFF]++;
				histogram[5][w >> 40 & 0xFF]++;
				histogram[6][w >> 48 & 0xFF]++;
				histogram[7][w >> 56 & 0xFF]++;
			}
			else {
				uint32_t w;
				memcpy(&w, buf, 4);
				histogram[0][w >> 0 & 0xFF]++;
				histogram[1][w >> 8 & 0xFF]++;
				histogram[2][w >> 16 & 0xFF]++;
				histogram[3][w >> 24 & 0xFF]++;
				memcpy(&w, buf + 4, 4);
				histogram[4][w >> 0 & 0xFF]++;
				histogram[5][w >> 8 & 0xFF]++;
				histogram[6][w >> 16 & 0xFF]++;
				histogram[7][w >> 24 & 0xFF]++;
			}
		}
		for (int i = 0; buf != bufEnd; buf++, i++)
			histogram[i % 8][*buf]++;
	}

	float calculate_entropy(const uint8_t* buf, const size_t bufSize) {

		uint32_t histogram[8][256];
		get_histogram8(buf, bufSize, histogram);
		
		const float probDiv = 1 / float(bufSize);
		float entropy = 0;

		for (int i = 0; i < 256; i++) {

			uint32_t count = histogram[0][i] + histogram[1][i] + histogram[2][i] + histogram[3][i] +
				histogram[4][i] + histogram[5][i] + histogram[6][i] + histogram[7][i];
			if (count) {
				const float prob = count * probDiv;
				entropy += -(prob * fast_log2(prob));
			}
		}
		return entropy;
	}

	//The number of channels is detected by making a histogram of the distances between
	// bytes of the same value, and then taking the most common distance.
	//To exploit out of order execution the input is divided into 4 streams
	int find_channels(const uint8_t* data, size_t size) {

		uint32_t distanceCount[4][256];
		std::fill_n(&distanceCount[0][0], 4 * 256, 0);
		const uint8_t* lastSeen[4][256];
		std::fill_n(&lastSeen[0][0], 4 * 256, data);
		
		const uint8_t* itA = data + 1;
		const uint8_t* itB = itA + size / 4;
		const uint8_t* itC = itB + size / 4;
		const uint8_t* itD = itC + size / 4;
		const uint8_t* const dataEnd = data + size;

		for (; itD < dataEnd; ) {
			size_t b1 = *itA; 
			distanceCount[0][itA - lastSeen[0][b1] & 0xFF]++;
			lastSeen[0][b1] = itA++;
			size_t b2 = *itB; 
			distanceCount[1][itB - lastSeen[1][b2] & 0xFF]++;
			lastSeen[1][b2] = itB++;
			size_t b3 = *itC;
			distanceCount[2][itC - lastSeen[2][b3] & 0xFF]++;
			lastSeen[2][b3] = itC++;
			size_t b4 = *itD;
			distanceCount[3][itD - lastSeen[3][b4] & 0xFF]++;
			lastSeen[3][b4] = itD++;
		}

		int channels = 1;
		size_t highestCount = 0;
		for (int i = 1; i < 256; i++) {
			size_t thisCount = distanceCount[0][i] + distanceCount[1][i] + distanceCount[2][i] + distanceCount[3][i];
			if (thisCount > highestCount) {
				highestCount = thisCount;
				channels = i;
			}
		}
		return channels;
	}

	//Tries to find a match between the two locations, and returns the length
	//Note that this function should be called with at least MIN_LENGTH + 8 bytes of buffer after limit
	FORCE_INLINE size_t test_match(const uint8_t* front, const uint8_t* back, const uint8_t* const limit, const size_t minLength) {

		if (minLength == 6 && IS_64BIT) {
			uint64_t a, b;
			memcpy(&a, front, sizeof(uint64_t));
			memcpy(&b, back, sizeof(uint64_t));
			if (is_little_endian()) {
				if ((a << 16) != (b << 16))
					return 0;
			}
			else {
				if ((a >> 16) != (b >> 16))
					return 0;
			}
		}
		else {
			if (!std::equal(back, back + minLength, front))
				return 0;
		}

		const uint8_t* const matchOrigin = front;
		front += minLength;
		back += minLength;

		while (true) {
			if (unlikely(front + sizeof(size_t) > limit)) {
				if (front > limit)
					return 0;

				while (*front == *back && front < limit) {
					front++;
					back++;
				}
				return front - matchOrigin;
			}

			//Compare 4 or 8 bytes at a time using xor. It has the property of returning 0 if the two values are equal.
			//In case they differ, we can get the first byte that differs using a bit scan.
			size_t a, b;
			memcpy(&a, front, sizeof(size_t));
			memcpy(&b, back, sizeof(size_t));
			const size_t xorVal = a ^ b;

			if (xorVal) {
				if (is_little_endian())
					front += unsafe_bit_scan_forward(xorVal) >> 3;
				else
					front += unsafe_int_log2(xorVal) >> 3;
				return front - matchOrigin;
			}

			front += sizeof(size_t);
			back += sizeof(size_t);
		}
	}

	//Default "compressor" used when no backend is specified
	size_t dummy_compressor(const uint8_t* input, const size_t size) {

		if (size <= 16)
			return size;

		const uint8_t* const inputStart = input;
		const uint8_t* const inputEnd = input + size - 15;  //Leave some buffer at the end. test_match() requires this
		input++;

		HashTable<uint32_t, FastIntHash> lzdict;
		try {
			lzdict.init(14);
		}
		catch (std::bad_alloc& e) {
			return 0;
		}
		uint32_t literalHistogram[256] = { 0 };

		size_t outSize = 0;  //Bits
		size_t distance = 1;
		size_t numberLiterals = 0;
		while (input < inputEnd) {

			uint32_t& entry = lzdict[read_hash6(input)];
			const uint8_t* const match = inputStart + entry;
			size_t length = test_match(input, match, inputEnd, 6);
			entry = input - inputStart;

			if (length) {
				distance = input - match;
				outSize += 16; //2 bytes
				input += length;
			}
			else {
				literalHistogram[*input]++;
				numberLiterals++;
				input++;
			}
		}

		float entropy = 0;
		for (int i = 0; i < 256; i++) {
			if (literalHistogram[i]) {
				float prob = (float)literalHistogram[i] / numberLiterals;
				entropy -= prob * fast_log2(prob);
			}
		}
		outSize += numberLiterals * entropy;

		return outSize / 8;
	}

	const int BINARY_MODEL_PRECISION_BITS = 12;
	const int BINARY_MODEL_FULL_RANGE = 1 << BINARY_MODEL_PRECISION_BITS;
	const int BINARY_MODEL_MID_RANGE = 1 << BINARY_MODEL_PRECISION_BITS - 1;
	const int BINARY_MODEL_UPDATE_SPEED = 5;

	class BinaryModel {
	public:
		uint16_t model = BINARY_MODEL_MID_RANGE;
		BinaryModel() {}

		void update(bool bit) {
			model += (bit ? (1 << BINARY_MODEL_UPDATE_SPEED) - 1 : BINARY_MODEL_FULL_RANGE) - model >> BINARY_MODEL_UPDATE_SPEED;
		}
		uint16_t get_low(bool bit) {
			return (-bit) & model;
		}
		uint16_t get_freq(bool bit) {
			return bit ? BINARY_MODEL_FULL_RANGE - model : model;
		}
		uint16_t get_mid() const {
			return model;
		}
	};

	const uint32_t RANS_BIT_PRECISION = 32;
	const uint32_t RANS_NORMALIZATION_INTERVAL = (1 << (RANS_BIT_PRECISION - 16));
	const uint32_t RANS_FLUSH_PERIOD = 32768;

	//simple 32bit single state rans
	class RansEncoder {

		uint8_t* streamBegin;
		uint8_t* streamIt;

		uint32_t state;
		uint8_t* blockBufferBegin = nullptr;
		uint8_t* blockBufferIt;
		uint32_t* dataBuffer = nullptr;
		size_t bitsStored;

	public:
		RansEncoder() {}
		~RansEncoder() {
			delete[] blockBufferBegin;
			delete[] dataBuffer;
		}

		void flush() {
			state = RANS_NORMALIZATION_INTERVAL;

			do {
				bitsStored--;
				uint32_t data = dataBuffer[bitsStored];

				const size_t low = data & (1 << BINARY_MODEL_PRECISION_BITS) - 1;
				const size_t freq = data >> BINARY_MODEL_PRECISION_BITS;

				const uint32_t interval = (RANS_NORMALIZATION_INTERVAL << (16 - BINARY_MODEL_PRECISION_BITS)) * freq;
				if (state >= interval) {
					blockBufferIt -= 2;
					write_uint16le(blockBufferIt, state);
					state >>= 16;
				}
				state = ((state / freq) << BINARY_MODEL_PRECISION_BITS) + (state % freq) + low;
			} while (bitsStored > 0);

			blockBufferIt -= 4;
			write_uint32le(blockBufferIt, state);

			size_t finalBlockSize = (blockBufferBegin + RANS_FLUSH_PERIOD / 4) - blockBufferIt;
			memcpy(streamIt, blockBufferIt, finalBlockSize);
			blockBufferIt = blockBufferBegin + RANS_FLUSH_PERIOD / 4;
			streamIt += finalBlockSize;
		}

		void encode_bit(BinaryModel* model, const uint8_t bit) {
			dataBuffer[bitsStored] = (model->get_freq(bit) << BINARY_MODEL_PRECISION_BITS) | model->get_low(bit);
			bitsStored++;
			model->update(bit);

			if (bitsStored == RANS_FLUSH_PERIOD)
				flush();
		}
		void start_rans(uint8_t* output) {
			streamBegin = output;
			streamIt = output;
			blockBufferBegin = new uint8_t[RANS_FLUSH_PERIOD / 4];
			blockBufferIt = blockBufferBegin + RANS_FLUSH_PERIOD / 4;
			dataBuffer = new uint32_t[RANS_FLUSH_PERIOD];
			bitsStored = 0;
		}
		size_t end_rans() {
			if (bitsStored > 0)
				flush();
			return streamIt - streamBegin;
		}
	};

	class RansDecoder {
		uint32_t state;
		size_t readBits;
		const uint8_t* compressedStreamIt;

	public:
		RansDecoder() {}
		~RansDecoder() {}

		//rans block functions
		void start_rans(const uint8_t* compressed) {
			compressedStreamIt = compressed;
			readBits = 0;
		}
		void start_block() {
			state = read_uint32le(compressedStreamIt);
			compressedStreamIt += 4;
		}
		void normalize() {
			bool renormalize = state < RANS_NORMALIZATION_INTERVAL;
			uint32_t newState = (state << 16) | read_uint16le(compressedStreamIt);
			state = (0 - renormalize & (newState ^ state)) ^ state;
			compressedStreamIt += renormalize << 1;
		}
		size_t decode_bit(BinaryModel* model) {
			if (readBits % RANS_FLUSH_PERIOD == 0)
				start_block();

			size_t stateLow = state & (BINARY_MODEL_FULL_RANGE - 1);
			size_t bit = stateLow >= model->get_mid();
			state = model->get_freq(bit) * (state >> BINARY_MODEL_PRECISION_BITS) + stateLow - model->get_low(bit);
			model->update(bit);
			normalize();
			readBits++;
			return bit;
		}
	};

	const int CALL_ADDRESS = 0;
	const int JUMP_ADDRESS = 1;
	const int MOVLEA_ADDRESS = 2;

	//Based on Igor's BCJ2 and Shelwien's x64flt3
	size_t x86_encode(const uint8_t* input, const size_t size, uint8_t* output) {

		const uint8_t* const start = input;
		//Allows to read up to 4 bytes of opcode and 4 bytes of address
		const uint8_t* const end = size < 7 ? input : input + size - 7;

		uint32_t* addressBuf = nullptr;
		uint8_t* addressTypeBuf = nullptr;
		uint8_t* bitBuf = nullptr;

		try {
			//Each instruction takes 1 byte for the opcode and 4 for the offset, so it is impossible to have more than NUMBER_BYTES / 5 instructions
			addressBuf = new uint32_t[size / 5 + 1];
			addressTypeBuf = new uint8_t[size / 5 + 1];
			bitBuf = new uint8_t[size / 8 + 1]();
		}
		catch (std::bad_alloc& e) {
			delete[] addressBuf;
			delete[] addressTypeBuf;
			delete[] bitBuf;
			return -1;
		}

		uint32_t* addressIt = addressBuf;
		uint8_t* addressTypeIt = addressTypeBuf;
		RansEncoder ransEncoder;
		ransEncoder.start_rans(bitBuf);
		BinaryModel bitModel[512];

		size_t callAddressCount = 0;
		size_t jumpAddressCount = 0;
		size_t movLeaAddressCount = 0;

		uint8_t* mainIt = output;
		//First byte is sent as is
		*mainIt++ = *input++;

		for (; input < end; ) {

			//Perform two passes: first one is to know which addresses are repeated so that we dont have false E8 and E9.
			//I have decided to do this in blocks. Very large ones could start getting more collisions, and thus reduce compression.
			const size_t BLOCK_SIZE = 1 << 22;
			const uint8_t* nextCheckpoint = end - input < BLOCK_SIZE * 5 / 4 ? end : input + BLOCK_SIZE;

			const size_t HASH_SIZE = 1 << 22;
			std::bitset<HASH_SIZE>* bcjEncountered = new (std::nothrow) std::bitset<HASH_SIZE>;
			std::bitset<HASH_SIZE>* bcjDuplicate = new (std::nothrow) std::bitset<HASH_SIZE>;
			if (!bcjEncountered || !bcjDuplicate) {
				delete bcjEncountered;
				return -1;
			}

			for (const uint8_t* it = input; it < nextCheckpoint; ) {
				const uint32_t opcode = read_uint16le(it - 1);
				it++;

				if ((opcode & 0xFE00) == 0xE800 || (opcode & 0xF0FF) == 0x800F) {
					uint32_t address = read_uint32le(it);
					address += (it - start);

					size_t hash = FastIntHash{}(address) % HASH_SIZE;
					bool isDuplicate = bcjEncountered->test(hash);
					bcjEncountered->set(hash);
					(*bcjDuplicate)[hash] = isDuplicate;
					it += 4;
				}
			}

			for (; input < nextCheckpoint; ) {

				const uint32_t opcode = read_uint32le(input);
				write_uint32le(mainIt, opcode);

				if ((opcode & 0xFE) == 0xE8) { //Call and jump
					mainIt++;
					input++;

					uint32_t relative = read_uint32le(input);
					uint32_t address = relative + (input - start);

					size_t isJump = opcode & 1;
					//If the relative offset is very small, then it probably is a CALL instruction
					if (bcjDuplicate->test(FastIntHash{}(address) % HASH_SIZE) || std::abs(int(relative)) < 0x10000) {
						ransEncoder.encode_bit(&bitModel[(isJump << 8) | input[-2]], 1);
						*addressIt++ = address;
						*addressTypeIt++ = isJump ? JUMP_ADDRESS : CALL_ADDRESS;
						callAddressCount += isJump ^ 1;
						jumpAddressCount += isJump;
						input += 4;
					}
					else
						ransEncoder.encode_bit(&bitModel[(isJump << 8) | input[-2]], 0);

					continue;
				}

				bool isBranch = (opcode & 0xF0FF) == 0x800F;
				bool isMov = (opcode & 0xC7FD) == 0x0589;
				bool isLea = (opcode & 0xC7FFFB) == 0x058D48;
				if (isBranch || isMov || isLea) { //MOV reg,[addr], mov [addr],reg or REX + LEA
					size_t bytes = 2 + isLea;
					mainIt += bytes;
					input += bytes;

					uint32_t address = read_uint32le(input);
					address += (input - start);

					*addressIt++ = address;
					*addressTypeIt++ = (isBranch ? JUMP_ADDRESS : MOVLEA_ADDRESS);
					jumpAddressCount += isBranch;
					movLeaAddressCount += isBranch ^ 1;
					input += 4;
				}

				else {
					mainIt++;
					input++;
				}
			}

			delete bcjEncountered;
			delete bcjDuplicate;
		}

		while (input < start + size)
			*mainIt++ = *input++;

		size_t mainSize = mainIt - output;
		size_t bitSize = ransEncoder.end_rans();

		size_t metadataBytes = 0;
		metadataBytes += 1 + int_log2(callAddressCount) / 7;
		metadataBytes += 1 + int_log2(jumpAddressCount) / 7;
		metadataBytes += 1 + int_log2(movLeaAddressCount) / 7;
		metadataBytes += 1 + int_log2(bitSize) / 7;

		uint8_t* callBuf = output + metadataBytes;
		uint8_t* jumpBuf = callBuf + callAddressCount * 4;
		uint8_t* movLeaBuf = jumpBuf + jumpAddressCount * 4;
		memmove(movLeaBuf + movLeaAddressCount * 4 + bitSize, output, mainSize);
		memcpy(movLeaBuf + movLeaAddressCount * 4, bitBuf, bitSize);
		size_t totalSize = metadataBytes + size + bitSize;

		const size_t totalAddressCount = callAddressCount + jumpAddressCount + movLeaAddressCount;
		for (size_t i = 0; i < totalAddressCount; i++) {
			switch (addressTypeBuf[i]) {
			case CALL_ADDRESS:
				write_uint32le(callBuf, addressBuf[i]);
				callBuf += 4;
				break;
			case JUMP_ADDRESS:
				write_uint32le(jumpBuf, addressBuf[i]);
				jumpBuf += 4;
				break;
			case MOVLEA_ADDRESS:
				write_uint32le(movLeaBuf, addressBuf[i]);
				movLeaBuf += 4;
				break;
			}
		}

		write_LEB128(output, callAddressCount);
		write_LEB128(output, jumpAddressCount);
		write_LEB128(output, movLeaAddressCount);
		write_LEB128(output, bitSize);

		delete[] addressBuf;
		delete[] addressTypeBuf;
		delete[] bitBuf;

		return totalSize;
	}

	size_t x86_decode(const uint8_t* encoded, const uint8_t* const encodedEnd, const size_t size, uint8_t* decoded) {

		if (size == 0)
			return 0;

		const uint8_t* const metadataStart = encoded;

		size_t callSize, jumpSize, movLeaSize, bitSize;
		if (read_LEB128(encoded, encodedEnd, &callSize))
			return -1;
		if (read_LEB128(encoded, encodedEnd, &jumpSize))
			return -1;
		if (read_LEB128(encoded, encodedEnd, &movLeaSize))
			return -1;
		if (read_LEB128(encoded, encodedEnd, &bitSize))
			return -1;

		//Make sure all sizes are within encoded stream size. 
		//Better go one by one to ensure we do not get overflows.
		if (callSize * 4 > encodedEnd - encoded)
			return -1;
		if (jumpSize * 4 > encodedEnd - encoded - callSize * 4)
			return -1;
		if (movLeaSize * 4 > encodedEnd - encoded - callSize * 4 - jumpSize * 4)
			return -1;
		if (bitSize > encodedEnd - encoded - callSize * 4 - jumpSize * 4 - movLeaSize)
			return -1;
		//There must be at least 4 bytes for main to be able to read the opcode OR the stream is very small
		if (encodedEnd - encoded - callSize * 4 - jumpSize * 4 - movLeaSize * 4 - bitSize < std::min((size_t)(encodedEnd - encoded), (size_t)4))
			return -1;

		const size_t metadataSize = encoded - metadataStart;

		const uint8_t* callIt = encoded;
		const uint8_t* jumpIt = callIt + callSize * 4;
		const uint8_t* movLeaIt = jumpIt + jumpSize * 4;
		const uint8_t* bitBuf = movLeaIt + movLeaSize * 4;
		const uint8_t* mainIt = bitBuf + bitSize;

		RansDecoder ransDecoder;
		ransDecoder.start_rans(bitBuf);
		BinaryModel bitModel[512];

		const uint8_t* const start = decoded;
		const uint8_t* end = size < 7 ? decoded : decoded + size - 7;

		//First byte is sent as is
		*decoded++ = *mainIt++;

		for (; decoded < end;) {

			//On a correct stream we will always have more than 4 bytes to read
			if (encodedEnd - mainIt < 4)
				return -1;

			const uint32_t opcode = read_uint32le(mainIt);
			write_uint32le(decoded, opcode);

			if ((opcode & 0xFE) == 0xE8) {
				decoded++;
				mainIt++;

				size_t isJump = opcode & 1;
				//bitBuf always starts behind mainIt, and it will advance slower, 
				// so if mainIt is not out of bounds, neither is bitBuf.
				if (ransDecoder.decode_bit(&bitModel[(isJump << 8) | decoded[-2]])) {
					//Would read from next buffer, but not from out of bounds
					uint32_t callAddress = read_uint32le(callIt);
					uint32_t jumpAddress = read_uint32le(jumpIt);
					callIt += (isJump ^ 1) << 2;
					jumpIt += isJump << 2;

					if (callIt > jumpIt || jumpIt > movLeaIt)
						return -1;

					uint32_t address = (isJump ? jumpAddress : callAddress) - (decoded - start);
					memcpy(decoded, &address, 4);
					decoded += 4;
				}

				continue;
			}

			bool isBranch = (opcode & 0xF0FF) == 0x800F;
			bool isMov = (opcode & 0xC7FD) == 0x0589;
			bool isLea = (opcode & 0xC7FFFB) == 0x058D48;
			if (isBranch || isMov || isLea) {
				size_t bytes = 2 + isLea;
				decoded += bytes;
				mainIt += bytes;

				uint32_t jumpAddress = read_uint32le(jumpIt);
				uint32_t movLeaAddress = read_uint32le(movLeaIt);
				jumpIt += isBranch << 2;
				movLeaIt += (isBranch ^ 1) << 2;

				if (jumpIt > movLeaIt || movLeaIt > bitBuf)
					return -1;

				uint32_t address = (isBranch ? jumpAddress : movLeaAddress) - (decoded - start);
				memcpy(decoded, &address, 4);
				decoded += 4;
			}

			else {
				decoded++;
				mainIt++;
			}
		}

		if (decoded < start + size) {
			//Insufficient bytes to end
			if (encodedEnd - mainIt < start + size - decoded)
				return -1;
			while (decoded < start + size)
				*decoded++ = *mainIt++;
		}

		return size + bitSize + metadataSize;
	}

	size_t lpc_encode(const uint8_t* input, size_t size, uint8_t* output,
		int order, int channels, int channelWidth, int offset)
	{
		const uint8_t* const end = input + size;
		int sampleWidth = channels * channelWidth;  //Number of bytes each sample occupies

		for (; offset > 0 && input < end; offset--)
			*output++ = *input++;
		for (int i = 0; i < order * sampleWidth && input < end; i++)
			*output++ = *input++;

		switch (order) {
		case 1:
			switch (channelWidth) {
			case 1:
#ifdef x64
				for (; input + 15 < end;) {
					__m128i cur = _mm_loadu_si128((__m128i*)input);
					__m128i prev = _mm_loadu_si128((__m128i*)(input - sampleWidth));
					cur = _mm_sub_epi8(cur, prev);
					_mm_storeu_si128((__m128i*)output, cur);
					input += 16;
					output += 16;
				}
#endif
				for (; input < end; input++)
					*output++ = *input - *(input - sampleWidth);
				break;
			case 2:
#ifdef x64
				for (; input + 15 < end;) {
					__m128i cur = _mm_loadu_si128((__m128i*)input);
					__m128i prev = _mm_loadu_si128((__m128i*)(input - sampleWidth));
					cur = _mm_sub_epi16(cur, prev);
					_mm_storeu_si128((__m128i*)output, cur);
					input += 16;
					output += 16;
				}
#endif
				for (; input + 1 < end; ) {
					write_uint16le(output, read_uint16le(input) - read_uint16le(input - sampleWidth));
					output += 2;
					input += 2;
				}
				break;
			}
			break;
		case 2:
			switch (channelWidth) {
			case 1:
#ifdef x64
				for (; input + 15 < end;) {
					__m128i cur = _mm_loadu_si128((__m128i*)input);
					__m128i prev1 = _mm_loadu_si128((__m128i*)(input - sampleWidth));
					__m128i prev2 = _mm_loadu_si128((__m128i*)(input - sampleWidth * 2));
					cur = _mm_add_epi8(_mm_sub_epi8(_mm_sub_epi8(cur, prev1), prev1), prev2);
					_mm_storeu_si128((__m128i*)output, cur);
					input += 16;
					output += 16;
				}
#endif
				for (; input < end; input++)
					*output++ = *input - *(input - sampleWidth) * 2 + *(input - sampleWidth * 2);
				break;
			case 2:
#ifdef x64
				for (; input + 15 < end;) {
					__m128i cur = _mm_loadu_si128((__m128i*)input);
					__m128i prev1 = _mm_loadu_si128((__m128i*)(input - sampleWidth));
					__m128i prev2 = _mm_loadu_si128((__m128i*)(input - sampleWidth * 2));
					cur = _mm_add_epi16(_mm_sub_epi16(_mm_sub_epi16(cur, prev1), prev1), prev2);
					_mm_storeu_si128((__m128i*)output, cur);
					input += 16;
					output += 16;
				}
#endif
				for (; input + 1 < end; ) {
					write_uint16le(output, read_uint16le(input) - read_uint16le(input - sampleWidth) * 2
						+ read_uint16le(input - sampleWidth * 2) * 1);
					output += 2;
					input += 2;
				}
				break;
			}
			break;
		case 3:
			switch (channelWidth) {
			case 1:
				for (; input < end; input++)
					*output++ = *input - *(input - sampleWidth) * 3 + *(input - sampleWidth * 2) * 3 - *(input - sampleWidth * 3);
				break;
			case 2:
				for (; input + 1 < end; ) {
					write_uint16le(output, read_uint16le(input) - read_uint16le(input - sampleWidth) * 3
						+ read_uint16le(input - sampleWidth * 2) * 3 - read_uint16le(input - sampleWidth * 3));
					output += 2;
					input += 2;
				}
				break;
			}
			break;
		}

		while (input < end)
			*output++ = *input++;
		return size;
	}

	size_t lpc_decode(const uint8_t* input, const size_t size, uint8_t* output,
		int order, int channels, int channelWidth, int offset)
	{
		const uint8_t* const end = input + size;
		int sampleWidth = channels * channelWidth;  //Number of bytes each sample occupies

		for (; offset > 0 && input < end; offset--)
			*output++ = *input++;
		for (int i = 0; i < order * sampleWidth && input < end; i++)
			*output++ = *input++;

		switch (order) {
		case 1:
			switch (channelWidth) {
			case 1:
				for (; input < end; input++)
					*output++ = *input + *(output - sampleWidth);
				break;
			case 2:
				for (; input + 1 < end; ) {
					write_uint16le(output, read_uint16le(input) + read_uint16le(output - sampleWidth));
					output += 2;
					input += 2;
				}
				break;
			}
			break;
		case 2:
			switch (channelWidth) {
			case 1:
				for (; input < end; input++)
					*output++ = *input + *(output - sampleWidth) * 2 - *(output - sampleWidth * 2);
				break;
			case 2:
				for (; input + 1 < end; ) {
					write_uint16le(output, read_uint16le(input) + read_uint16le(output - sampleWidth) * 2
						- read_uint16le(output - sampleWidth * 2) * 1);
					output += 2;
					input += 2;
				}
				break;
			}
			break;
		case 3:
			switch (channelWidth) {
			case 1:
				for (; input < end; input++)
					*output++ = *input + *(output - sampleWidth) * 3 - *(output - sampleWidth * 2) * 3 + *(output - sampleWidth * 3);
				break;
			case 2:
				for (; input + 1 < end; ) {
					write_uint16le(output, read_uint16le(input) + read_uint16le(output - sampleWidth) * 3
						- read_uint16le(output - sampleWidth * 2) * 3 + read_uint16le(output - sampleWidth * 3));
					output += 2;
					input += 2;
				}
				break;
			}
			break;
		}

		while (input < end)
			*output++ = *input++;
		return size;
	}

	enum {
		NONE_FILTER, X86_FILTER, LPC_FILTER
	};

	struct PreprocessorBlock {
		size_t filter;
		size_t position;
		size_t size;
		//For linear prediction
		int order;
		int channels;
		int channelWidth;
		int offset;
		//For miscelaneous filters/recompressors
		uint8_t* extraData = nullptr;
		size_t extraDataLength;

		bool operator==(const PreprocessorBlock& other) {
			if (filter != other.filter)
				return false;

			if (filter == NONE_FILTER || filter == X86_FILTER)
				return true;

			return order == other.order && channels == other.channels &&
				channelWidth == other.channelWidth && offset == other.offset;
		}
	};

	size_t encode(const uint8_t* input, const size_t size, uint8_t* output, EncoderOptions options) {

		HashTable<uint32_t, FastIntHash> jumpTable;
		std::vector<PreprocessorBlock> filters;
		try {
			filters.reserve(size / options.blockSize + 1);
			filters.push_back({ 255, 0, 0 });
			jumpTable.init(12);
		}
		catch (std::bad_alloc& e) {
			return -1;
		}

		const uint8_t* const inputStart = input;
		const uint8_t* const inputEnd = input + size;

		for (; input < inputEnd; ) {

			size_t thisBlockSize = std::min((size_t)(inputEnd - input), options.blockSize);

			//If the block is small is probably better to just use the same filter,
			// as we could have more false positives without enough data
			if (thisBlockSize < 4096) {
				if (filters.size() > 1)
					filters.back().size += thisBlockSize;
				else
					filters.push_back({ NONE_FILTER, size_t(input - inputStart), thisBlockSize });
				input += thisBlockSize;
				continue;
			}
			const uint8_t* const thisBlockStart = input;
			const uint8_t* const thisBlockEnd = input + thisBlockSize;

			//  X86 DETECTION
			if (filters.back().filter != X86_FILTER) {
				jumpTable.reset();
				size_t e8count = 0;
				size_t duplicates = 0;
				const uint8_t* lastSeenDuplicate = thisBlockStart;

				const uint8_t* iterator = thisBlockStart;
#ifdef x64
				const uint8_t* end = inputEnd - 19;
				const __m128i e8 = _mm_set1_epi8(0xE8);
#else
				const uint8_t* end = inputEnd - 4;
#endif
				bool isX86 = false;
				const uint8_t* x86End = thisBlockStart;

				while (true) {

					//End reached
					if (iterator >= end) {
						isX86 = duplicates > thisBlockSize / 512;
						x86End = inputEnd;
						break;
					}
					//We have analised a big enough chunk
					if (iterator - thisBlockStart >= options.blockSize) {
						//Too few duplicates
						if (duplicates <= thisBlockSize / 512) {
							isX86 = false;
							break;
						}
						//Too much time without finding anything
						if (iterator - lastSeenDuplicate >= 65536) {
							isX86 = duplicates > thisBlockSize / 512;
							x86End = lastSeenDuplicate;
							break;
						}
					}

#ifdef x64
					__m128i bytes = _mm_loadu_si128((__m128i*)iterator);
					bytes = _mm_cmpeq_epi8(bytes, e8);
					const size_t mask = _mm_movemask_epi8(bytes);

					//No byte is e8, skip forward
					if (mask == 0) {
						iterator += 16;
						continue;
					}

					//Go to the index of the first e8 found
					const size_t index = unsafe_bit_scan_forward(mask);
					iterator += index + 1;
#else
					const uint8_t opcode = *iterator++;
					if (opcode != 0xE8)
						continue;
#endif

					uint32_t offset;
					memcpy(&offset, iterator, 4);
					offset += iterator - inputStart;

					uint32_t* tableEntry = &jumpTable[offset];
					if (*tableEntry == offset) {
						duplicates++;
						lastSeenDuplicate = iterator;
					}
					else {
						*tableEntry = offset;
					}

					iterator += 4;
					e8count++;
				}

				if (isX86) {
					size_t x86Size = x86End - thisBlockStart;
					if (filters.back().filter == X86_FILTER)
						filters.back().size += x86Size;
					else
						filters.push_back({ X86_FILTER, size_t(input - inputStart), x86Size });
					input += x86Size;
					continue;
				}
			}

			//  DELTA/LPC DETECTION		
			bool failedCheck = false;
			//Find channels
			PreprocessorBlock lpcO1Filter;
			lpcO1Filter.filter = LPC_FILTER;
			lpcO1Filter.position = input - inputStart;
			lpcO1Filter.size = thisBlockSize;
			lpcO1Filter.order = 1;
			lpcO1Filter.channelWidth = 1;
			lpcO1Filter.offset = 0;
			if (!options.bruteForce) 
				lpcO1Filter.channels = find_channels(thisBlockStart, thisBlockSize);
			else {
				float bestEntropy = 9;
				for (size_t channels = 1; channels <= 16; channels++) {
					lpc_encode(thisBlockStart, thisBlockSize, output, 1, channels, 1, 0);
					float entropy = calculate_entropy(output, thisBlockSize);
					if (entropy < bestEntropy) {
						lpcO1Filter.channels = channels;
						bestEntropy = entropy;
					}
				}
			}

			//Unsupported number of channels
			if (lpcO1Filter.channels > 16)
				failedCheck = true;
			//FAST CHECK: compare entropies
			float rawEntropy, lpcO1Entropy;
			if (!failedCheck) {
				lpc_encode(thisBlockStart, thisBlockSize, output, 1, lpcO1Filter.channels, lpcO1Filter.channelWidth, lpcO1Filter.offset);
				lpcO1Entropy = calculate_entropy(output, thisBlockSize);
				rawEntropy = calculate_entropy(thisBlockStart, thisBlockSize);
				if (lpcO1Entropy + (float)options.lpcO1Threshold / options.blockSize * 8 > rawEntropy)
					failedCheck = true;
			}
			//PRECISE CHECK: use the backend compressor and compare compressed sizes
			//To improve results, also the last blocks will be used, if available
			size_t rawSize, lpcO1Size;
			if (!failedCheck) {
				rawSize = dummy_compressor(thisBlockStart, thisBlockSize);
				lpcO1Size = dummy_compressor(output, thisBlockSize);
				failedCheck = lpcO1Size + options.lpcO1Threshold > rawSize;
			}

			if (failedCheck) {
				if (filters.back().filter == NONE_FILTER)
					filters.back().size += thisBlockSize;
				else
					filters.push_back({ NONE_FILTER, size_t(input - inputStart), thisBlockSize });
				input += thisBlockSize;
				continue;
			}

			PreprocessorBlock lpcO2Filter = lpcO1Filter;
			lpcO2Filter.order = 2;
			if (lpcO2Filter.channels % 2 == 0) {
				float bestEntropy = 9;
				size_t channels = lpcO2Filter.channels;
				for (size_t channelWidth = 1; channelWidth <= 2; channelWidth++) {
					for (size_t offset = 0; offset < channelWidth; offset++) {
						lpc_encode(thisBlockStart, thisBlockSize, output, 2, channels / channelWidth, channelWidth, offset);
						float entropy = calculate_entropy(output, thisBlockSize);
						if (entropy < bestEntropy) {
							lpcO2Filter.channels = channels / channelWidth;
							lpcO2Filter.channelWidth = channelWidth;
							lpcO2Filter.offset = offset;
							bestEntropy = entropy;
						}
					}
				}
			}
			
			lpc_encode(thisBlockStart, thisBlockSize, output, 2, lpcO2Filter.channels, lpcO2Filter.channelWidth, lpcO2Filter.offset);
			float lpcO2Entropy = calculate_entropy(output, thisBlockSize);
			failedCheck = lpcO2Entropy + (float)options.lpcO2Threshold / options.blockSize * 8 > lpcO1Entropy;
			size_t lpcO2Size;

			if (!failedCheck) {
				lpcO2Size = dummy_compressor(output, thisBlockSize);
				failedCheck = lpcO2Size + options.lpcO2Threshold > lpcO1Size;
			}
			
			if (failedCheck) {
				if (filters.back().operator==(lpcO1Filter))
					filters.back().size += thisBlockSize;
				else
					filters.push_back(lpcO1Filter);
				input += thisBlockSize;
				continue;
			}

			PreprocessorBlock lpcO3Filter = lpcO2Filter;
			lpcO3Filter.order = 3;

			lpc_encode(thisBlockStart, thisBlockSize, output, 3, lpcO3Filter.channels, lpcO3Filter.channelWidth, lpcO3Filter.offset);
			float lpcO3Entropy = calculate_entropy(output, thisBlockSize);
			failedCheck = lpcO3Entropy + (float)options.lpcO3Threshold / options.blockSize * 8 > lpcO2Entropy;
			size_t lpcO3Size;

			if (!failedCheck) {
				lpcO3Size = dummy_compressor(output, thisBlockSize);
				failedCheck = lpcO3Size + options.lpcO3Threshold > lpcO2Size;
			}

			if (failedCheck) {
				if (filters.back().operator==(lpcO2Filter))
					filters.back().size += thisBlockSize;
				else
					filters.push_back(lpcO2Filter);
				input += thisBlockSize;
				continue;
			}

			if (filters.back().operator==(lpcO3Filter))
				filters.back().size += thisBlockSize;
			else
				filters.push_back(lpcO3Filter);
			input += thisBlockSize;
		}

		input = inputStart;
		const uint8_t* const outputStart = output;

		//Second pass: remove false positives for lpc filter
		if (options.backendCompressor) {

			for (size_t i = 0; i < filters.size(); i++) {

				switch (filters[i].filter) {
				case LPC_FILTER:
				{
					lpc_encode(input + filters[i].position, filters[i].size, output, filters[i].order, filters[i].channels, filters[i].channelWidth, filters[i].offset);
					size_t originalSize = (*options.backendCompressor)(output, filters[i].size);
					//Try reducing order of lpc by 1, or disabling the filter if it was already 1
					if (filters[i].order == 1)
						memcpy(output, input + filters[i].position, filters[i].size);
					else
						lpc_encode(input + filters[i].position, filters[i].size, output, filters[i].order - 1, filters[i].channels, filters[i].channelWidth, filters[i].offset);
					size_t replaceSize = (*options.backendCompressor)(output, filters[i].size);

					//Change the filter if the result was better
					if (replaceSize < originalSize) {
						if (filters[i].order == 1)
							filters[i].filter = NONE_FILTER;
						else
							filters[i].order -= 1;
					}
					break;
				}
				default:
					break;
				}

				//Current filter is now equal to previous, remove it
				if (i > 0 && filters[i - 1].operator==(filters[i])) {
					filters[i - 1].size += filters[i].size;
					filters.erase(filters.begin() + i);
					i -= 1;
				}
			}
		}

		for (auto filter = filters.begin() + 1; filter != filters.end(); filter++) {

			//printf("\n Filter %d, pos %d, size %d, order %d, channels %d, width %d, offset %d", 
			//	filter->filter, filter->position, filter->size, filter->order, filter->channels, filter->channelWidth, filter->offset);

			*output++ = filter->filter;
			write_LEB128(output, filter->size - 1);
			if (filter->filter == LPC_FILTER) {
				uint8_t metadata = 0;
				metadata |= (filter->order - 1) << 6;
				metadata |= (filter->channels - 1) << 2;
				metadata |= (filter->channelWidth - 1) << 1;
				metadata |= filter->offset << 0;
				*output++ = metadata;
			}
		}

		for (auto filter = filters.begin() + 1; filter != filters.end(); filter++) {
			size_t processedSize;
			if (filter->filter == X86_FILTER)
				processedSize = x86_encode(input, filter->size, output);
			else if (filter->filter == LPC_FILTER)
				processedSize = lpc_encode(input, filter->size, output, filter->order, filter->channels, filter->channelWidth, filter->offset);
			//raw data
			else {
				memcpy(output, input, filter->size);
				processedSize = filter->size;
			}
			if (processedSize == -1)
				return -1;
			output += processedSize;
			input += filter->size;
			delete[] filter->extraData;
		}

		return output - outputStart;
	}

	size_t bound(size_t size) {
		//The current filter that can expand the most is the x86
		//Its maximum expansion is the maximum of the function x*-log2(x) + (1-x)*-log2(1-x)/5,
		// which is about 0.6 bits per byte.
		return size + size / 13 + 32;
	}

	int decode(const uint8_t* encoded, const size_t encodedSize, uint8_t* decoded, const size_t decodedSize) {

		const uint8_t* const decodedStart = decoded;
		const uint8_t* const decodedEnd = decoded + decodedSize;
		const uint8_t* const encodedEnd = encoded + encodedSize;

		std::vector<PreprocessorBlock> filters;
		try {
			size_t readSize = 0;  //total bytes stored by currently read filters
			while (readSize < decodedSize) {
				size_t filter, blockSize;
				int order, channels, channelWidth, offset;
				if (read_LEB128(encoded, encodedEnd, &filter))
					return -1;
				if (read_LEB128(encoded, encodedEnd, &blockSize))
					return -1;
				blockSize += 1;
				if (filter == LPC_FILTER) {
					if (encoded == encodedEnd)
						return -1;
					order = (*encoded >> 6 & 0x3) + 1;
					channels = (*encoded >> 2 & 0xF) + 1;
					channelWidth = (*encoded >> 1 & 0x1) + 1;
					offset = (*encoded >> 0 & 0x1);
					encoded++;
				}
				filters.push_back({ filter, readSize, blockSize, order, channels, channelWidth, offset });

				if (decodedSize - readSize < blockSize)
					return -1;
				readSize += blockSize;
			}
		}
		catch (std::bad_alloc& e) {
			return -1;
		}

		for (auto filter = filters.begin(); filter != filters.end(); filter++) {

			size_t processedSize;
			if (filter->filter == X86_FILTER)
				processedSize = x86_decode(encoded, encodedEnd, filter->size, decoded);
			else if (filter->filter == LPC_FILTER)
				processedSize = lpc_decode(encoded, filter->size, decoded, filter->order, filter->channels, filter->channelWidth, filter->offset);
			//raw data
			else {
				memcpy(decoded, encoded, filter->size);
				processedSize = filter->size;
			}
			if (processedSize == -1)
				return -1;
			encoded += processedSize;
			decoded += filter->size;
		}

		return 0;
	}
}

#endif //SPECTRUM_IMPLEMENTATION

#endif //__SPECTRUM__