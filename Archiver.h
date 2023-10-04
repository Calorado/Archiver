/*
 * Simple Archiver v0.3
 * Copyright (c) 2022 Carlos de Diego
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef __ARCHIVER__

#define __ARCHIVER__

#include <string>
#include <vector>
#include <stdio.h> //size_t

namespace archiver {

	const int NO_ERROR = 0;
	const int ERROR_BAD_FILE = -1;
	const int ERROR_UNKNOWN_CODEC = -2;
	const int ERROR_OUT_OF_MEMORY = -3;
	const int ERROR_INPUT_FILE_OPEN_FAIL = -4;
	const int ERROR_OUTPUT_FILE_OPEN_FAIL = -5;
	const int ERROR_BAD_CHECKSUM = -6;
	const int ERROR_INVALID_ARGUMENT = -7;
	const int ERROR_WRONG_PASSWORD = -8;
	const int ERROR_OTHER = -9;

	//Base class that allows to track progress of creation and extraction of an archive.
	//You will have to create a child class which implements the functions.
	// - progress(totalSize, consumedSize, compressedSize): number of bytes to compress/decompress, number of bytes already compressed/decompressed, size of read/written data in compressed form
	// - pause(): while this returns true, the operation will be paused
	// - abort(): if this returns true, the operation will stop with a return code of 0 and will remove any created files
	class ArchiveCallback {
	public:
		ArchiveCallback() {}
		virtual void progress(size_t totalSize, size_t consumedSize, size_t compressedSize) {
			return;
		}
		virtual bool pause() {
			return false;
		}
		virtual bool abort() {
			return false;
		}
	};

	struct Parameters {
		std::vector<std::string> codecNameList;
		int compressionLevel = 0;
		std::string password;
		//How much memory will the deduplicator use. 0 is disabled,
		// otherwise about 64*16*2^N bytes
		size_t deduplicationMemoryLog = 0;
		bool useSolidBlock = false;
		size_t maxBlockSize = 1048576;
		int threads = 1;
	};

	//Creates and extracts archives. Both will return 0 on success or user abort or an error code on failure
	int create_archive(const std::vector<std::string>& inputElements, const std::string& archivePath,
		const Parameters& parameters, ArchiveCallback* callbacks = nullptr);
	int extract_archive(const std::string& file, const std::string& outDir, const Parameters& parameters, ArchiveCallback* callbacks = nullptr);

	//Returs an estimation of the amount of memory the encoder will use 
	size_t estimate_memory(const Parameters& parameters);
	//Returns whether a given archive is encrypted or an error code on failure
	int is_archive_encrypted(const std::string& file);
}

#ifdef ARCHIVER_IMPLEMENTATION

#include <thread>
#include <mutex>
#include <shared_mutex>
#include <cstdint>
#include <time.h>
#include <chrono>
#include <unordered_map>
#include <filesystem>
#include <new>
#include <thread>

#define SKANDA_IMPLEMENTATION
#include "library/Skanda.h"
#define STRIDER_IMPLEMENTATION
#include "library/Strider.h"
#define SPECTRUM_IMPLEMENTATION
#include "library/Spectrum.h"
#define XXH_STATIC_LINKING_ONLY
#define XXH_IMPLEMENTATION
#include "library/xxhash.h"
#include "library/picosha2.h"
#include "library/crc.h"
#include "library/aes.h"

//Why microsoft
#if defined(_MSC_VER)
#define CPP_VER _MSVC_LANG
#else
#define CPP_VER __cplusplus
#endif

namespace archiver {

	const int END_BLOCK_ID = 0;
	const int FILE_TREE_BLOCK_ID = 1;
	const int DATA_BLOCK_ID = 2;

	const uint8_t FILE_SIGNATURE[4] = { 'S', 'a', 'r', 'c' };

	bool is_little_endian() {
		const union { uint16_t u; uint8_t c[2]; } LITTLE_ENDIAN_CHECK = { 1 };
		return LITTLE_ENDIAN_CHECK.c[0];
	}

	uint32_t hash32(uint32_t x) {
		x = ((x >> 16) ^ x) * 0x45d9f3b;
		x = ((x >> 16) ^ x) * 0x45d9f3b;
		x = (x >> 16) ^ x;
		return x + 0x27d4eb2d;
	}

	//Encodes the value, and advances the pointer
	void write_LEB128_ptr(uint8_t*& out, size_t value) {
		do {
			uint8_t byte = value & 0x7F;
			value >>= 7;
			byte |= (value > 0) << 7;
			*out++ = byte;
		} while (value);
	}

	void write_LEB128_file(std::fstream* out, size_t value) {
		do {
			uint8_t byte = value & 0x7F;
			value >>= 7;
			byte |= (value > 0) << 7;
			out->put(byte);
		} while (value);
	}

	void write_LEB128_vector(std::vector<uint8_t>* out, size_t value) {
		do {
			uint8_t byte = value & 0x7F;
			value >>= 7;
			byte |= (value > 0) << 7;
			out->push_back(byte);
		} while (value);
	}

	//Decodes a value, advances the pointer, and determines whether an out of bounds or overflow has ocurred
	int read_LEB128_ptr(const uint8_t*& in, const uint8_t* const inEnd, size_t* value) {
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

	int read_LEB128_file(std::fstream* in, size_t* value) {
		*value = 0;
		uint8_t byte;
		size_t iterations = 0;
		do {
			if (in->eof() || iterations >= (IS_64BIT ? 10 : 5))
				return -1;
			byte = in->get();
			*value |= (size_t)(byte & 0x7F) << iterations * 7;
			iterations++;
		} while (byte >= 128);
		return 0;
	}

	uint32_t read_uint32le(const uint8_t* const ptr) {
		if (is_little_endian()) {
			uint32_t value;
			memcpy(&value, ptr, 4);
			return value;
		}
		uint32_t value = 0;
		for (int i = 0; i < 4; i++)
			value |= (uint32_t)ptr[i] << i * 8;
		return value;
	}

	uint32_t read_uint32le(std::fstream* file) {
		uint32_t value = file->get();
		value |= file->get() << 8;
		value |= file->get() << 16;
		value |= file->get() << 24;
		return value;
	}

	void write_uint32le(uint8_t* const ptr, const uint32_t value) {
		if (is_little_endian())
			memcpy(ptr, &value, 4);
		else {
			for (int i = 0; i < 4; i++)
				ptr[i] = value >> i * 8;
		}
	}

	void write_uint32le(std::fstream* file, const uint32_t value) {
		file->put((value >> 0) & 0xFF);
		file->put((value >> 8) & 0xFF);
		file->put((value >> 16) & 0xFF);
		file->put((value >> 24) & 0xFF);
	}

	uint16_t read_uint16le(const uint8_t* const ptr) {
		if (is_little_endian()) {
			uint16_t value;
			memcpy(&value, ptr, 2);
			return value;
		}
		uint16_t value = (uint16_t)ptr[0] << 0;
		value |= (uint16_t)ptr[1] << 8;
		return value;
	}

	uint16_t read_uint16le(std::fstream* file) {
		uint16_t value = file->get();
		value |= file->get() << 8;
		return value;
	}

	void write_uint16le(uint8_t* const ptr, const uint16_t value) {
		if (is_little_endian())
			memcpy(ptr, &value, 2);
		else {
			ptr[0] = value >> 0;
			ptr[1] = value >> 8;
		}
	}

	void write_uint16le(std::fstream* file, const uint16_t value) {
		file->put((value >> 0) & 0xFF);
		file->put((value >> 8) & 0xFF);
	}

	//Keeps track of the progress of all threads, internal errors, and any callbacks from the user
	class ArchiveCallbackInternal {
		ArchiveCallback* userCallbacks = nullptr;
		std::mutex threadMtx;
		size_t containedSize = 0;
		size_t baseProgress = 0;
		std::vector<size_t> threadProgress;
		std::vector<size_t> threadCompressedSize;
		int internalError = 0;  //For errors like out of memory or bad crc
		bool doAbort = false;  //When we get confirmation for abort from user do not ask again

	public:
		ArchiveCallbackInternal(ArchiveCallback* c) {
			userCallbacks = c;
		}
		void init(size_t threads, size_t _containedSize) {
			threadProgress = std::vector<size_t>(threads, 0);
			threadCompressedSize = std::vector<size_t>(threads, 0);
			containedSize = _containedSize;
		}
		void add_base_progress(size_t processedBytes) {
			if (userCallbacks) {
				threadMtx.lock();
				baseProgress += processedBytes;
				size_t totalProgress = baseProgress;
				size_t totalCompressedSize = 0;
				for (size_t i = 0; i < threadProgress.size(); i++) {
					totalProgress += threadProgress[i];
					totalCompressedSize += threadCompressedSize[i];
				}
				userCallbacks->progress(containedSize, totalProgress, totalCompressedSize);
				threadMtx.unlock();
			}
		}
		//The functions below will be called by multiple threads
		void add_progress(size_t processedBytes, size_t compressedSize, size_t threadID) {

			if (userCallbacks) {
				threadMtx.lock();
				threadProgress[threadID] = processedBytes;
				threadCompressedSize[threadID] = compressedSize;
				size_t totalProgress = baseProgress;
				size_t totalCompressedSize = 0;
				for (size_t i = 0; i < threadProgress.size(); i++) {
					totalProgress += threadProgress[i];
					totalCompressedSize += threadCompressedSize[i];
				}
				userCallbacks->progress(containedSize, totalProgress, totalCompressedSize);
				threadMtx.unlock();
			}
		}
		void set_error(int code) {
			threadMtx.lock();
			internalError = code;
			threadMtx.unlock();
		}
		int get_error() {
			threadMtx.lock();
			int err = internalError;
			threadMtx.unlock();
			return err;
		}
		bool abort() {
			threadMtx.lock();
			if (userCallbacks && !doAbort)
				doAbort = userCallbacks->abort();
			bool result = internalError != 0 || doAbort;
			threadMtx.unlock();
			return result;
		}
		bool pause() {
			//Do not pause if an abort has been queued
			if (abort())
				return false;

			threadMtx.lock();
			bool pause = false;
			if (userCallbacks)
				pause = userCallbacks->pause();
			threadMtx.unlock();
			return pause;
		}
	};

	//Keeps track of progress or errors within an individual thread
	class ThreadCallback {

		ArchiveCallbackInternal* archiveCallbacks;
		int internalError = 0;
		size_t threadID = 0;
		//Preprocessor codecs might expand input, which will make compressor codecs progress report inacurate
		double progressScale = 1;
		size_t totalProgress = 0;
		size_t totalCompressedSize = 0;

	public:
		ThreadCallback() {}
		void init(size_t id, ArchiveCallbackInternal* c) {
			threadID = id;
			archiveCallbacks = c;
		}
		void set_progress_scale(double s) {
			progressScale = s;
		}
		void add_base_progress(size_t p) {
			totalProgress += p;
			progress(0, 0); //Update progress bar
		}
		void end_block(size_t blockRawSize, size_t blockCompressedSize) {
			progressScale = 1;
			totalProgress += blockRawSize;
			totalCompressedSize += blockCompressedSize;
			progress(0, 0); //Update progress bar
		}
		bool progress(size_t processedBytes, size_t compressedSize) {
			if (!archiveCallbacks)
				return false;

			archiveCallbacks->add_progress(totalProgress + processedBytes * progressScale, totalCompressedSize + compressedSize, threadID);
			while (archiveCallbacks->pause())
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			return archiveCallbacks->abort();
		}
		void set_error(int error) {
			if (archiveCallbacks)
				archiveCallbacks->set_error(error);
			internalError = error;
		}
		int get_error() {
			if (archiveCallbacks)
				return archiveCallbacks->get_error();
			return internalError;
		}
		bool abort() {
			if (!archiveCallbacks)
				return internalError != NO_ERROR;
			return archiveCallbacks->abort();
		}
	};

	enum {
		CODEC_COMPRESSOR,
		CODEC_ENCRYPTOR,
	};

	class Codec {
	public:
		std::string name;
		int codecType;

		std::string get_name() {
			return name;
		}
		int get_codec_type() {
			return codecType;
		}
		virtual size_t encode(uint8_t* input, size_t inSize, uint8_t* output, const Parameters* parameters, ThreadCallback* callbacks) {
			memcpy(output, input, inSize);
			return inSize;
		}
		virtual void decode(uint8_t* input, size_t encodedSize, uint8_t* output, size_t decodedSize, const Parameters* parameters, ThreadCallback* callbacks) {
			if (decodedSize != encodedSize) {
				callbacks->set_error(ERROR_BAD_FILE);
				return;
			}
			memcpy(output, input, encodedSize);
		}
		virtual size_t encode_bound(size_t inSize) {
			return inSize;
		}
		virtual size_t estimate_memory(size_t inSize, const Parameters* parameters) {
			return 0;
		}
		virtual size_t encode_init(uint8_t* out, const Parameters* parameters) {
			return 0;
		}
		virtual int decode_init(uint8_t* in, size_t inLength, const Parameters* parameters) {
			return NO_ERROR;
		}
		virtual Codec* clone() {
			return new Codec();
		}
	};

	size_t spectrum_strider_fast_backend(const uint8_t* data, const size_t size) {
		uint8_t* out = new (std::nothrow) uint8_t[strider::compress_bound(size)];
		if (!out)
			return 0;
		size_t compressed = strider::compress(data, size, out, 0);
		delete[] out;
		return compressed;
	}

	size_t spectrum_strider_optimal_backend(const uint8_t* data, const size_t size) {
		uint8_t* out = new (std::nothrow) uint8_t[strider::compress_bound(size)];
		if (!out)
			return 0;
		size_t compressed = strider::compress(data, size, out, 4);
		delete[] out;
		return compressed;
	}

	class SpectrumCodec : public Codec {

	public:
		SpectrumCodec(std::string _name, int _codecType) {
			name = _name;
			codecType = _codecType;
		}
		~SpectrumCodec() {}

		size_t encode(uint8_t* input, size_t inSize, uint8_t* output, const Parameters* parameters, ThreadCallback* callbacks) {

			spectrum::EncoderOptions spectrumOptions;
			if (parameters->codecNameList.size() > 1 && parameters->codecNameList[1] == "strider") {
				spectrum::EncoderOptions striderOptions[10] = {
					{ nullptr, 16384, 1024, 256, 128, false },
					{ nullptr, 16384, 1024, 256, 128, false },
					{ nullptr, 16384, 1024, 256, 128, false },
					{ nullptr, 16384, 1024, 256, 128, false },
					{ nullptr, 16384, 1024, 256, 128, false },
					{ nullptr, 16384, 1024, 256, 128, false },
					{ &spectrum_strider_fast_backend, 16384, 384, 128, 0, true },
					{ &spectrum_strider_fast_backend, 16384, 384, 128, 0, true },
					{ &spectrum_strider_fast_backend, 16384, 384, 128, 0, true },
					{ &spectrum_strider_optimal_backend, 16384, 384, 128, 0, true },
				};
				spectrumOptions = striderOptions[std::max(std::min(parameters->compressionLevel, 9), 0)];
			}
			else
				spectrumOptions = { nullptr, 16384, 512, 256, 0, false };

			size_t encodedSize = spectrum::encode(input, inSize, output, spectrumOptions);
			if (encodedSize == -1) {
				callbacks->set_error(ERROR_OUT_OF_MEMORY);
				return 0;
			}
			return encodedSize;
		}

		void decode(uint8_t* input, size_t encodedSize, uint8_t* output, size_t decodedSize, const Parameters* parameters, ThreadCallback* callbacks) {

			if (spectrum::decode(input, encodedSize, output, decodedSize))
				callbacks->set_error(ERROR_BAD_FILE);
		}

		size_t encode_bound(size_t inSize) {
			return spectrum::bound(inSize);
		}

		size_t estimate_memory(size_t inSize, const Parameters* parameters) {
			return 0;
		}

		Codec* clone() {
			return new SpectrumCodec(static_cast<const SpectrumCodec&>(*this));
		}
	};

	class SkandaProgressCallback : public skanda::ProgressCallback {
		ThreadCallback* backendCallback;
	public:
		SkandaProgressCallback(ThreadCallback* callbacks) {
			backendCallback = callbacks;
		}
		bool progress(size_t processedBytes, size_t compressedSize) {
			if (!backendCallback)
				return false;
			return backendCallback->progress(processedBytes, compressedSize);
		}
	};

	class SkandaCodec : public Codec {

	public:
		SkandaCodec(std::string _name, int _codecType) {
			name = _name;
			codecType = _codecType;
		}
		~SkandaCodec() {}

		size_t encode(uint8_t* input, size_t inSize, uint8_t* output, const Parameters* parameters, ThreadCallback* callbacks) {

			SkandaProgressCallback progressCallback(callbacks);
			size_t compressedSize = skanda::compress(input, inSize, output, parameters->compressionLevel, 0.35f, &progressCallback);
			if (compressedSize == -1) {
				callbacks->set_error(ERROR_OUT_OF_MEMORY);
				return 0;
			}
			return compressedSize;
		}

		void decode(uint8_t* input, size_t encodedSize, uint8_t* output, size_t decodedSize, const Parameters* parameters, ThreadCallback* callbacks) {

			if (skanda::decompress(input, encodedSize, output, decodedSize))
				callbacks->set_error(ERROR_BAD_FILE);
			callbacks->progress(decodedSize, encodedSize);
		}

		size_t encode_bound(size_t inSize) {
			return skanda::compress_bound(inSize);
		}

		size_t estimate_memory(size_t inSize, const Parameters* parameters) {
			return skanda::estimate_memory(inSize, parameters->compressionLevel);
		}

		Codec* clone() {
			return new SkandaCodec(static_cast<const SkandaCodec&>(*this));
		}
	};

	class StriderProgressCallback : public strider::ProgressCallback {
		ThreadCallback* backendCallback;
	public:
		StriderProgressCallback(ThreadCallback* backend) {
			backendCallback = backend;
		}
		bool progress(size_t processedBytes, size_t compressedSize) {
			if (!backendCallback)
				return false;
			return backendCallback->progress(processedBytes, compressedSize);
		}
	};

	class StriderCodec : public Codec {

	public:
		StriderCodec(std::string _name, int _codecType) {
			name = _name;
			codecType = _codecType;
		}
		~StriderCodec() {}

		size_t encode(uint8_t* input, size_t inSize, uint8_t* output, const Parameters* parameters, ThreadCallback* callbacks) {

			StriderProgressCallback progressCallback(callbacks);
			size_t compressedSize = strider::compress(input, inSize, output, parameters->compressionLevel, &progressCallback);
			if (compressedSize == -1) {
				callbacks->set_error(ERROR_OUT_OF_MEMORY);
				return 0;
			}
			return compressedSize;
		}

		void decode(uint8_t* input, size_t encodedSize, uint8_t* output, size_t decodedSize, const Parameters* parameters, ThreadCallback* callbacks) {

			StriderProgressCallback progressCallback(callbacks);
			if (strider::decompress(input, encodedSize, output, decodedSize, &progressCallback))
				callbacks->set_error(ERROR_BAD_FILE);
		}

		size_t encode_bound(size_t inSize) {
			return strider::compress_bound(inSize);
		}

		size_t estimate_memory(size_t inSize, const Parameters* parameters) {
			return strider::estimate_memory(inSize, parameters->compressionLevel);
		}

		Codec* clone() {
			return new StriderCodec(static_cast<const StriderCodec&>(*this));
		}
	};

	class AES256Codec : public Codec {

		std::vector<uint8_t> globalHash = std::vector<uint8_t>(32, 0);

		uint64_t generate_salt() {
			static std::mutex mtx;
			//Just to make sure different threads dont get the same time
			mtx.lock();
			std::chrono::time_point<std::chrono::steady_clock> ts = std::chrono::steady_clock::now();
			uint64_t time = std::chrono::duration_cast<std::chrono::nanoseconds>(ts.time_since_epoch()).count();
			mtx.unlock();
			return time;
		}

		template<class Container>
		std::vector<uint8_t> sha256_hash_salted(Container password, uint8_t* salt, size_t iterations) {
			//Add salt to the password
			for (int i = 0; i < 16; i++)
				password.push_back(salt[i]);
			//Perform first hash on the password
			std::vector<uint8_t> hashA(picosha2::k_digest_size);
			picosha2::hash256<Container>(password, hashA);

			//Key stretching
			std::vector<uint8_t> hashB(picosha2::k_digest_size);
			for (size_t i = 1; i < iterations; i++) {
				//Readd salt
				for (int i = 0; i < 16; i++)
					hashA.push_back(salt[i]);
				picosha2::hash256<std::vector<uint8_t>>(hashA, hashB);
				hashA = hashB;
			}
			return hashA;
		}

	public:
		AES256Codec(std::string _name, int _codecType) {
			name = _name;
			codecType = _codecType;
		}
		~AES256Codec() {}

		size_t encode(uint8_t* input, size_t inSize, uint8_t* output, const Parameters* parameters, ThreadCallback* callbacks) {

			uint8_t iv[16];
			for (int i = 0; i < 2; i++) {
				uint64_t x = generate_salt();
				memcpy(iv + i * 8, &x, 8);
			}
			AES_ctx aes_ctx;
			AES_init_ctx_iv(&aes_ctx, globalHash.data(), iv);

			memcpy(output, iv, 16);
			memcpy(output + 16, input, inSize);
			AES_CTR_xcrypt_buffer(&aes_ctx, output + 16, inSize);

			return inSize + 16;
		}

		void decode(uint8_t* input, size_t encodedSize, uint8_t* output, size_t decodedSize, const Parameters* parameters, ThreadCallback* callbacks) {

			if (encodedSize - 16 != decodedSize) {
				callbacks->set_error(ERROR_BAD_FILE);
				return;
			}

			uint8_t iv[16];
			memcpy(iv, input, 16);
			AES_ctx aes_ctx;
			AES_init_ctx_iv(&aes_ctx, globalHash.data(), iv);

			memcpy(output, input + 16, decodedSize);
			AES_CTR_xcrypt_buffer(&aes_ctx, output, decodedSize);
		}

		size_t encode_bound(size_t inSize) {
			return inSize + 16;
		}

		size_t estimate_memory(size_t inSize, const Parameters* parameters) {
			return 0;
		}

		size_t encode_init(uint8_t* out, const Parameters* parameters) {

			uint8_t salt[16];
			for (int i = 0; i < 2; i++) {
				uint64_t x = generate_salt();
				memcpy(salt + i * 8, &x, 8);
			}

			std::vector<uint8_t> primaryHash = sha256_hash_salted<std::string>(parameters->password, salt, 1048576);
			std::vector<uint8_t> secondaryHash = sha256_hash_salted<std::vector<uint8_t>>(primaryHash, salt, 1048576);
			memcpy(globalHash.data(), primaryHash.data(), 32);

			memcpy(out, salt, 16);
			uint32_t storedHash = 0;
			for (int i = 0; i < 32; i++)
				storedHash ^= secondaryHash[i] << (i * 8) % 32;
			write_uint32le(out + 16, storedHash);
			return 20;
		}

		int decode_init(uint8_t* in, size_t inLength, const Parameters* parameters) {

			if (inLength < 20)
				return ERROR_BAD_FILE;

			uint8_t salt[16];
			memcpy(salt, in, 16);
			uint32_t storedHash = read_uint32le(in + 16);
			std::vector<uint8_t> primaryHash = sha256_hash_salted<std::string>(parameters->password, salt, 1048576);
			std::vector<uint8_t> secondaryHash = sha256_hash_salted<std::vector<uint8_t>>(primaryHash, salt, 1048576);
			memcpy(globalHash.data(), primaryHash.data(), 32);

			uint32_t computedHash = 0;
			for (int i = 0; i < 32; i++)
				computedHash ^= secondaryHash[i] << (i * 8) % 32;
			if (computedHash != storedHash)
				return ERROR_WRONG_PASSWORD;
			return NO_ERROR;
		}

		Codec* clone() {
			return new AES256Codec(static_cast<const AES256Codec&>(*this));
		}
	};

	std::vector<Codec*> AVAILABLE_CODECS = {
		new SpectrumCodec("spectrum", CODEC_COMPRESSOR),
		new SkandaCodec("skanda", CODEC_COMPRESSOR),
		new StriderCodec("strider", CODEC_COMPRESSOR),
		new AES256Codec("aes256", CODEC_ENCRYPTOR),
	};

	Codec* find_codec(const std::string& name) {
		for (int i = 0; i < AVAILABLE_CODECS.size(); i++) {
			if (AVAILABLE_CODECS[i]->get_name() == name)
				return AVAILABLE_CODECS[i];
		}
		return nullptr;
	}

	void free_codec_list(std::vector<Codec*>* codecList) {
		for (int i = 0; i < codecList->size(); i++)
			delete codecList->at(i);
	}

	////////////////////////////////////////////////////////
	//                                                    //
	//                      PACKING                       //
	//                                                    //
	////////////////////////////////////////////////////////

	struct DedupChunk {
		size_t originalPos;
		size_t copyPos;
		int length;
		union {
			//For compressor
			bool isLastChunkOfBlock; 
			//For decompressor: whether this chunk has already been copied
			bool copied;  
		};
	};

	struct ArchiveEntry {
		char type;
		std::string absolutePath;
		size_t size;  //Contained size for directories
		uint16_t permissions;
		time_t modifyTime;
		uint64_t globalPos = 0;  //If we concatenate all files, this is the byte this one would start at

		std::string get_filename() {
			return std::filesystem::path(absolutePath).filename().string();
		}
		std::string get_extension() {
			return std::filesystem::path(absolutePath).extension().string();
		}

		//For file sort. Placing similar files together can improve compression
		bool operator<(ArchiveEntry& other) {

			if (this->type != other.type)
				return this->type < other.type;

			std::string extensionA = this->get_extension();
			std::string extensionB = other.get_extension();

			if (extensionA != extensionB)
				return extensionA < extensionB;
			return this->get_filename() < other.get_filename();  //Can place similar files together
		}
	};

	void find_file_and_offset_from_global_pos(std::vector<ArchiveEntry>* entryList, size_t pos, size_t* fileIndex, size_t* fileOffset) {

		size_t low = 0;
		size_t high = entryList->size();

		while (high - low > 1) {
			size_t mid = (high + low) / 2;
			if (entryList->at(mid).globalPos > pos)
				high = mid;
			else
				low = mid;
		}

		*fileIndex = low;
		*fileOffset = pos - entryList->at(low).globalPos;
	}

	const size_t AVERAGE_CHUNK_SIZE = 4096;
	const size_t MAX_CHUNK_SIZE = 32767;
	const size_t ROLLING_HASH_SIZE = 32;

	//Precomputed byte to random integer for the rolling hash
	const uint32_t BYTE_HASHES[256] = {
		0x2f3a0a45,0x9c38665a,0x38431bfc,0xb81be8d6,0x9420a1d0,0x28c87049,0xb1a708b6,0x3af451c3,
		0x6fe6937c,0xf094e967,0x202c2072,0xf6bcaa8a,0x810a2e75,0x8bd3e945,0x8a73550f,0x1fe70f03,
		0x79989975,0xc30fc7e3,0x950d0630,0x24310762,0x4c4949a7,0xef7c4c47,0x4aa78544,0xf8b42971,
		0x65371b93,0x5e9be6ba,0x47a294e6,0x44350769,0xdb7052fd,0x1faaaabe,0x73860414,0x4f3c0926,
		0xbb89a34a,0xb8127034,0xeda7788c,0x16997c6c,0x4451b11d,0xf72a71b,0x9d4aeb07,0xebad3a01,
		0xf8da26ac,0xcb95b54e,0xc307eb2,0xc5a7dd41,0xd1bd71f6,0xc3413083,0xf5c7afbf,0xd2505c25,
		0xba557874,0x3464a504,0x4ee4c325,0x7b7d78da,0xeaf2e28c,0x969ed0d5,0x318b71ac,0x43d339c5,
		0xf0e0b248,0x2bc6b123,0x357d86f,0x67de96ce,0x552570ac,0x92d612f6,0x94891b6,0x901e3da1,
		0xc6e39678,0xa88a2820,0x21e6d565,0xb4ba417f,0x41bbe603,0x5ed0e2c,0x75b70db,0xc7aabd2,
		0x340bdd96,0x2cd12219,0x29faa5fc,0x269c9937,0xdb212f46,0x2777cdb9,0xabbc5003,0xbfe205a7,
		0xe249e419,0x3ac31e1e,0xc15a3b73,0x4bb2696a,0xeaa5490,0xe3312b76,0x9e2ac894,0xf664d08,
		0x302924d,0x48172839,0xcd944f60,0x56f2941f,0x54bec81,0x3cbeabb2,0xf2998564,0x6d9f57e8,
		0xb192f2d5,0x2104808f,0xd9136438,0xa4f1084c,0x80e04dcc,0xe2542dc1,0xabf804ec,0xa8378503,
		0x1c99a8bc,0xd617985b,0xef8832d5,0x9c52fc54,0x47c51eb6,0xc4a0c1d6,0xe0b94e5e,0xc3d5b2a8,
		0x66512015,0x63b9ae1c,0x2c717ad0,0x6fea4a96,0xdda2acd4,0x6759abea,0x189a6c20,0x48c4ec8b,
		0x92f033af,0xbeb6be58,0x3bf4bf34,0x62665277,0x6718bb11,0x786aff13,0xef3e650b,0x32309cfb,
		0x3bf3c6d9,0xadf26af1,0xbb62e089,0xea38eada,0x1b031103,0x715579cc,0x271143b9,0x6525bf45,
		0x7babddce,0x81248d44,0xbd9f1e75,0x8f12bfa4,0x9b65c7ca,0x2fb22cd8,0xdb43b174,0x19bae237,
		0x1382b363,0x8b4cc3ed,0x200e811f,0x4decac7b,0xe53cfc43,0xa208eca6,0xc3d50927,0xa5ad53b7,
		0x59acb870,0xf2d968bf,0x9539428d,0x1d6ccb88,0x6005afb8,0xb147d8f3,0x45e80345,0xeaaa3769,
		0xbb05edd5,0x609b76f0,0x435951a6,0xb49ffe6d,0x15ba6a26,0xcff2af2b,0xe57749d3,0xaf2c1c58,
		0x7da9e,0x3ef081dc,0x1eaa9908,0x7f783ea2,0x46df7be8,0x932b4cc9,0x8f9daf72,0xa8df42e6,
		0xb06b17b7,0x94866a5f,0xe74e22ab,0x969e4be9,0x9892a13c,0xa6f1261a,0xa03bf0c6,0x354a12b0,
		0x5a7794a0,0xbfca2454,0xa2fccb,0xb7c3b863,0x9f594208,0xb6f32f53,0xce5401fd,0x52d8d7fb,
		0x1285f1f8,0x4f813b6a,0x7f02d161,0x83377fd2,0x8f5e20d,0x4ada849e,0xf13460b6,0x8378fe9a,
		0x67c670d5,0xd109fa6c,0x914eb121,0xd19f995e,0x9031cefd,0xc557c196,0xebb42f55,0x69d88fb4,
		0x7441514b,0x6cfdf55d,0xe47ba83d,0x7f7d4b73,0x77168d75,0xae2bd5c1,0xcabdf4ae,0xdeb867a,
		0x2b5b72a6,0xa9cc2bd4,0xed6b6526,0x7c3bf7d7,0x38e194e3,0x96bf66d0,0x2c5570fe,0xcf67d4f9,
		0x1404ba44,0x7f706fd1,0xe5878a67,0xa4f951d1,0x2068b1c1,0x2036f947,0x5960a011,0x7a23d260,
		0x9188ba73,0x57095aff,0xf562d381,0x1ae47165,0x7aa87b90,0x608989b8,0x19ab2123,0x37f25d42,
		0xd950a782,0x7de2c7e5,0xfd84378a,0x71ac5b8a,0x76979dac,0xabcfe049,0x33bbe89c,0x29dd8754,
		0xd87e544f,0xe031f4fe,0x4b810d44,0x88749533,0xa4f0c5d2,0x2b24e2df,0x577dc1bf,0xecfc9c92,
	};

	size_t get_chunk_size(uint8_t* data, size_t dataSize) {
		//Not much data left, the chunk will extend to file end
		if (dataSize < AVERAGE_CHUNK_SIZE / 2)
			return dataSize;
		else {
			size_t pos = AVERAGE_CHUNK_SIZE / 2;
			uint32_t rollingHash = 0;
			for (size_t i = 0; i < ROLLING_HASH_SIZE; i++)
				rollingHash = (rollingHash >> 1) ^ BYTE_HASHES[data[pos - ROLLING_HASH_SIZE + i]];

			for (; pos < dataSize; pos++) {
				rollingHash = (rollingHash >> 1) ^ BYTE_HASHES[data[pos]];
				if (rollingHash % (AVERAGE_CHUNK_SIZE / 2) == 0)
					break;
			}
			return pos;
		}
	}

	#pragma pack(push, 2)
	struct DeduperDictEntry {
		uint64_t pos = 0;
		uint64_t hash = 0;
		uint16_t otherData = 0;
		DeduperDictEntry() {}
		DeduperDictEntry(uint64_t pos, uint64_t hash, uint16_t length, bool lastChunkOfBlock) {
			this->pos = pos;
			this->hash = hash;
			this->otherData = length | (lastChunkOfBlock << 15);
		}
		uint16_t length() {
			return otherData & 0x7FFF;
		}
		bool is_last_chunk_of_block() {
			return otherData >> 15;
		}
	};
	#pragma pack(pop)

	class DeduperDictionary {
	public:
		//A very high load factor allows us to more tightly pack all the hashes in memory, at the cost
		// of speed. This is however not an issue, since the bottleneck will still be disk reads.
		const size_t BUCKET_LOAD = 64;
		DeduperDictEntry* hashTable = nullptr;
		size_t* bucketLoads = nullptr;
		size_t tableMask = 0;
		std::shared_mutex mtx;

		DeduperDictionary() {}
		~DeduperDictionary() {
			delete[] hashTable;
			delete[] bucketLoads;
		}
		void init(size_t bucketsLog) {
			tableMask = (1 << bucketsLog) - 1;
			hashTable = new DeduperDictEntry[BUCKET_LOAD << bucketsLog];
			bucketLoads = new size_t[1 << bucketsLog]();
		}
		//Returns length of 0 if not found
		DeduperDictEntry at(uint64_t hash) {
			mtx.lock_shared();
			size_t maxPos = bucketLoads[hash & tableMask];
			size_t pos = maxPos < BUCKET_LOAD ? 0 : maxPos - BUCKET_LOAD;
			DeduperDictEntry result(0, 0, 0, 0);
			DeduperDictEntry* bucket = &hashTable[(hash & tableMask) * BUCKET_LOAD];
			for (; pos < maxPos; pos++) {
				if (bucket[pos % BUCKET_LOAD].hash == hash) {
					result = bucket[pos % BUCKET_LOAD];
					break;
				}
			}
			mtx.unlock_shared();
			return result;
		}
		//Adds the new element to the table
		void emplace(DeduperDictEntry block) {
			mtx.lock();
			DeduperDictEntry* bucket = &hashTable[(block.hash & tableMask) * BUCKET_LOAD];
			size_t load = bucketLoads[block.hash & tableMask];
			bucket[load % BUCKET_LOAD] = block;
			bucketLoads[block.hash & tableMask]++;
			mtx.unlock();
		}
	};

	struct PackedBlock {
		uint8_t* data = nullptr;
		//Output sizes of each codec. The first element is the raw size minus deduplicated chunks
		std::vector<size_t> outputSizes; 
		int type = 0;
		//Position of data block in global space
		size_t globalPos = 0;
		//For data blocks
		std::vector<DedupChunk> dedupChunks;
	};

	void pack_block(PackedBlock* packedBlock, std::vector<Codec*>* codecList, const Parameters& parameters, ThreadCallback* callbacks)
	{
		for (auto codec : *codecList) {

			uint8_t* output = new (std::nothrow) uint8_t[codec->encode_bound(packedBlock->outputSizes.back())];
			if (!output) {
				callbacks->set_error(ERROR_OUT_OF_MEMORY);
				delete[] packedBlock->data;
				packedBlock->data = nullptr;
				return;
			}

			size_t encodedSize = codec->encode(packedBlock->data, packedBlock->outputSizes.back(), output, &parameters, callbacks);
			packedBlock->outputSizes.push_back(encodedSize);
			delete[] packedBlock->data;
			packedBlock->data = nullptr;

			if (callbacks->abort())
				return;
			packedBlock->data = output;
			callbacks->set_progress_scale((double)packedBlock->outputSizes.front() / std::max(packedBlock->outputSizes.back(), (size_t)1));
		}
		callbacks->end_block(packedBlock->outputSizes.front(), packedBlock->outputSizes.back());
	}

	void write_block(std::fstream* outFile, PackedBlock* packedBlock) {

		if (packedBlock->type == END_BLOCK_ID) {
			std::vector<uint8_t> blockHeader;
			blockHeader.push_back(1);
			blockHeader.push_back(packedBlock->type);
			uint16_t checksum = CRC::Calculate(blockHeader.data(), blockHeader.size(), CRC::CRC_16_X25());
			write_uint16le(outFile, checksum);
			outFile->write((char*)blockHeader.data(), blockHeader.size());
			return;
		}

		std::vector<uint8_t> blockHeader(10, 0);
		//Block type
		blockHeader.push_back(packedBlock->type);
		//Sizes of all codecs
		for (int i = 0; i < packedBlock->outputSizes.size(); i++) 
			write_LEB128_vector(&blockHeader, packedBlock->outputSizes[i]);
		if (packedBlock->type == DATA_BLOCK_ID) {
			//Block pos
			write_LEB128_vector(&blockHeader, packedBlock->globalPos);
			//Dedup info
			size_t lastCopyEnd = 0;
			for (int i = 0; i < packedBlock->dedupChunks.size(); i++) {
				write_LEB128_vector(&blockHeader, packedBlock->dedupChunks[i].length);
				size_t copyPosDelta = packedBlock->dedupChunks[i].copyPos - lastCopyEnd;
				write_LEB128_vector(&blockHeader, copyPosDelta);
				write_LEB128_vector(&blockHeader, packedBlock->dedupChunks[i].originalPos);
				lastCopyEnd = packedBlock->dedupChunks[i].copyPos + packedBlock->dedupChunks[i].length;
			}
			//Signal no more deduplication with a length 0
			blockHeader.push_back(0);
		}

		//Write header length
		uint8_t* headerSizePtr = blockHeader.data();
		write_LEB128_ptr(headerSizePtr, blockHeader.size() - 10);
		blockHeader.erase(blockHeader.begin() + (headerSizePtr - blockHeader.data()), blockHeader.begin() + 10);

		uint16_t headerChecksum = CRC::Calculate(blockHeader.data(), blockHeader.size(), CRC::CRC_16_X25());
		write_uint16le(outFile, headerChecksum);
		outFile->write((char*)blockHeader.data(), blockHeader.size());

		uint32_t dataChecksum = CRC::Calculate(packedBlock->data, packedBlock->outputSizes.back(), CRC::CRC_32());
		write_uint32le(outFile, dataChecksum);
		outFile->write((char*)packedBlock->data, packedBlock->outputSizes.back());
	}

	void data_block_thread(std::fstream* outFile, std::vector<Codec*>* codecList, const Parameters& parameters,
		std::vector<ArchiveEntry>* entryList, size_t* globalReadBytes, const size_t totalBytes,
		std::mutex* diskReadMtx, std::mutex* diskWriteMtx, ThreadCallback* progress, DeduperDictionary* blockHashes)
	{
		size_t lastOpenedFile = -1;
		std::fstream otherFileStream;
		uint8_t* otherFileData = new uint8_t[MAX_CHUNK_SIZE];

		while (true) {
			size_t thisBlockSize = 0;
			uint8_t* inputBuffer = new (std::nothrow) uint8_t[parameters.maxBlockSize];
			if (!inputBuffer) {
				progress->set_error(ERROR_OUT_OF_MEMORY);
				delete[] otherFileData;
				return;
			}

			diskReadMtx->lock();

			if (*globalReadBytes == totalBytes) {
				diskReadMtx->unlock();
				delete[] inputBuffer;
				delete[] otherFileData;
				return;
			}

			size_t globalBlockPos = *globalReadBytes;
			size_t fileIndex, fileOffset;
			find_file_and_offset_from_global_pos(entryList, globalBlockPos, &fileIndex, &fileOffset);

			if (parameters.useSolidBlock) 
				thisBlockSize = std::min(totalBytes - globalBlockPos, parameters.maxBlockSize);
			else {
				//Skip zero length files and non files
				while (entryList->at(fileIndex).size == 0 || entryList->at(fileIndex).type != 'f') { fileIndex++; }
				thisBlockSize = std::min(entryList->at(fileIndex).size - fileOffset, parameters.maxBlockSize);
			}
			*globalReadBytes += thisBlockSize;

			PackedBlock packedBlock;
			packedBlock.data = inputBuffer;
			packedBlock.outputSizes.push_back(thisBlockSize);
			packedBlock.type = DATA_BLOCK_ID;
			packedBlock.globalPos = globalBlockPos;

			diskReadMtx->unlock();

			if (thisBlockSize == 0) {
				delete[] inputBuffer;
				delete[] otherFileData;
				return;
			}

			size_t readBytes = 0;
			std::fstream inFile;

			while (readBytes < thisBlockSize) {

				//Last file was finished, open the next one
				if (!inFile.is_open()) {
					if (entryList->at(fileIndex).type != 'f' || entryList->at(fileIndex).size == 0) {
						fileIndex++;
						continue;
					}
					inFile.open(entryList->at(fileIndex).absolutePath, std::fstream::in | std::fstream::binary);
					if (!inFile.is_open()) {
						progress->set_error(ERROR_INPUT_FILE_OPEN_FAIL);
						delete[] inputBuffer;
						delete[] otherFileData;
						return;
					}
					inFile.seekg(fileOffset);
				}

				size_t bytesToRead = std::min(thisBlockSize - readBytes, entryList->at(fileIndex).size - fileOffset);
				inFile.read((char*)inputBuffer + readBytes, bytesToRead);
				readBytes += bytesToRead;

				if (entryList->at(fileIndex).size == inFile.tellg()) {
					inFile.close();
					fileIndex++;
					fileOffset = 0;
				}
			}

			inFile.close();
			
			//This can happen when the last files have size 0 or we have read all files
			if (thisBlockSize == 0) {
				delete[] inputBuffer;
				delete[] otherFileData;
				return;
			}

			if (blockHashes != nullptr) {

				size_t totalDedup = 0;
				size_t blockPos = 0;

				while (blockPos < thisBlockSize) {
					
					size_t fileIndex, fileOffset;
					find_file_and_offset_from_global_pos(entryList, globalBlockPos + blockPos, &fileIndex, &fileOffset);

					size_t bytesToEndOfBlock = thisBlockSize - blockPos;
					size_t bytesToEndOfFile = entryList->at(fileIndex).globalPos + entryList->at(fileIndex).size - (globalBlockPos + blockPos);
					size_t maxChunkSize = std::min(bytesToEndOfBlock, bytesToEndOfFile);

					//Skip very small chunks
					if (maxChunkSize < 512) {
						blockPos += maxChunkSize;
						continue;
					}

					uint8_t* const chunkBegin = inputBuffer + blockPos;
					uint64_t hash = XXH3_64bits(chunkBegin, std::min(maxChunkSize, AVERAGE_CHUNK_SIZE / 2));
					size_t chunkSize = get_chunk_size(chunkBegin, std::min(maxChunkSize, MAX_CHUNK_SIZE));

					DeduperDictEntry otherBlock = blockHashes->at(hash);
					if (otherBlock.length() != 0) {
						size_t otherFileIndex, otherFileOffset;
						find_file_and_offset_from_global_pos(entryList, otherBlock.pos, &otherFileIndex, &otherFileOffset);
						size_t maxCompare = std::min(chunkSize, (size_t)otherBlock.length());

						uint8_t* dedupBuffer;
						//Possible dedup is in current memory block
						if (otherBlock.pos >= globalBlockPos && otherBlock.pos < globalBlockPos + thisBlockSize)
							dedupBuffer = inputBuffer + otherBlock.pos - globalBlockPos;
						else {
							if (lastOpenedFile != otherFileIndex) {
								otherFileStream.close();
								otherFileStream.open(entryList->at(otherFileIndex).absolutePath, std::fstream::in | std::fstream::binary);
								lastOpenedFile = otherFileIndex;
							}

							otherFileStream.seekg(otherFileOffset);
							otherFileStream.read((char*)otherFileData, maxCompare);
							dedupBuffer = otherFileData;
						}

						size_t dedupLength = std::mismatch(chunkBegin, chunkBegin + maxCompare, dedupBuffer).first - chunkBegin;

						if (dedupLength >= ROLLING_HASH_SIZE) {

							DedupChunk newDedup;
							newDedup.copyPos = blockPos;
							newDedup.length = dedupLength;
							newDedup.originalPos = otherBlock.pos; 
							newDedup.isLastChunkOfBlock = otherBlock.is_last_chunk_of_block();

							if (packedBlock.dedupChunks.size() > 0) {

								//Check if this deduped chunk is a continuation of the last deduped chunk, 
								// and does not cross any file or block boundaries.
								size_t lastCopyIndex, lastCopyOffset;
								find_file_and_offset_from_global_pos(entryList, packedBlock.dedupChunks.back().copyPos + packedBlock.globalPos, &lastCopyIndex, &lastCopyOffset);
								size_t lastOriginalIndex, lastOriginalOffset;
								find_file_and_offset_from_global_pos(entryList, packedBlock.dedupChunks.back().originalPos, &lastOriginalIndex, &lastOriginalOffset);

								//If the last deduped chunk references the last chunk of another block, and
								// this would be a continuation of that it means it would cross a block boundary.
								if (!packedBlock.dedupChunks.back().isLastChunkOfBlock &&
									lastCopyIndex == fileIndex && lastOriginalIndex == otherFileIndex &&
									packedBlock.dedupChunks.back().copyPos + packedBlock.dedupChunks.back().length == blockPos &&
									packedBlock.dedupChunks.back().originalPos + packedBlock.dedupChunks.back().length == otherBlock.pos)
								{
									packedBlock.dedupChunks.back().length += dedupLength;
									packedBlock.dedupChunks.back().isLastChunkOfBlock = otherBlock.is_last_chunk_of_block();
								}
								else
									packedBlock.dedupChunks.push_back(newDedup);
							}
							else 
								packedBlock.dedupChunks.push_back(newDedup);
							
							totalDedup += dedupLength;
							progress->add_base_progress(dedupLength);
						}
					}
					else {
						bool isLastChunkOfBlock = blockPos + chunkSize == thisBlockSize;
						blockHashes->emplace(DeduperDictEntry(globalBlockPos + blockPos, hash, chunkSize, isLastChunkOfBlock));
					}
					blockPos += chunkSize;
				}

				//Remove deduped chunks
				if (packedBlock.dedupChunks.size() != 0) {
					size_t pos = packedBlock.dedupChunks[0].copyPos;
					for (int i = 0; i < packedBlock.dedupChunks.size(); i++) {
						size_t nextDedup = i + 1 >= packedBlock.dedupChunks.size() ? thisBlockSize : packedBlock.dedupChunks[i + 1].copyPos;
						size_t curDedupEnd = packedBlock.dedupChunks[i].copyPos + packedBlock.dedupChunks[i].length;
						memmove(inputBuffer + pos, inputBuffer + curDedupEnd, nextDedup - curDedupEnd);
						pos += nextDedup - curDedupEnd;
					}
				}
				packedBlock.outputSizes.back() -= totalDedup;
			}

			pack_block(&packedBlock, codecList, parameters, progress);

			//Error during encoding
			if (progress->abort()) {
				delete[] otherFileData;
				return;
			}

			diskWriteMtx->lock();

			write_block(outFile, &packedBlock);

			diskWriteMtx->unlock();
			
			delete[] packedBlock.data;
		}
	}

	void write_data_blocks(std::fstream* outFile, std::vector<Codec*>* codecList, const Parameters& parameters,
		std::vector<ArchiveEntry>* entryList, size_t totalBytes, ArchiveCallbackInternal* callbacksInternal)
	{
		DeduperDictionary blockHashes;
		if (parameters.deduplicationMemoryLog)
			blockHashes.init(std::min(std::max((int)log2(totalBytes) - 18, 0), (int)parameters.deduplicationMemoryLog));
		std::thread* cpu = new std::thread[parameters.threads];
		ThreadCallback* progress = new ThreadCallback[parameters.threads];
		for (int i = 0; i < parameters.threads; i++)
			progress[i].init(i, callbacksInternal);
		std::mutex diskReadMtx;
		std::mutex diskWriteMtx;
		size_t globalReadBytes = 0;

		for (int i = 0; i < parameters.threads; i++)
			cpu[i] = std::thread(data_block_thread, outFile, codecList, parameters, entryList, &globalReadBytes, totalBytes, 
				&diskReadMtx, &diskWriteMtx, &progress[i], parameters.deduplicationMemoryLog ? &blockHashes : nullptr);
		for (int i = 0; i < parameters.threads; i++) {
			if (cpu[i].joinable())
				cpu[i].join();
		}

		delete[] cpu;
		delete[] progress;
	}

	time_t convert_modify_time(const std::filesystem::file_time_type& time) {
#if CPP_VER >= 202002L
		const auto systemTime = std::chrono::clock_cast<std::chrono::system_clock>(time);
		return std::chrono::system_clock::to_time_t(systemTime);
#else
		//No portable way of doing this pre C++20, just return something
		return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
#endif
	}

	uint16_t convert_permissions(std::filesystem::perms permissions) {
		return ((permissions & std::filesystem::perms::owner_read) != std::filesystem::perms::none) << 0 |
			((permissions & std::filesystem::perms::owner_write) != std::filesystem::perms::none) << 1 |
			((permissions & std::filesystem::perms::owner_exec) != std::filesystem::perms::none) << 2 |
			((permissions & std::filesystem::perms::group_read) != std::filesystem::perms::none) << 3 |
			((permissions & std::filesystem::perms::group_write) != std::filesystem::perms::none) << 4 |
			((permissions & std::filesystem::perms::group_exec) != std::filesystem::perms::none) << 5 |
			((permissions & std::filesystem::perms::others_read) != std::filesystem::perms::none) << 6 |
			((permissions & std::filesystem::perms::others_write) != std::filesystem::perms::none) << 7 |
			((permissions & std::filesystem::perms::others_exec) != std::filesystem::perms::none) << 8;
	}

	void get_directory_entries(std::vector<ArchiveEntry>* entryList, const std::string& path, size_t* containedSize) {

		for (auto entry : std::filesystem::directory_iterator(path)) {

			std::string entryPath = entry.path().generic_string();
			if (entry.is_directory()) {
				size_t subContainedSize = 0;
				get_directory_entries(entryList, entryPath, &subContainedSize);
				entryList->push_back({ 'd', entryPath, subContainedSize, convert_permissions(entry.status().permissions()), convert_modify_time(entry.last_write_time()) });
				*containedSize += subContainedSize;
			}
			else if (entry.is_regular_file()) {
				entryList->push_back({ 'f', entryPath, entry.file_size(), convert_permissions(entry.status().permissions()), convert_modify_time(entry.last_write_time()) });
				*containedSize += entry.file_size();
			}
		}
	}

	int get_all_files(const std::vector<std::string>& inputElements, std::vector<ArchiveEntry>* entryList) {

		if (inputElements.empty())
			return ERROR_INVALID_ARGUMENT;
		//Common base path shared by all elements
		std::string commonPath = std::filesystem::absolute(inputElements[0]).parent_path().generic_string();

		try {
			for (size_t i = 0; i < inputElements.size(); i++) {

				std::string entryPath = std::filesystem::absolute(inputElements[i]).generic_string();
				std::string parentPath = std::filesystem::path(entryPath).parent_path().generic_string();
				if (parentPath != commonPath)
					return ERROR_INVALID_ARGUMENT;

				if (std::filesystem::is_directory(inputElements[i])) {

					size_t containedSize;
					get_directory_entries(entryList, inputElements[i], &containedSize);
					entryList->push_back({ 'd', entryPath, containedSize, convert_permissions(std::filesystem::status(entryPath).permissions()),
						convert_modify_time(std::filesystem::last_write_time(entryPath)) });
				}
				else {
					size_t fileSize = std::filesystem::file_size(entryPath);
					entryList->push_back({ 'f', entryPath, fileSize, convert_permissions(std::filesystem::status(entryPath).permissions()),
						convert_modify_time(std::filesystem::last_write_time(entryPath)) });
				}
			}
		}
		catch (std::bad_alloc& e) {
			return ERROR_OUT_OF_MEMORY;
		}
		catch (std::filesystem::filesystem_error& e) {
			return ERROR_INPUT_FILE_OPEN_FAIL;
		}
		return NO_ERROR;
	}

	int write_file_tree_header(const std::vector<std::string>& inputElements, std::vector<ArchiveEntry>* entryList,
		std::fstream* outFile, std::vector<Codec*>* codecList, const Parameters& parameters)
	{
		std::string commonPath = std::filesystem::absolute(inputElements[0]).parent_path().generic_string();
		size_t relativePathOff = commonPath.size() + (commonPath.back() != '/');

		std::vector<uint8_t> headerStream;
		uint8_t* headerStreamPtr = nullptr;
		try {

			write_LEB128_vector(&headerStream, entryList->size());
			for (size_t i = 0; i < entryList->size(); i++) {
				headerStream.push_back(entryList->at(i).type);
				if (entryList->at(i).type == 'f' || entryList->at(i).type == 'd') {
					std::string relPath = entryList->at(i).absolutePath.substr(relativePathOff);
					for (size_t c = 0; c < relPath.size(); c++)
						headerStream.push_back(relPath[c]);
					headerStream.push_back('\0');
					write_LEB128_vector(&headerStream, entryList->at(i).size);
					headerStream.push_back(entryList->at(i).permissions & 0xFF);
					headerStream.push_back(entryList->at(i).permissions >> 8);
					write_LEB128_vector(&headerStream, entryList->at(i).modifyTime);
				}
			}

			//Yes, this is ugly, but I want to reuse the pack_block function, and that deletes input buffer
			headerStreamPtr = new uint8_t[headerStream.size()];
			memcpy(headerStreamPtr, headerStream.data(), headerStream.size());
		}
		catch (std::bad_alloc& e) {
			return ERROR_OUT_OF_MEMORY;
		}

		PackedBlock packedHeader;
		packedHeader.type = FILE_TREE_BLOCK_ID;
		packedHeader.data = headerStreamPtr;
		packedHeader.outputSizes.push_back(headerStream.size());
		
		ThreadCallback threadCallback;
		threadCallback.init(0, nullptr);
		pack_block(&packedHeader, codecList, parameters, &threadCallback);
		if (threadCallback.get_error())
			return threadCallback.get_error();
		write_block(outFile, &packedHeader);
		return NO_ERROR;
	}

	int write_codec_header(std::fstream* outFile, std::vector<Codec*>* codecList, const Parameters& parameters)
	{
		std::vector<uint8_t> codecHeader(2, 0);  //Reserve 2 bytes for header size
		for (auto codecName : parameters.codecNameList) {

			Codec* codec = find_codec(codecName);
			if (codec == nullptr)
				return ERROR_UNKNOWN_CODEC;
			codecList->push_back(codec->clone());

			uint8_t codecData[255];
			int codecDataLength = codecList->back()->encode_init(codecData, &parameters);
			codecHeader.push_back(codecList->back()->name.size());
			for (int i = 0; i < codecList->back()->name.size(); i++)
				codecHeader.push_back(codecList->back()->name[i]);
			codecHeader.push_back(codecDataLength);
			for (int i = 0; i < codecDataLength; i++)
				codecHeader.push_back(codecData[i]);
		}
		codecHeader.push_back(0);
		write_uint16le(codecHeader.data(), codecHeader.size() - 2);

		uint16_t checksum = CRC::Calculate(codecHeader.data(), codecHeader.size(), CRC::CRC_16_X25());
		write_uint16le(outFile, checksum);
		outFile->write((char*)codecHeader.data(), codecHeader.size());
		return NO_ERROR;
	}

	int create_archive(const std::vector<std::string>& inputElements, const std::string& archivePath,
		const Parameters& parameters, ArchiveCallback* callbacks)
	{
		ArchiveCallbackInternal callbacksInternal(callbacks);

		//Create the archive
		std::fstream outFile(archivePath, std::fstream::binary | std::fstream::out);
		if (!outFile.is_open())
			return ERROR_OUTPUT_FILE_OPEN_FAIL;
		outFile.write((char*)FILE_SIGNATURE, sizeof(FILE_SIGNATURE));
		std::vector<Codec*> codecList;
		int error = write_codec_header(&outFile, &codecList, parameters);
		if (error) {
			free_codec_list(&codecList);
			outFile.close();
			std::filesystem::remove(archivePath);
			return error;
		}

		std::vector<ArchiveEntry> entryList;
		error = get_all_files(inputElements, &entryList);
		if (error) {
			free_codec_list(&codecList);
			outFile.close();
			std::filesystem::remove(archivePath);
			return error;
		}

		//Sort files to try and put the ones with similar content closer to each other
		if (parameters.useSolidBlock)
			std::sort(entryList.begin(), entryList.end());
		size_t totalContainedSize = 0;
		for (auto it = entryList.begin(); it != entryList.end(); it++) {
			it->globalPos = totalContainedSize;
			if (it->type != 'f')
				continue;
			totalContainedSize += it->size;
		}
		callbacksInternal.init(parameters.threads, totalContainedSize);

		error = write_file_tree_header(inputElements, &entryList, &outFile, &codecList, parameters);
		if (error) {
			free_codec_list(&codecList);
			outFile.close();
			std::filesystem::remove(archivePath);
			return error;
		}
		
		//Write end block
		write_data_blocks(&outFile, &codecList, parameters, &entryList, totalContainedSize, &callbacksInternal);
		PackedBlock endBlock;
		endBlock.type = END_BLOCK_ID;
		write_block(&outFile, &endBlock);

		outFile.close();
		if (callbacksInternal.abort())
			std::filesystem::remove(archivePath);
		free_codec_list(&codecList);
		return callbacksInternal.get_error();
	}

	////////////////////////////////////////////////////////
	//                                                    //
	//                     EXTRACTION                     //
	//                                                    //
	////////////////////////////////////////////////////////

	struct UnpackedBlock {
		uint8_t* data = nullptr;
		size_t rawSize;  //Bytes contained in this block
		//Encoded size from each codec. First element is rawSize minus deduplicated chunks
		std::vector<size_t> codecSizes;
		int type = 0;
		size_t offset = 0;  //Position of contents of block from start of archive file
		size_t globalPos = 0;  //Position of contents of block in terms of global file position
		uint32_t dataChecksum;
		std::vector<DedupChunk> dedupChunks;
	};

	void unpack_block(UnpackedBlock* unpackedBlock, std::vector<Codec*>* codecList, const Parameters& parameters, ThreadCallback* callbacks)
	{
		size_t storedSize = unpackedBlock->codecSizes.back();

		for (auto codec = codecList->rbegin(); codec != codecList->rend(); codec++) {

			size_t encodedSize = unpackedBlock->codecSizes.back();
			unpackedBlock->codecSizes.pop_back();
			size_t decodedSize = unpackedBlock->codecSizes.back();
			callbacks->set_progress_scale((double)unpackedBlock->codecSizes.front() / std::max(decodedSize, (size_t)1));

			uint8_t* output = new (std::nothrow) uint8_t[decodedSize];
			if (!output) {
				callbacks->set_error(ERROR_OUT_OF_MEMORY);
				delete[] unpackedBlock->data;
				unpackedBlock->data = nullptr;
				return;
			}

			(*codec)->decode(unpackedBlock->data, encodedSize, output, decodedSize, &parameters, callbacks);
			delete[] unpackedBlock->data;
			unpackedBlock->data = nullptr;

			if (callbacks->abort())
				return;
			unpackedBlock->data = output;
		}

		callbacks->end_block(unpackedBlock->codecSizes.back(), storedSize);
	}

	int read_block_header(std::fstream* inFile, UnpackedBlock* unpackedBlock, std::vector<Codec*>* codecList)
	{
		uint16_t storedHeaderChecksum = read_uint16le(inFile);
		size_t headerSize;
		if (read_LEB128_file(inFile, &headerSize))
			return ERROR_BAD_FILE;
		uint8_t* headerData = new uint8_t[headerSize + 10];
		uint8_t* headerSizeIt = headerData;
		write_LEB128_ptr(headerSizeIt, headerSize);
		const uint8_t* headerIt = headerSizeIt;
		const uint8_t* headerEnd = headerIt + headerSize;
		inFile->read((char*)headerIt, headerSize);

		uint16_t computedHeaderChecksum = CRC::Calculate(headerData, headerEnd - headerData, CRC::CRC_16_X25());
		if (computedHeaderChecksum != storedHeaderChecksum) {
			delete[] headerData;
			return ERROR_BAD_CHECKSUM;
		}

		unpackedBlock->codecSizes.clear();
		unpackedBlock->type = *headerIt++;
		if (unpackedBlock->type == END_BLOCK_ID) {
			delete[] headerData;
			return NO_ERROR;
		}

		for (int i = 0; i <= codecList->size(); i++) {
			size_t size;
			if (read_LEB128_ptr(headerIt, headerEnd, &size)) {
				delete[] headerData;
				return ERROR_BAD_FILE;
			}
			unpackedBlock->codecSizes.push_back(size);
		}

		//Dedup info
		size_t dedupSize = 0;
		if (unpackedBlock->type == DATA_BLOCK_ID) {

			if (read_LEB128_ptr(headerIt, headerEnd, &unpackedBlock->globalPos)) {
				delete[] headerData;
				return ERROR_BAD_FILE;
			}

			size_t lastCopyEnd = 0;
			while (true) {
				DedupChunk newChunk;
				newChunk.copied = false;
				size_t length;
				if (read_LEB128_ptr(headerIt, headerEnd, &length)) {
					delete[] headerData;
					return ERROR_BAD_FILE;
				}
				if (length == 0)
					break;
				newChunk.length = length;
				dedupSize += newChunk.length;
				size_t copyPosDelta;
				if (read_LEB128_ptr(headerIt, headerEnd, &copyPosDelta)) {
					delete[] headerData;
					return ERROR_BAD_FILE;
				}
				newChunk.copyPos = copyPosDelta + lastCopyEnd;
				lastCopyEnd = newChunk.copyPos + newChunk.length;
				if (read_LEB128_ptr(headerIt, headerEnd, &newChunk.originalPos)) {
					delete[] headerData;
					return ERROR_BAD_FILE;
				}
				unpackedBlock->dedupChunks.push_back(newChunk);
			}
		}

		unpackedBlock->rawSize = unpackedBlock->codecSizes.front() + dedupSize;

		delete[] headerData;
		unpackedBlock->dataChecksum = read_uint32le(inFile);
		unpackedBlock->offset = inFile->tellg();

		return NO_ERROR;
	}

	int parse_file_tree_header(const uint8_t* headerStream, const size_t headerStreamSize,
		std::vector<ArchiveEntry>* entryList, const std::string& outDir)
	{
		try {
			size_t globalPos = 0;
			const uint8_t* const headerStreamEnd = headerStream + headerStreamSize;

			if (headerStream == headerStreamEnd)
				return ERROR_BAD_FILE;

			size_t numberElements;
			if (read_LEB128_ptr(headerStream, headerStreamEnd, &numberElements))
				return ERROR_BAD_FILE;

			for (size_t i = 0; i < numberElements; i++) {
				if (headerStream == headerStreamEnd)
					return ERROR_BAD_FILE;
				char elementType = *headerStream++;

				//Directory
				if (elementType == 'd' || elementType == 'f') {

					std::string relPath;
					while (true) {
						if (headerStream == headerStreamEnd)
							return ERROR_BAD_FILE;
						uint8_t ch = *headerStream++;
						if (ch == '\0')
							break;
						relPath.push_back(ch);
					}
					size_t size;
					if (read_LEB128_ptr(headerStream, headerStreamEnd, &size))
						return ERROR_BAD_FILE;
					if (headerStream + 1 >= headerStreamEnd)
						return ERROR_BAD_FILE;
					uint16_t permissions = *headerStream++;
					permissions |= *headerStream++ << 8;
					size_t modifyTime;
					if (read_LEB128_ptr(headerStream, headerStreamEnd, &modifyTime))
						return ERROR_BAD_FILE;
					entryList->push_back({ elementType, outDir + '/' + relPath, size, permissions, (time_t)modifyTime, globalPos });
					if (elementType == 'f')
						globalPos += size;
				}
			}
		}
		catch (std::bad_alloc& e) {
			return ERROR_OUT_OF_MEMORY;
		}
		return NO_ERROR;
	}

	int read_file_tree_header(std::fstream* inFile, std::vector<Codec*>* codecList, const Parameters& parameters,
		std::vector<ArchiveEntry>* entryList, const std::string& outDir)
	{
		UnpackedBlock block;
		int error = read_block_header(inFile, &block, codecList);
		if (error)
			return error;
		if (block.type != FILE_TREE_BLOCK_ID)
			return ERROR_BAD_FILE;
		block.data = new (std::nothrow) uint8_t[block.codecSizes.back()];
		if (!block.data)
			return ERROR_OUT_OF_MEMORY;
		inFile->read((char*)block.data, block.codecSizes.back());

		ThreadCallback threadCallback;
		threadCallback.init(0, nullptr);
		unpack_block(&block, codecList, parameters, &threadCallback);
		if (threadCallback.get_error())
			return threadCallback.get_error();

		error = parse_file_tree_header(block.data, block.rawSize, entryList, outDir);
		delete[] block.data;
		return error;
	}

	int read_codec_header(std::fstream* inFile, std::vector<Codec*>* codecList, const Parameters& parameters)
	{
		uint16_t storedChecksum = read_uint16le(inFile);
		uint16_t headerSize = read_uint16le(inFile);

		uint8_t* headerData = new uint8_t[headerSize + 2];
		write_uint16le(headerData, headerSize);
		inFile->read((char*)headerData + 2, headerSize);
		uint8_t* headerIt = headerData + 2;

		uint16_t computedChecksum = CRC::Calculate(headerData, headerSize + 2, CRC::CRC_16_X25());
		if (computedChecksum != storedChecksum) {
			delete[] headerData;
			return ERROR_BAD_CHECKSUM;
		}

		while (true) {
			int nameLength = *headerIt++;
			if (nameLength == 0)
				break;

			std::string codecName;
			codecName.resize(nameLength);
			memcpy(codecName.data(), headerIt, nameLength);
			headerIt += nameLength;

			Codec* codec = find_codec(codecName);
			if (codec == nullptr) {
				delete[] headerData;
				return ERROR_UNKNOWN_CODEC;
			}
			codecList->push_back(codec->clone());

			int codecDataLength = *headerIt++;
			int error = codecList->back()->decode_init(headerIt, codecDataLength, &parameters);
			headerIt += codecDataLength;
			if (error) {
				delete[] headerData;
				return error;
			}
		}
		delete[] headerData;
		return NO_ERROR;
	}

	std::filesystem::perms convert_to_std_perms(uint16_t perms) {
		return (perms & 0x1 ? std::filesystem::perms::owner_read : std::filesystem::perms::none) |
			(perms & 0x2 ? std::filesystem::perms::owner_write : std::filesystem::perms::none) |
			(perms & 0x4 ? std::filesystem::perms::owner_exec : std::filesystem::perms::none) |
			(perms & 0x8 ? std::filesystem::perms::group_read : std::filesystem::perms::none) |
			(perms & 0x10 ? std::filesystem::perms::group_write : std::filesystem::perms::none) |
			(perms & 0x20 ? std::filesystem::perms::group_exec : std::filesystem::perms::none) |
			(perms & 0x40 ? std::filesystem::perms::others_read : std::filesystem::perms::none) |
			(perms & 0x80 ? std::filesystem::perms::others_write : std::filesystem::perms::none) |
			(perms & 0x100 ? std::filesystem::perms::others_exec : std::filesystem::perms::none);
	}

	std::filesystem::file_time_type convert_to_filesystem_time(time_t time) {
#if CPP_VER >= 202002L
		auto systemClock = std::chrono::system_clock::from_time_t(time);
		auto fileClock = std::chrono::clock_cast<std::chrono::file_clock>(systemClock);
		return fileClock;
#else	
		//No portable way pre C++20
		return std::filesystem::file_time_type::clock::now();
#endif
	}

	int generate_directory_structure(const std::vector<ArchiveEntry>& entryList) {
		//Directory creation
		std::error_code e;
		for (auto it = entryList.begin(); it != entryList.end(); it++) {
			if (it->type != 'd')
				continue;
			std::filesystem::create_directories(it->absolutePath, e);
			if (e)
				return ERROR_OUTPUT_FILE_OPEN_FAIL;
		}
		for (auto it = entryList.begin(); it != entryList.end(); it++) {
			if (it->type != 'f')
				continue;
			std::fstream o(it->absolutePath, std::fstream::out | std::fstream::binary);
			if (!o.is_open())
				return ERROR_OUTPUT_FILE_OPEN_FAIL;
		}
		return NO_ERROR;
	}

	void apply_attributes(const std::vector<ArchiveEntry>& entryList) {
		std::error_code e;
		for (auto it = entryList.begin(); it != entryList.end(); it++) {
			if (it->type == 'd' || it->type == 'f') {
				std::filesystem::permissions(it->absolutePath, convert_to_std_perms(it->permissions), e);
				std::filesystem::last_write_time(it->absolutePath, convert_to_filesystem_time(it->modifyTime));
			}
		}
	}

	//Remove any file/directory generated in case of abort
	void clean_directory_structure(const std::vector<ArchiveEntry>& entryList) {
		std::error_code e;
		for (auto it = entryList.begin(); it != entryList.end(); it++) {
			if (it->type == 'f')
				std::filesystem::remove(it->absolutePath, e);
			else if (it->type == 'd')
				std::filesystem::remove_all(it->absolutePath, e);
		}
	}

	//Undeduplicates any chunk whose reference is inside the same block, 
	// and places not deduplicated data in its real position. This means some chunks remain not decoded.
	void partial_undeduplication(UnpackedBlock* dataBlock, ThreadCallback* progress) {

		if (dataBlock->dedupChunks.size() == 0)
			return;

		uint8_t* tmp = new (std::nothrow) uint8_t[dataBlock->rawSize];
		if (!tmp) {
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return;
		}
		size_t dataPos = 0;
		size_t tmpPos = 0;

		for (int i = 0; i < dataBlock->dedupChunks.size(); i++) {
			memcpy(tmp + tmpPos, dataBlock->data + dataPos, dataBlock->dedupChunks[i].copyPos - tmpPos);
			dataPos += dataBlock->dedupChunks[i].copyPos - tmpPos;
			tmpPos += dataBlock->dedupChunks[i].copyPos - tmpPos;
			if (dataBlock->dedupChunks[i].originalPos >= dataBlock->globalPos &&
				dataBlock->dedupChunks[i].originalPos < dataBlock->globalPos + tmpPos)
			{
				memcpy(tmp + tmpPos, tmp + dataBlock->dedupChunks[i].originalPos - dataBlock->globalPos, dataBlock->dedupChunks[i].length);
				dataBlock->dedupChunks[i].copied = true;
				progress->add_base_progress(dataBlock->dedupChunks[i].length);
			}
			tmpPos += dataBlock->dedupChunks[i].length;
		}

		memcpy(tmp + tmpPos, dataBlock->data + dataPos, dataBlock->codecSizes.front() - dataPos);
		delete[] dataBlock->data;
		dataBlock->data = tmp;
	}

	void extract_data_thread(std::fstream* inFile, std::vector<Codec*>* codecList, const Parameters& parameters,
		std::vector<ArchiveEntry>* entryList, std::vector<UnpackedBlock*>* dataBlocks, 
		std::mutex* readMtx, ThreadCallback* progress)
	{
		while (true) {

			readMtx->lock();

			//End block found by another thread
			if (dataBlocks->size() > 0 && dataBlocks->back()->type == END_BLOCK_ID) {
				readMtx->unlock();
				return;
			}

			UnpackedBlock* dataBlock = new UnpackedBlock();
			dataBlocks->push_back(dataBlock);
			int error = read_block_header(inFile, dataBlock, codecList);
			if (error) {
				readMtx->unlock();
				progress->set_error(error);
				return;
			}
			if (dataBlock->type == END_BLOCK_ID) {
				readMtx->unlock();
				return;
			}
			if (dataBlock->type != DATA_BLOCK_ID) {
				readMtx->unlock();
				progress->set_error(ERROR_BAD_FILE);
				return;
			}

			dataBlock->data = new (std::nothrow) uint8_t[dataBlock->codecSizes.back()];
			if (!dataBlock->data) {
				readMtx->unlock();
				progress->set_error(ERROR_OUT_OF_MEMORY);
				return;
			}
			inFile->read((char*)dataBlock->data, dataBlock->codecSizes.back());

			readMtx->unlock();

			uint32_t computedDataChecksum = CRC::Calculate(dataBlock->data, dataBlock->codecSizes.back(), CRC::CRC_32());
			if (computedDataChecksum != dataBlock->dataChecksum) {
				delete[] dataBlock->data;
				progress->set_error(ERROR_BAD_CHECKSUM);
				return;
			}

			unpack_block(dataBlock, codecList, parameters, progress);
			//Error during block decoding or operation was canceled
			if (progress->abort()) 
				return;

			partial_undeduplication(dataBlock, progress);
			if (progress->abort())
				return;

			size_t fileIndex, fileOffset;
			find_file_and_offset_from_global_pos(entryList, dataBlock->globalPos, &fileIndex, &fileOffset);
			std::fstream outFile;
			size_t blockPos = 0;

			while (blockPos < dataBlock->rawSize) {

				if (!outFile.is_open()) {
					if (entryList->at(fileIndex).type != 'f' || entryList->at(fileIndex).size == 0) {
						fileIndex++;
						continue;
					}
					outFile.open(entryList->at(fileIndex).absolutePath, std::fstream::binary | std::fstream::in | std::fstream::out);
					if (!outFile.is_open()) {
						progress->set_error(ERROR_OUTPUT_FILE_OPEN_FAIL);
						delete[] dataBlock->data;
						return;
					}
					if (fileOffset != 0)
						outFile.seekp(fileOffset);
				}

				size_t bytesToWrite = std::min(entryList->at(fileIndex).size - outFile.tellp(), dataBlock->rawSize - blockPos);
				outFile.write((char*)dataBlock->data + blockPos, bytesToWrite);
				blockPos += bytesToWrite;

				if (entryList->at(fileIndex).size == outFile.tellp()) {
					outFile.close();
					fileIndex++;
					fileOffset = 0;
				}
			}

			if (outFile.is_open()) 
				outFile.close();
			delete[] dataBlock->data;
		}
	}

	void undeduplicate_thread(std::vector<ArchiveEntry>* entryList, std::vector<UnpackedBlock*>* dataBlocks, 
		size_t* blockIt, size_t* chunkIt, std::mutex* mtx, ThreadCallback* progress) {

		const size_t COPY_LENGTH = 65536;
		uint8_t* data = new (std::nothrow) uint8_t[COPY_LENGTH];
		if (!data) {
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return;
		}

		size_t lastOpenedCopyFile = -1;
		std::fstream copyFile;
		size_t lastOpenedOriginalFile = -1;
		std::fstream originalFile;

		while (true) {

			mtx->lock();

			if (*blockIt >= dataBlocks->size()) {
				mtx->unlock();
				delete[] data;
				return;
			}

			if (*chunkIt == dataBlocks->at(*blockIt)->dedupChunks.size()) {
				(*blockIt)++;
				*chunkIt = 0;
				mtx->unlock();
				continue;
			}

			size_t thisBlock = *blockIt;
			size_t thisChunk = *chunkIt;
			(*chunkIt)++;

			mtx->unlock();

			if (dataBlocks->at(thisBlock)->dedupChunks[thisChunk].copied)
				continue;

			size_t copyFileIndex, copyFileOffset;
			find_file_and_offset_from_global_pos(entryList,
				dataBlocks->at(thisBlock)->dedupChunks[thisChunk].copyPos + dataBlocks->at(thisBlock)->globalPos, &copyFileIndex, &copyFileOffset);
			size_t originalFileIndex, originalFileOffset;
			find_file_and_offset_from_global_pos(entryList,
				dataBlocks->at(thisBlock)->dedupChunks[thisChunk].originalPos, &originalFileIndex, &originalFileOffset);

			if (originalFileIndex >= entryList->size() || copyFileIndex >= entryList->size() ||
				originalFileOffset >= entryList->at(originalFileIndex).size ||
				copyFileOffset >= entryList->at(copyFileIndex).size)
			{
				delete[] data;
				progress->set_error(ERROR_BAD_FILE);
				return;
			}

			if (lastOpenedCopyFile != copyFileIndex) {
				copyFile.close();
				copyFile.open(entryList->at(copyFileIndex).absolutePath, std::fstream::binary | std::fstream::in | std::fstream::out);
				lastOpenedCopyFile = copyFileIndex;
			}

			size_t remaining = dataBlocks->at(thisBlock)->dedupChunks[thisChunk].length;
			if (originalFileIndex == copyFileIndex) {
				size_t pos = 0;
				while (remaining) {
					size_t bytes = std::min(remaining, COPY_LENGTH);
					copyFile.seekg(originalFileOffset + pos);
					copyFile.read((char*)data, bytes);
					copyFile.seekp(copyFileOffset + pos);
					copyFile.write((char*)data, bytes);
					remaining -= bytes;
					pos += bytes;
				}
			}
			else {

				if (lastOpenedOriginalFile != originalFileIndex) {
					originalFile.close();
					originalFile.open(entryList->at(originalFileIndex).absolutePath, std::fstream::binary | std::fstream::in | std::fstream::out);
					lastOpenedOriginalFile = originalFileIndex;
				}

				originalFile.seekg(originalFileOffset);
				copyFile.seekp(copyFileOffset);
				while (remaining) {
					size_t bytes = std::min(remaining, COPY_LENGTH);
					originalFile.read((char*)data, bytes);
					copyFile.write((char*)data, bytes);
					remaining -= bytes;
				}
			}

			progress->add_base_progress(dataBlocks->at(thisBlock)->dedupChunks[thisChunk].length);
		}

		delete[] data;
	}

	void extract_data_blocks(std::fstream* inFile, std::vector<Codec*>* codecList, const Parameters& parameters,
		std::vector<ArchiveEntry>* entryList, std::vector<UnpackedBlock*>* dataBlocks, ArchiveCallbackInternal* callbacksInternal)
	{
		std::mutex readMtx;
		std::thread* cpu = new std::thread[parameters.threads];
		ThreadCallback* threadCallbacks = new ThreadCallback[parameters.threads];

		for (int i = 0; i < parameters.threads; i++) {
			threadCallbacks[i].init(i, callbacksInternal);
			cpu[i] = std::thread(extract_data_thread, inFile, codecList, parameters, entryList, dataBlocks, &readMtx, &threadCallbacks[i]);
		}
		for (int i = 0; i < parameters.threads; i++)
			cpu[i].join();

		//Undo deduplication
		if (!callbacksInternal->abort()) {
			size_t blockIt = 0;
			size_t chunkIt = 0;
			for (int i = 0; i < parameters.threads; i++)
				cpu[i] = std::thread(undeduplicate_thread, entryList, dataBlocks, &blockIt, &chunkIt, &readMtx, &threadCallbacks[i]);
			for (int i = 0; i < parameters.threads; i++)
				cpu[i].join();
		}

		delete[] cpu;
		delete[] threadCallbacks;
	}

	int extract_archive(const std::string& file, const std::string& outDir, const Parameters& parameters, ArchiveCallback* callbacks)
	{
		ArchiveCallbackInternal callbacksInternal(callbacks);

		std::fstream inFile(file, std::fstream::binary | std::fstream::in);
		if (!inFile.is_open())
			return ERROR_INPUT_FILE_OPEN_FAIL;
		uint8_t storedSignature[sizeof(FILE_SIGNATURE)];
		inFile.read((char*)storedSignature, sizeof(FILE_SIGNATURE));
		if (!std::equal(storedSignature, storedSignature + sizeof(FILE_SIGNATURE), FILE_SIGNATURE))
			return ERROR_BAD_FILE;

		std::vector<Codec*> codecList;
		int error = read_codec_header(&inFile, &codecList, parameters);
		if (error) {
			free_codec_list(&codecList);
			return error;
		}

		//Headers
		std::vector<ArchiveEntry> entryList;
		error = read_file_tree_header(&inFile, &codecList, parameters, &entryList, outDir);
		if (error) {
			free_codec_list(&codecList);
			return error;
		}

		error = generate_directory_structure(entryList);
		if (error) {
			free_codec_list(&codecList);
			clean_directory_structure(entryList);
			return error;
		}

		//Amount of data to decompress, for the progress bar
		size_t totalContainedSize = 0;
		for (auto it = entryList.begin(); it != entryList.end(); it++) {
			if (it->type != 'f')
				continue;
			totalContainedSize += it->size;
		}
		callbacksInternal.init(parameters.threads, totalContainedSize);

		std::vector<UnpackedBlock*> dataBlocks;
		extract_data_blocks(&inFile, &codecList, parameters, &entryList, &dataBlocks, &callbacksInternal);

		for (size_t i = 0; i < dataBlocks.size(); i++)
			delete dataBlocks[i];

		if (callbacksInternal.abort())
			clean_directory_structure(entryList);
		else
			apply_attributes(entryList);
		free_codec_list(&codecList);
		return callbacksInternal.get_error();
	}

	////////////////////////////////////////////////////////
	//                                                    //
	//                     UTILITIES                      //
	//                                                    //
	////////////////////////////////////////////////////////

	size_t estimate_memory(const Parameters& parameters)
	{
		size_t outBufferSize = parameters.maxBlockSize;
		size_t maxCodecMemoryUsage = 0;

		for (auto codecName : parameters.codecNameList) {
			Codec* codec = find_codec(codecName);
			if (codec == nullptr)
				return ERROR_UNKNOWN_CODEC;

			maxCodecMemoryUsage = std::max(maxCodecMemoryUsage, codec->estimate_memory(outBufferSize, &parameters));
			outBufferSize = codec->encode_bound(outBufferSize);
		}

		size_t deduplicatorMemoryUsage = (size_t)64 * sizeof(DeduperDictEntry) << parameters.deduplicationMemoryLog;
		return (parameters.maxBlockSize + outBufferSize + maxCodecMemoryUsage) * parameters.threads + deduplicatorMemoryUsage;
	}
	int is_archive_encrypted(const std::string& file) {

		std::fstream inFile(file, std::fstream::binary | std::fstream::in);
		if (!inFile.is_open())
			return ERROR_INPUT_FILE_OPEN_FAIL;

		uint8_t storedSignature[sizeof(FILE_SIGNATURE)];
		inFile.read((char*)storedSignature, sizeof(FILE_SIGNATURE));
		if (!std::equal(storedSignature, storedSignature + sizeof(FILE_SIGNATURE), FILE_SIGNATURE))
			return ERROR_BAD_FILE;

		uint16_t storedChecksum = read_uint16le(&inFile);
		uint16_t headerSize = read_uint16le(&inFile);

		uint8_t* headerData = new uint8_t[headerSize + 2];
		write_uint16le(headerData, headerSize);
		inFile.read((char*)headerData + 2, headerSize);
		uint8_t* headerIt = headerData + 2;

		uint16_t computedChecksum = CRC::Calculate(headerData, headerSize + 2, CRC::CRC_16_X25());
		if (computedChecksum != storedChecksum) {
			delete[] headerData;
			return ERROR_BAD_CHECKSUM;
		}

		while (true) {
			int nameLength = *headerIt++;
			if (nameLength == 0)
				break;

			std::string codecName;
			codecName.resize(nameLength);
			memcpy(codecName.data(), headerIt, nameLength);
			headerIt += nameLength;

			Codec* codec = find_codec(codecName);
			if (codec == nullptr) {
				delete[] headerData;
				return ERROR_UNKNOWN_CODEC;
			}
			if (codec->get_codec_type() == CODEC_ENCRYPTOR) {
				delete[] headerData;
				return true;
			}

			int codecDataLength = *headerIt++;
			headerIt += codecDataLength;
		}
		delete[] headerData;
		return false;
	}
}

#endif  //ARCHIVER_IMPLEMENTATION

#endif  //__ARCHIVER__
