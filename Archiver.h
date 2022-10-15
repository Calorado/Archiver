/*
 * Simple Archiver v1.1.0
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

	const int ERROR_BAD_FILE = -1;
	const int ERROR_UNKNOWN_COMPRESSION = -2;
	const int ERROR_UNKNOWN_ENCRYPTION = -3;
	const int ERROR_OUT_OF_MEMORY = -4;
	const int ERROR_FILE_OPEN_FAILED = -5;
	const int ERROR_BAD_CRC = -6;
	const int ERROR_OTHER = -7;

	//Base class that allows to track progress of creation and extraction of an archive.
	//You will have to create a child class which implements the functions.
	// - progress(progressPercent): progress in percentage of completion
	// - abort(): if this returns true, the operation will stop with a return code of 0 and will remove any created files
	class ArchiveCallback {
	public:
		ArchiveCallback() {}
		virtual void progress(float progressPercent) {
			return;
		}
		virtual bool abort() {
			return false;
		}
	};

	struct CompressionMethodData {
		std::string name;
		int minLevel;
		int maxLevel;
	};

	//Creates and extracts archives. Both will return 0 on success or user abort or an error code on failure
	int create_archive(const std::vector<std::string>& inputFiles, const std::string& archivePath, 
		const std::string& compressionName, const int compressionLevel, const std::string& encryptionName, 
		const std::string& password, const size_t blockSize, const bool useSolidBlock, const int threads, 
		ArchiveCallback* callbacks = nullptr);
	int extract_archive(const std::string& file, const std::string& outDir, const std::string& password, 
		const int threads, ArchiveCallback* callbacks = nullptr);

	//Returs some data about the available compression algorithms
	std::vector<CompressionMethodData> get_compression_methods();
	//Returs an estimation of the amount of memory the encoder will use 
	size_t estimate_memory(const std::string& compressionName, const int compressionLevel, 
		const size_t blockSize, const int threads);
	//Returns whether a given archive is encrypted or an error code on failure
	int is_archive_encrypted(const std::string& file);
}

#ifdef ARCHIVER_IMPLEMENTATION

#include <thread>
#include <mutex>
#include <cstdint>
#include <time.h>

#define SKANDA_IMPLEMENTATION
#include "Skanda.h"
#define STRIDER_IMPLEMENTATION
#include "Strider.h"
#define SPECTRUM_IMPLEMENTATION
#include "Spectrum.h"
#include "library/picosha2.h"
#include "library/crc.h"

//Probably not the correct way to do it but bleh
#if UINTPTR_MAX > UINT32_MAX
#define IS_64BIT 1
#else
#define IS_64BIT 0
#endif

namespace archiver {

	const uint8_t FILE_MAGIC_NUMBER[8] = { 'S', 'f', 'i', 'l', 'e', 0x10, 0x09, 0x02 };

	uint32_t rand32(uint32_t seed) {
		seed ^= seed >> 14;
		seed *= 0x27d4eb2d;
		seed ^= seed >> 15;
		return seed;
	}

	//Returns the log2 of the value as an int, or 0 if the input is 0
	int int_log2(const size_t value) {
		if (value == 0)
			return 0;
		return int(std::log2(value));
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

	//Keeps track of the progress of all threads, internal errors, and any callbacks from the user
	class ArchiveCallbackInternal {
		ArchiveCallback* userCallbacks = nullptr;
		std::mutex threadMtx;
		size_t totalSize = 0;
		std::vector<size_t> threadProgress;
		int internalError = 0;  //For errors like out of memory or bad crc
		bool doAbort = false;  //When we get confirmation for abort from user do not ask again

	public:
		ArchiveCallbackInternal(ArchiveCallback* c) {
			userCallbacks = c;
		}
		void init(size_t threads, size_t size) {
			threadProgress = std::vector<size_t>(threads, 0);
			totalSize = size;
		}
		int get_error() {
			return internalError;
		}
		//The functions below will be called by multiple threads
		void add_progress(size_t bytes, size_t threadID) {
			threadMtx.lock();
			threadProgress[threadID] = bytes;
			if (userCallbacks) {
				size_t progress = 0;
				for (size_t i = 0; i < threadProgress.size(); i++)
					progress += threadProgress[i];
				userCallbacks->progress((float)progress / totalSize * 100);
			}
			threadMtx.unlock();
		}
		void set_error(int code) {
			threadMtx.lock();
			internalError = code;
			threadMtx.unlock();
		}
		bool abort() {
			threadMtx.lock();
			if (userCallbacks && !doAbort)
				doAbort = userCallbacks->abort();
			bool result = internalError != 0 || doAbort;
			threadMtx.unlock();
			return result;
		}
	};

	//Keeps track of progress or errors within an individual thread
	class ThreadCallback {

		ArchiveCallbackInternal* archiveCallbacks;
		int internalError = 0;
		size_t threadID = 0;
		size_t totalProgress = 0;
		size_t blockRawSize = 0;
		size_t blockProgress = 0;

	public:
		ThreadCallback() { }
		void init(size_t id, ArchiveCallbackInternal* c) {
			threadID = id;
			archiveCallbacks = c;
		}
		void end_block(size_t blockRawSize) {
			totalProgress += blockRawSize;
			blockProgress = 0;
		}
		void progress(size_t bytes) {
			blockProgress = bytes;
			if (archiveCallbacks)
				archiveCallbacks->add_progress(totalProgress + blockProgress, threadID);
		}
		void set_error(int error) {
			if (archiveCallbacks)
				archiveCallbacks->set_error(error);
			internalError = error;
		}
		int get_error() {
			return internalError;
		}
		int abort() {
			if (archiveCallbacks)
				return archiveCallbacks->abort();
			return false;
		}
	};

	class SkandaProgressCallback : public skanda::ProgressCallback {
		ThreadCallback* backendCallback;
	public:
		SkandaProgressCallback(ThreadCallback* callbacks) {
			backendCallback = callbacks;
		}
		void progress(size_t bytes) {
			if (backendCallback)
				backendCallback->progress(bytes);
		}
		int abort() {
			if (backendCallback)
				return backendCallback->abort();
			return false;
		}
	};

	size_t skanda_compress(uint8_t*& input, size_t size, uint8_t*& output, int level, ThreadCallback* progress) 
	{
		SkandaProgressCallback progressCallback(progress);
		try {
			output = new uint8_t[skanda::compress_bound(size)];
		}
		catch (std::bad_alloc& e) {
			delete[] input;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		size_t compressedSize = skanda::compress(input, size, output, level, 999, &progressCallback);
		delete[] input;
		if (compressedSize == -1) {
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		return compressedSize;
	}
	void skanda_decompress(uint8_t*& compressed, size_t compressedSize, uint8_t*& decompressed,
		size_t uncompressedSize, ThreadCallback* progress)
	{
		SkandaProgressCallback progressCallback(progress);
		try {
			decompressed = new uint8_t[uncompressedSize];
		}
		catch (std::bad_alloc& e) {
			delete[] compressed;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return;
		}
		int error = skanda::decompress(compressed, compressedSize, decompressed, uncompressedSize, &progressCallback);
		delete[] compressed;
		if (error)
			progress->set_error(ERROR_BAD_FILE);
	}
	size_t skanda_estimate_memory(size_t size, int level) {
		return skanda::estimate_memory(size, level, 999) + skanda::compress_bound(size);
	}

	class StriderProgressCallback : public strider::ProgressCallback {
		ThreadCallback* backendCallback;
	public:
		StriderProgressCallback(ThreadCallback* backend) {
			backendCallback = backend;
		}
		void progress(size_t bytes) {
			if (backendCallback)
				backendCallback->progress(bytes);
		}
		int abort() {
			if (backendCallback)
				return backendCallback->abort();
			return false;
		}
	};

	size_t strider_compress(uint8_t*& input, size_t size, uint8_t*& output, int level, ThreadCallback* progress)
	{
		StriderProgressCallback progressCallback(progress);
		try {
			output = new uint8_t[strider::compress_bound(size)];
		}
		catch (std::bad_alloc& e) {
			delete[] input;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		size_t compressedSize = strider::compress(input, size, output, level, 999, &progressCallback);
		delete[] input;
		if (compressedSize == -1) {
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		return compressedSize;
	}
	void strider_decompress(uint8_t*& compressed, size_t compressedSize, uint8_t*& decompressed,
		size_t uncompressedSize, ThreadCallback* progress)
	{
		StriderProgressCallback progressCallback(progress);
		try {
			decompressed = new uint8_t[uncompressedSize];
		}
		catch (std::bad_alloc& e) {
			delete[] compressed;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return;
		}
		int error = strider::decompress(compressed, compressedSize, decompressed, uncompressedSize, &progressCallback);
		delete[] compressed;
		if (error)
			progress->set_error(ERROR_BAD_FILE);
	}
	size_t strider_estimate_memory(size_t size, int level) {
		return strider::estimate_memory(size, level, 999) + strider::compress_bound(size);
	}

	class SpectrumStriderProgressCallback : public strider::ProgressCallback {
		ThreadCallback* backendCallback;
		//Preprocessing will usually increase the block size, and so
		// progress reported by the compression will be a bit off.
		size_t preprocessedSize = 0;
		size_t originalSize = 0;
	public:
		SpectrumStriderProgressCallback(ThreadCallback* backend, size_t preSize, size_t origSize) {
			backendCallback = backend;
			preprocessedSize = preSize;
			originalSize = origSize;
		}
		void progress(size_t bytes) {
			size_t relative = std::min(originalSize, (size_t)((float)bytes / preprocessedSize * originalSize));
			if (backendCallback)
				backendCallback->progress(relative);
		}
		int abort() {
			if (backendCallback)
				return backendCallback->abort();
			return false;
		}
	};

	size_t spectrum_strider_backend(const uint8_t* data, const size_t size) {
		uint8_t* out;
		try {
			out = new uint8_t[strider::compress_bound(size)];
		}
		catch (std::bad_alloc& e) {
			return 0;
		}
		size_t compressed = strider::compress(data, size, out, 0);
		delete[] out;
		return compressed;
	}

	size_t spectrum_strider_compress(uint8_t*& input, size_t size, uint8_t*& output, int level, ThreadCallback* progress)
	{
		uint8_t* preprocessed;
		try {
			preprocessed = new uint8_t[spectrum::bound(size)];
		}
		catch (std::bad_alloc& e) {
			delete[] input;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		size_t preprocessedSize = spectrum::encode(input, size, preprocessed, level < 6 ? nullptr : &spectrum_strider_backend);
		delete[] input;
		if (preprocessedSize == -1) {
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}

		try {
			output = new uint8_t[strider::compress_bound(preprocessedSize)];
		}
		catch (std::bad_alloc& e) {
			delete[] preprocessed;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		//We have to store preprocessed size
		uint8_t* compressedBegin = output;
		write_LEB128_ptr(compressedBegin, preprocessedSize);
		SpectrumStriderProgressCallback progressCallback(progress, preprocessedSize, size);
		size_t compressedSize = strider::compress(preprocessed, preprocessedSize, compressedBegin, level, 999, &progressCallback);
		delete[] preprocessed;
		if (compressedSize == -1) {
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		return compressedSize + (compressedBegin - output);
	}
	void spectrum_strider_decompress(uint8_t*& compressed, size_t compressedSize, uint8_t*& decompressed,
		size_t uncompressedSize, ThreadCallback* progress)
	{
		//First we read preprocessed size
		size_t preprocessedSize;
		const uint8_t* compressedBegin = compressed;
		read_LEB128_ptr(compressedBegin, compressed + compressedSize, &preprocessedSize);

		SpectrumStriderProgressCallback progressCallback(progress, preprocessedSize, uncompressedSize);
		uint8_t* preprocessed;
		try {
			preprocessed = new uint8_t[preprocessedSize];
		}
		catch (std::bad_alloc& e) {
			delete[] compressed;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return;
		}
		int error = strider::decompress(compressedBegin, compressedSize, preprocessed, preprocessedSize, &progressCallback);
		delete[] compressed;
		if (error) {
			progress->set_error(ERROR_BAD_FILE);
			return;
		}
		try {
			decompressed = new uint8_t[uncompressedSize];
		}
		catch (std::bad_alloc& e) {
			delete[] preprocessed;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return;
		}
		error = spectrum::decode(preprocessed, preprocessedSize, decompressed, uncompressedSize);
		delete[] preprocessed;
		if (error)
			progress->set_error(ERROR_BAD_FILE);
	}
	size_t spectrum_strider_estimate_memory(size_t size, int level) {
		return strider::estimate_memory(size, level, 999) + strider::compress_bound(spectrum::bound(size));
	}

	size_t none_compress(uint8_t*& input, size_t size, uint8_t*& output, int level, ThreadCallback* progress) 
	{
		output = input;
		if (progress)
			progress->progress(size);
		return size;
	}
	void none_decompress(uint8_t*& compressed, size_t compressedSize, uint8_t*& decompressed, 
		size_t uncompressedSize, ThreadCallback* progress)
	{
		decompressed = compressed;
		if (progress)
			progress->progress(uncompressedSize);
		return;
	}
	size_t none_estimate_memory(size_t size, int level) {
		return size;
	}

	struct CompressionMethod {
		CompressionMethodData data;
		//Both compress and decompress take a pointer to a memory location with the input data, and must allocate
		// the pointer to the output data. In all cases the input data must be freed.
		size_t(*compress)(uint8_t*& input, size_t size, uint8_t*& output, int level, ThreadCallback* progress);
		void(*decompress)(uint8_t*& compressed, size_t compressedSize, uint8_t*& decompressed, size_t uncompressedSize, ThreadCallback* progress);
		size_t(*estimate_memory)(size_t size, int level);

		//To find the algorithm
		bool operator==(const std::string& other) const {
			return data.name == other;
		}
	};

	const std::vector<CompressionMethod> compressionMethods = {
		{ { std::string("none"), 0, 0 }, &none_compress, &none_decompress, &none_estimate_memory },
		{ { std::string("skanda"), 0, 9 }, &skanda_compress, &skanda_decompress, &skanda_estimate_memory },
		{ { std::string("strider"), 0, 9 }, &strider_compress, &strider_decompress, &strider_estimate_memory },
		{ { std::string("spectrum/strider"), 0, 9 }, &spectrum_strider_compress, &spectrum_strider_decompress, &spectrum_strider_estimate_memory },
	};

	std::vector<uint8_t> hash_none(std::string password, const std::vector<uint8_t>& salt) {
		return std::vector<uint8_t>();
	}
	void encrypt_none(uint8_t* data, size_t size, std::vector<uint8_t> hash) {
		return;
	}

	std::vector<uint8_t> hash_sha256(std::string password, const std::vector<uint8_t>& salt) {
		//Add salt to the password
		for (uint8_t byte : salt)
			password.push_back(byte);
		//Perform first hash on the password
		std::vector<uint8_t> hashA(picosha2::k_digest_size);
		picosha2::hash256<std::string>(password, hashA);

		//Key stretching
		std::vector<uint8_t> hashB(picosha2::k_digest_size);
		for (size_t i = 0; i < 65536; i++) {
			picosha2::hash256<std::vector<uint8_t>>(hashA, hashB);
			hashA = hashB;
		}
		return hashA;
	}
	//Both encryptor and decryptor perform the same operations
	void encrypt_sha256(uint8_t* data, size_t size, std::vector<uint8_t> hash) {

		for (size_t i = 0; i < size; i++) {
			uint32_t baseHashIndex = i % 32;
			data[i] ^= hash[baseHashIndex];

			uint32_t mixHashIndex = rand32(i);
			hash[baseHashIndex] ^= hash[mixHashIndex % 32];
		}
	}

	struct EncryptionMethod {
		std::string name;
		size_t saltLength;
		std::vector<uint8_t>(*hash)(std::string password, const std::vector<uint8_t>& salt);
		void(*encrypt)(uint8_t* data, size_t size, std::vector<uint8_t> hash);
		void(*decrypt)(uint8_t* data, size_t size, std::vector<uint8_t> hash);

		bool operator==(const std::string& other) const {
			return name == other;
		}
	};

	const std::vector<EncryptionMethod> encryptionMethods = {
		{ "none", 0, &hash_none, &encrypt_none, &encrypt_none },
		{ "sha256", 4, &hash_sha256, &encrypt_sha256, &encrypt_sha256 }
	};

	std::vector<uint8_t> generate_salt(size_t saltLength) {
		std::vector<uint8_t> result(saltLength, 0);
		uint32_t seedA = rand32(std::time(nullptr));
		uint32_t seedB = reinterpret_cast<size_t>(result.data());

		if (saltLength != 0) {
			for (size_t i = 0; i < 4; i++) {
				result[(i + 0) % saltLength] ^= seedA >> i * 8;
				result[(i + 4) % saltLength] ^= seedB >> i * 8;
			}
		}
		return result;
	}

	struct FileInfo {
		std::string absolutePath;
		std::string relativePath;
		std::string filename;
		size_t size;

		//For file sort. Placing similar files together can improve compression
		bool operator<(FileInfo& other) {
			
			std::string extensionA = std::filesystem::path(absolutePath).extension().string();
			std::string extensionB = std::filesystem::path(other.absolutePath).extension().string();

			if (extensionA != extensionB)
				return extensionA < extensionB;
			return filename < other.filename;  //Can place duplicate files together
		}
	};

	struct CompressedBlock {
		uint8_t* data = nullptr;
		size_t originalSize = 0;
		size_t compressedSize = 0;
		uint32_t checksum = 0;
	};

	void compress_block(uint8_t* input, CompressedBlock* compressedBlock, const CompressionMethod& compressionMethod, 
		int compressionLevel, const EncryptionMethod& encryptionMethod, const std::vector<uint8_t>& hash, ThreadCallback* callbacks)
	{
		compressedBlock->compressedSize = compressionMethod.compress(input, compressedBlock->originalSize, compressedBlock->data, compressionLevel, callbacks);
		if (callbacks->abort()) 
			return;
		callbacks->end_block(compressedBlock->originalSize);
		compressedBlock->checksum = CRC::Calculate(compressedBlock->data, compressedBlock->compressedSize, CRC::CRC_32());
		encryptionMethod.encrypt(compressedBlock->data, compressedBlock->compressedSize, hash);
	}

	int read_directory_and_create_header(std::vector<std::string> inputFiles, std::fstream* outFile, const CompressionMethod& compressionMethod, int compressionLevel,
		const EncryptionMethod& encryptionMethod, const std::vector<uint8_t>& hash, std::vector<FileInfo>* filesToCompress, bool useSolidBlock) {

		//Search for all archives
		std::vector<std::string> directories;
		uint8_t* headerStream;
		size_t headerStreamSize;
		try {
			for (size_t i = 0; i < inputFiles.size(); i++) {

				if (std::filesystem::is_directory(inputFiles[i])) {
                    
					directories.push_back(std::filesystem::path(inputFiles[i]).filename().string());
                    //We need to cut the path of the contained files relative to the base directory. 
                    size_t relativePathStart = std::filesystem::path(inputFiles[i]).parent_path().generic_string().size();

					for (auto entry : std::filesystem::recursive_directory_iterator(inputFiles[i])) {
                        
                        std::string absPath = entry.path().generic_string();
                        std::string relPath = absPath.substr(relativePathStart);
						while (relPath[0] == '/')
							relPath.erase(0, 1);

						if (entry.is_directory()) {
							directories.push_back(relPath);
						}
						else {
							std::string filename = entry.path().filename().string();
							size_t size = std::filesystem::file_size(absPath);
							filesToCompress->push_back({ absPath, relPath, filename, size });
						}
					}
				}
				else {
                    std::string filename = std::filesystem::path(inputFiles[i]).filename().string();
					size_t size = std::filesystem::file_size(inputFiles[i]);
					filesToCompress->push_back({ inputFiles[i], filename, filename, size });
				}
			}

			if (useSolidBlock)
				std::sort(filesToCompress->begin(), filesToCompress->end());

			//Calculate how much space would the header take
			size_t numberElements = directories.size() + filesToCompress->size();
			headerStreamSize = 1 + int_log2(numberElements) / 7;
			for (size_t i = 0; i < directories.size(); i++) 
				headerStreamSize += directories[i].size() + 2;
			for (size_t i = 0; i < filesToCompress->size(); i++) 
				headerStreamSize += filesToCompress->at(i).relativePath.size() + 2 + int_log2(filesToCompress->at(i).size) / 7;

			headerStream = new uint8_t[headerStreamSize];
			uint8_t* headerStreamIt = headerStream;
			write_LEB128_ptr(headerStreamIt, numberElements);

			for (size_t i = 0; i < directories.size(); i++) {
				//Directories are marked by starting with '/'
				*headerStreamIt++ = '/';
				for (size_t c = 0; c < directories[i].size(); c++)
					*headerStreamIt++ = directories[i][c];
				*headerStreamIt++ = '\0';
			}
			for (size_t i = 0; i < filesToCompress->size(); i++) {
				for (size_t c = 0; c < filesToCompress->at(i).relativePath.size(); c++)
					*headerStreamIt++ = filesToCompress->at(i).relativePath[c];
				*headerStreamIt++ = '\0';

				write_LEB128_ptr(headerStreamIt, filesToCompress->at(i).size);
			}
		}
		catch (std::bad_alloc& e) {
			return ERROR_OUT_OF_MEMORY;
		}
		catch (std::filesystem::filesystem_error& e) {
			return ERROR_FILE_OPEN_FAILED;
		}

		//To get any error from compressing the header
		ThreadCallback threadCallback;
		threadCallback.init(0, nullptr);

		uint8_t* compressedHeaderStream;
		size_t compressedHeaderSize = compressionMethod.compress(headerStream, headerStreamSize, compressedHeaderStream, compressionLevel, &threadCallback);
		if (threadCallback.get_error())
			return threadCallback.get_error();
		uint32_t checksum = CRC::Calculate(compressedHeaderStream, compressedHeaderSize, CRC::CRC_32());
		encryptionMethod.encrypt(compressedHeaderStream, compressedHeaderSize, hash);
		write_LEB128_file(outFile, compressedHeaderSize);
		write_LEB128_file(outFile, headerStreamSize);
		outFile->write((char*)&checksum, 4);
		outFile->write((char*)compressedHeaderStream, compressedHeaderSize);
		return 0;
	}

	int create_archive(const std::vector<std::string>& inputFiles, const std::string& archivePath, 
		const std::string& compressionName, const int compressionLevel, const std::string& encryptionName, 
		const std::string& password, const size_t blockSize, const bool useSolidBlock, 
		const int threads, ArchiveCallback* callbacks) 
	{
		ArchiveCallbackInternal callbacksInternal(callbacks);

		//Create the archive
		std::fstream outFile(archivePath, std::fstream::binary | std::fstream::out);
        if (!outFile.is_open())
            return ERROR_FILE_OPEN_FAILED;
		outFile.write((char*)&FILE_MAGIC_NUMBER, 8);

		//Write compression method used
		auto compressionMethod = std::find(compressionMethods.begin(), compressionMethods.end(), compressionName);
        if (compressionMethod == compressionMethods.end())
            return ERROR_UNKNOWN_COMPRESSION;
		outFile.put(compressionMethod->data.name.size());
		outFile.write(compressionMethod->data.name.data(), compressionMethod->data.name.size());

		//Write encryption method used
		auto encryptionMethod = std::find(encryptionMethods.begin(), encryptionMethods.end(), encryptionName);
        if (encryptionMethod == encryptionMethods.end())
            return ERROR_UNKNOWN_ENCRYPTION;
		outFile.put(encryptionMethod->name.size());
		outFile.write(encryptionMethod->name.data(), encryptionMethod->name.size());
		std::vector<uint8_t> salt = generate_salt(encryptionMethod->saltLength);
		outFile.write((char*)salt.data(), salt.size());
		std::vector<uint8_t> hash = encryptionMethod->hash(password, salt);

		//Directories
		std::vector<FileInfo> filesToCompress;
		int error = read_directory_and_create_header(inputFiles, &outFile, *compressionMethod, compressionLevel,
			*encryptionMethod, hash, &filesToCompress, useSolidBlock);
		if (error) {
			outFile.close();
			std::filesystem::remove(archivePath);
			return error;
		}

		size_t totalContainedSize = 0;
		for (auto it = filesToCompress.begin(); it != filesToCompress.end(); it++) 
			totalContainedSize += it->size;
		callbacksInternal.init(threads, totalContainedSize);

		//Compression
		std::fstream inFile;
		size_t readFiles = 0;
		
		std::thread* cpu = new std::thread[threads];
		ThreadCallback* progress = new ThreadCallback[threads]; 
		CompressedBlock* outBlocks = new CompressedBlock[threads];

		//Create threads using a circular buffer
		size_t startedThreads = 0;
		size_t consumedThreads = 0;

		while (readFiles != filesToCompress.size() || consumedThreads != startedThreads) {

			for (; startedThreads < consumedThreads + threads; startedThreads++) {

				if (readFiles == filesToCompress.size() || callbacksInternal.abort())
					break;

				size_t thisBlockSize = 0;
				uint8_t* inputBuffer;
				try {
					inputBuffer = new uint8_t[blockSize];
				}
				catch (std::bad_alloc& e) {
					callbacksInternal.set_error(ERROR_OUT_OF_MEMORY);
					break;
				}

				do {
					if (readFiles == filesToCompress.size())
						break;

                    //Last file was finished, open the next one
					if (!inFile.is_open()) {
						inFile.open(filesToCompress[readFiles].absolutePath, std::fstream::in | std::fstream::binary);
                        //Could not open new file
                        if (!inFile.is_open()) {
                            callbacksInternal.set_error(ERROR_FILE_OPEN_FAILED);
                            break;
                        }
                    }
					size_t bytesToRead = std::min(blockSize - thisBlockSize, filesToCompress[readFiles].size);
					inFile.read((char*)inputBuffer + thisBlockSize, bytesToRead);

					thisBlockSize += bytesToRead;
					filesToCompress[readFiles].size -= bytesToRead;

					if (filesToCompress[readFiles].size == 0) {
						inFile.close();
						readFiles++;
					}
				} while (thisBlockSize < (useSolidBlock ? blockSize : 1));

				//This can happen when the last files have size 0, or an error ocurred while reading files
				if (thisBlockSize == 0 || callbacksInternal.abort()) {
					delete[] inputBuffer;
					break;
				}

				size_t thisThreadID = startedThreads % threads;
				progress[thisThreadID].init(thisThreadID, &callbacksInternal);
				outBlocks[thisThreadID] = { nullptr, thisBlockSize, 0, 0 };
				cpu[thisThreadID] = std::thread(compress_block, inputBuffer, &outBlocks[thisThreadID], *compressionMethod,
					compressionLevel, *encryptionMethod, hash, &progress[thisThreadID]);
			}

			if (callbacksInternal.abort())
				break;

			size_t thisThreadID = consumedThreads % threads;
			cpu[thisThreadID].join();
			write_LEB128_file(&outFile, outBlocks[thisThreadID].originalSize);
			write_LEB128_file(&outFile, outBlocks[thisThreadID].compressedSize);
			outFile.write((char*)&outBlocks[thisThreadID].checksum, 4);
			outFile.write((char*)outBlocks[thisThreadID].data, outBlocks[thisThreadID].compressedSize);
			delete[] outBlocks[thisThreadID].data;
			outBlocks[thisThreadID].data = nullptr;
			consumedThreads++;
		}
		
		//In case of error or abort there can be leftovers
		for (; consumedThreads < startedThreads; consumedThreads++)
			cpu[consumedThreads % threads].join();
		for (int i = 0; i < threads; i++)
			delete[] outBlocks[i].data;
		delete[] cpu;
		delete[] outBlocks;
		delete[] progress;

		outFile.close();
		if (callbacksInternal.abort()) {
			std::error_code e;
			std::filesystem::remove(archivePath, e);
		}
		return callbacksInternal.get_error();
	}

	struct DecompressedBlock {
		uint8_t* data = nullptr;
		size_t bytesToWrite = 0;
	};

	void decompress_block(uint8_t* input, uint8_t** output, size_t compressedSize, size_t originalSize, 
		CompressionMethod compressionMethod, EncryptionMethod encryptionMethod, uint32_t crc, 
		std::vector<uint8_t> hash, ThreadCallback* callbacks) 
	{
		encryptionMethod.decrypt(input, compressedSize, hash);
		uint32_t computedChecksum = CRC::Calculate(input, compressedSize, CRC::CRC_32());
		if (computedChecksum != crc) {
			delete[] input;
			callbacks->set_error(ERROR_BAD_CRC);
			return;
		}
		compressionMethod.decompress(input, compressedSize, *output, originalSize, callbacks);
		callbacks->end_block(originalSize);
	}

	int read_directory_header(std::fstream* inFile, const EncryptionMethod& encryptionMethod, const CompressionMethod& compressionMethod, 
		const std::vector<uint8_t>& hash, std::vector<std::string>* directories, std::vector<FileInfo>* fileList, const std::string& outDir) 
	{
		size_t compressedHeaderSize = 0;
		size_t headerStreamSize = 0;
		if (read_LEB128_file(inFile, &compressedHeaderSize))
			return ERROR_BAD_FILE;
		if (read_LEB128_file(inFile, &headerStreamSize))
			return ERROR_BAD_FILE;
		uint32_t storedChecksum;
		inFile->read((char*)&storedChecksum, 4);

		uint8_t* compressedHeaderStream = nullptr;
		uint8_t* headerStream = nullptr;
		try {
			compressedHeaderStream = new uint8_t[compressedHeaderSize];
		}
		catch (std::bad_alloc& e) {
			return ERROR_OUT_OF_MEMORY;
		}
		inFile->read((char*)compressedHeaderStream, compressedHeaderSize);
		encryptionMethod.decrypt(compressedHeaderStream, compressedHeaderSize, hash);
		uint32_t computedChecksum = CRC::Calculate(compressedHeaderStream, compressedHeaderSize, CRC::CRC_32());
		if (computedChecksum != storedChecksum) {
			delete[] compressedHeaderStream;
			return ERROR_BAD_CRC;
		}
		ThreadCallback threadCallback;
		threadCallback.init(0, nullptr);
		compressionMethod.decompress(compressedHeaderStream, compressedHeaderSize, headerStream, headerStreamSize, &threadCallback);
		if (threadCallback.get_error())
			return threadCallback.get_error();

		const uint8_t* headerStreamIt = headerStream;
		const uint8_t* const headerStreamEnd = headerStream + headerStreamSize;

		size_t numberElements;
		if (read_LEB128_ptr(headerStreamIt, headerStreamEnd, &numberElements)) {
			delete[] headerStream;
			return ERROR_BAD_FILE;
		}

		try {
			for (size_t i = 0; i < numberElements; i++) {
				if (headerStreamIt == headerStreamEnd) {
					delete[] headerStream;
					return ERROR_BAD_FILE;
				}
				std::string relPath;
				relPath.push_back(*headerStreamIt++);
				//File names must be at least one byte long
				if (relPath[0] == '\0') {
					delete[] headerStream;
					return ERROR_BAD_FILE;
				}

				//Directories start with '/'
				if (relPath[0] == '/') {
					while (true) {
						if (headerStreamIt == headerStreamEnd) {
							delete[] headerStream;
							return ERROR_BAD_FILE;
						}
						uint8_t ch = *headerStreamIt++;
						if (ch == '\0')
							break;
						relPath.push_back(ch);
					}
					directories->push_back(outDir + relPath);
				}
				else {
					while (true) {
						if (headerStreamIt == headerStreamEnd) {
							delete[] headerStream;
							return ERROR_BAD_FILE;
						}
						uint8_t ch = *headerStreamIt++;
						if (ch == '\0')
							break;
						relPath.push_back(ch);
					}
					size_t fileSize;
					if (read_LEB128_ptr(headerStreamIt, headerStreamEnd, &fileSize)) {
						delete[] headerStream;
						return ERROR_BAD_FILE;
					}

					std::string absPath = outDir + '/' + relPath;
					std::string filename = std::filesystem::path(absPath).filename().string();
					fileList->push_back({ absPath, relPath, filename, fileSize });
				}
			}
		}
		catch (std::bad_alloc& e) {
			delete[] headerStream;
			return ERROR_OUT_OF_MEMORY;
		}

		delete[] headerStream;
		return 0;
	}

	int extract_archive(const std::string& file, const std::string& outDir, const std::string& password, 
		const int threads, ArchiveCallback* callbacks) 
	{
		ArchiveCallbackInternal callbacksInternal(callbacks);

		std::fstream inFile(file, std::fstream::binary | std::fstream::in);
		if (!inFile.is_open())
			return ERROR_FILE_OPEN_FAILED;
        //Magic number
		uint8_t storedMagicNumber[8];
		inFile.read((char*)&storedMagicNumber, 8);
		if (storedMagicNumber[0] != FILE_MAGIC_NUMBER[0] || storedMagicNumber[1] != FILE_MAGIC_NUMBER[1] || 
			storedMagicNumber[2] != FILE_MAGIC_NUMBER[2] || storedMagicNumber[3] != FILE_MAGIC_NUMBER[3] || 
			storedMagicNumber[4] != FILE_MAGIC_NUMBER[4] || storedMagicNumber[5] != FILE_MAGIC_NUMBER[5] || 
			storedMagicNumber[6] != FILE_MAGIC_NUMBER[6] || storedMagicNumber[7] != FILE_MAGIC_NUMBER[7]) 
		{
			return ERROR_BAD_FILE;
		}

		//Compression method
		std::string compressionName;
		compressionName.resize(inFile.get());
		inFile.read(compressionName.data(), compressionName.size());
		auto compressionMethod = std::find(compressionMethods.begin(), compressionMethods.end(), compressionName);
		if (compressionMethod == compressionMethods.end()) 
			return ERROR_UNKNOWN_COMPRESSION;

		//Encryption method
		std::string encryptionName;
		encryptionName.resize(inFile.get());
		inFile.read(encryptionName.data(), encryptionName.size());
		auto encryptionMethod = std::find(encryptionMethods.begin(), encryptionMethods.end(), encryptionName);
		if (encryptionMethod == encryptionMethods.end())
			return ERROR_UNKNOWN_ENCRYPTION;
		std::vector<uint8_t> salt(encryptionMethod->saltLength);
		inFile.read((char*)salt.data(), salt.size());
		
		std::vector<uint8_t> hash;
		hash = encryptionMethod->hash(password, salt);

		//Header
		std::vector<std::string> directories;
		std::vector<FileInfo> fileList;
		int error = read_directory_header(&inFile, *encryptionMethod, *compressionMethod,
			hash, &directories, &fileList, outDir);
		if (error)
			return error;

		try {
			for (auto it = directories.begin(); it != directories.end(); it++) 
				std::filesystem::create_directories(*it);
		}
		catch (std::filesystem::filesystem_error& e) {
			callbacksInternal.set_error(ERROR_OTHER);
		}
		for (auto it = fileList.begin(); it != fileList.end(); it++) {
			std::fstream o(it->absolutePath, std::fstream::out | std::fstream::binary);
			//Error during file creation, perhaps an invalid filename
			if (!o.is_open()) {
				callbacksInternal.set_error(ERROR_OTHER);
				break;
			}
		}
		
		//No errors during file/directory creation? Extract the data
		if (!callbacks->abort()) {

			size_t totalContainedSize = 0;
			for (auto it = fileList.begin(); it != fileList.end(); it++) 
				totalContainedSize += it->size;
			callbacksInternal.init(threads, totalContainedSize);

			//Compressed data
			std::fstream outFile;
			size_t writtenFiles = 0;
			size_t remainingData = totalContainedSize;

			std::thread* cpu = new std::thread[threads];
			ThreadCallback* progress = new ThreadCallback[threads];
			DecompressedBlock* outBlocks = new DecompressedBlock[threads];

			//Create threads using a circular buffer
			size_t startedThreads = 0;
			size_t consumedThreads = 0;

			while (remainingData != 0 || consumedThreads != startedThreads) {

				for (; startedThreads < consumedThreads + threads; startedThreads++) {

					if (remainingData == 0 || callbacksInternal.abort())
						break;

					size_t originalSize;
					if (read_LEB128_file(&inFile, &originalSize) || originalSize > remainingData) {
						callbacksInternal.set_error(ERROR_BAD_FILE);
						break;
					}
					size_t compressedSize;
					if (read_LEB128_file(&inFile, &compressedSize)) {
						callbacksInternal.set_error(ERROR_BAD_FILE);
						break;
					}
					uint32_t storedChecksum;
					inFile.read((char*)&storedChecksum, 4);

					uint8_t* compressedData;
					try {
						compressedData = new uint8_t[compressedSize];
					}
					catch (std::bad_alloc& e) {
						callbacksInternal.set_error(ERROR_OUT_OF_MEMORY);
						break;
					}
					inFile.read((char*)compressedData, compressedSize);
					remainingData -= originalSize;

					size_t thisThreadID = startedThreads % threads;
					progress[thisThreadID].init(thisThreadID, &callbacksInternal);
					outBlocks[thisThreadID] = { nullptr, originalSize };
					cpu[thisThreadID] = std::thread(decompress_block, compressedData, &outBlocks[thisThreadID].data, compressedSize, originalSize,
						*compressionMethod, *encryptionMethod, storedChecksum, hash, &progress[thisThreadID]);
				}

				//Error during block reading
				if (callbacksInternal.abort())
					break;

				size_t thisThreadID = consumedThreads % threads;
				cpu[thisThreadID].join();

				//Error during block decoding
				if (callbacksInternal.abort())
					break;

				size_t bytesWritten = 0;
				do {
					if (writtenFiles == fileList.size())
						break;

					if (!outFile.is_open()) {
						outFile.open(fileList[writtenFiles].absolutePath, std::fstream::binary | std::fstream::out);
						//Could not open file
						if (!outFile.is_open()) {
							callbacksInternal.set_error(ERROR_FILE_OPEN_FAILED);
							break;
						}
					}

					size_t bytesToWrite = std::min(fileList[writtenFiles].size, outBlocks[thisThreadID].bytesToWrite);
					outFile.write((char*)outBlocks[thisThreadID].data + bytesWritten, bytesToWrite);
					fileList[writtenFiles].size -= bytesToWrite;
					outBlocks[thisThreadID].bytesToWrite -= bytesToWrite;
					bytesWritten += bytesToWrite;

					if (fileList[writtenFiles].size == 0) {
						outFile.close();
						writtenFiles++;
					}
				} while (outBlocks[thisThreadID].bytesToWrite);
				delete[] outBlocks[thisThreadID].data;
				outBlocks[thisThreadID].data = nullptr;
				
				consumedThreads++;
			}

			//There might be leftovers due to an error or abort
			for (; consumedThreads < startedThreads; consumedThreads++)
				cpu[consumedThreads % threads].join();
			for (int i = 0; i < threads; i++)
				delete[] outBlocks[i].data;
			outFile.close();
			delete[] cpu;
			delete[] outBlocks;
			delete[] progress;
		}
		
		if (callbacksInternal.abort()) {
			std::error_code e;
			try {
				for (auto it = fileList.begin(); it != fileList.end(); it++)
					std::filesystem::remove(it->absolutePath, e);
				for (auto it = directories.begin(); it != directories.end(); it++)
					std::filesystem::remove_all(*it, e);
			}
			catch (...) {}
		}
		return callbacksInternal.get_error();
	}

	std::vector<CompressionMethodData> get_compression_methods() {
		std::vector<CompressionMethodData> list;
		for (auto method : compressionMethods)
			list.push_back(method.data);
		return list;
	}
	size_t estimate_memory(const std::string& compressionName, const int compressionLevel, 
		const size_t blockSize, const int threads) 
	{
		auto compressionMethod = std::find(compressionMethods.begin(), compressionMethods.end(), compressionName);
		if (compressionMethod == compressionMethods.end())
			return 0;
		return (compressionMethod->estimate_memory(blockSize, compressionLevel) + blockSize) * threads;
	}
	int is_archive_encrypted(const std::string& file) {

		std::fstream inFile(file, std::fstream::binary | std::fstream::in);
		if (!inFile.is_open())
			return ERROR_FILE_OPEN_FAILED;
		uint8_t storedMagicNumber[8];
		inFile.read((char*)&storedMagicNumber, 8);
		if (storedMagicNumber[0] != FILE_MAGIC_NUMBER[0] || storedMagicNumber[1] != FILE_MAGIC_NUMBER[1] ||
			storedMagicNumber[2] != FILE_MAGIC_NUMBER[2] || storedMagicNumber[3] != FILE_MAGIC_NUMBER[3] ||
			storedMagicNumber[4] != FILE_MAGIC_NUMBER[4] || storedMagicNumber[5] != FILE_MAGIC_NUMBER[5] ||
			storedMagicNumber[6] != FILE_MAGIC_NUMBER[6] || storedMagicNumber[7] != FILE_MAGIC_NUMBER[7])
		{
			return ERROR_BAD_FILE;
		}

		size_t compressionNameSize = inFile.get();
		inFile.seekg(compressionNameSize, std::fstream::cur);

		std::string encryptionName;
		encryptionName.resize(inFile.get());
		inFile.read(encryptionName.data(), encryptionName.size());
		return encryptionName != "none";
	}
}

#endif  //ARCHIVER_IMPLEMENTATION

#endif  //__ARCHIVER__
