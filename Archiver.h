/*
 * Simple Archiver v1.0.0
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
#include <iostream>

namespace archiver {

	const int ERROR_BAD_FILE = -1;
	const int ERROR_UNKNOWN_COMPRESSION = -2;
	const int ERROR_UNKNOWN_ENCRYPTION = -3;
	const int ERROR_OUT_OF_MEMORY = -4;
	const int ERROR_FILE_OPEN_FAILED = -5;
	const int ERROR_BAD_CRC = -6;

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
		string name;
		int minLevel;
		int maxLevel;
	};

	//Creates and extracts archives. Both will return 0 on success or user abort or an error code on failure
	int create_archive(vector<string> inputFiles, string archivePath, string compressionName, 
		int compressionLevel, string encryptionName, string password, size_t blockSize, 
		bool useSolidBlock, int threads, ArchiveCallback* callbacks = nullptr);
	int extract_archive(string file, string outDir, string password, int threads, ArchiveCallback* callbacks = nullptr);

	//Returs some data about the available compression algorithms
	vector<CompressionMethodData> get_compression_methods();
	//Returs an estimation of the amount of memory the encoder will use 
	size_t estimate_memory(string compressionName, int compressionLevel, size_t blockSize, int threads);
	//Returns whether a given archive is encrypted or an error code on failure
	int is_archive_encrypted(string file);
}

#ifdef ARCHIVER_IMPLEMENTATION

#include <thread>
#include <mutex>
#include <atomic>
#include <cstdint>

#define SKANDA_IMPLEMENTATION
#include "Skanda.h"
#define STRIDER_IMPLEMENTATION
#include "Strider.h"
#define SPECTRUM_IMPLEMENTATION
#include "Spectrum.h"
#include "picosha2.h"
#include "crc.h"

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

	//Encodes the value, and advances the pointer
	void write_LEB128_ptr(uint8_t*& out, size_t value) {
		do {
			uint8_t byte = value & 0x7F;
			value >>= 7;
			byte |= (value > 0) << 7;
			*out++ = byte;
		} while (value);
	}
	void write_LEB128_file(fstream* out, size_t value) {
		do {
			uint8_t byte = value & 0x7F;
			value >>= 7;
			byte |= (value > 0) << 7;
			out->put(byte);
		} while (value);
	}
	void write_LEB128_vector(vector<uint8_t>* out, size_t value) {
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
	int read_LEB128_file(fstream* in, size_t* value) {
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
		vector<size_t> threadProgress;
		int internalError = 0;  //For errors like out of memory or bad crc
		bool doAbort = false;  //When we get confirmation for abort from user do not ask again

	public:
		ArchiveCallbackInternal(ArchiveCallback* c) {
			userCallbacks = c;
		}
		void set_parameters(size_t threads, size_t size) {
			threadProgress = vector<size_t>(threads, 0);
			totalSize = size;
		}
		int get_internal_error() {
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
		void set_internal_error(int code) {
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
		void start_block(size_t _blockRawSize) {
			blockRawSize = _blockRawSize;
			blockProgress = 0;
		}
		void progress(size_t bytes) {
			blockProgress = bytes;
			if (blockProgress == blockRawSize) {
				totalProgress += blockRawSize;
				blockProgress = 0;
			}
			archiveCallbacks->add_progress(totalProgress + blockProgress, threadID);
		}
		void set_error(int error) {
			archiveCallbacks->set_internal_error(error);
		}
		int abort() {
			return archiveCallbacks->abort();
		}
	};

	class SkandaProgressCallback : public skanda::ProgressCallback {
		ThreadCallback* threadCallbacks;
	public:
		SkandaProgressCallback(ThreadCallback* callbacks) {
			threadCallbacks = callbacks;
		}
		void progress(size_t bytes) {
			threadCallbacks->progress(bytes);
		}
		void set_error(int error) {
			threadCallbacks->set_error(error);
		}
		int abort() {
			return threadCallbacks->abort();
		}
	};

	size_t skanda_compress(uint8_t*& input, size_t size, uint8_t*& output, int level, ThreadCallback* progress) 
	{
		progress->start_block(size);
		SkandaProgressCallback progressCallback(progress);
		try {
			output = new uint8_t[skanda::skanda_compress_bound(size)];
		}
		catch (std::bad_alloc& e) {
			delete[] input;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		size_t compressedSize = skanda::skanda_compress(input, size, output, level, 999, &progressCallback);
		delete[] input;
		if (compressedSize == -1) {
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		return compressedSize;
	}
	void skanda_decompress(uint8_t*& compressed, size_t compressedSize, uint8_t*& decompressed,
		size_t decompressedSize, ThreadCallback* progress) 
	{
		progress->start_block(decompressedSize);
		SkandaProgressCallback progressCallback(progress);
		try {
			decompressed = new uint8_t[decompressedSize];
		}
		catch (std::bad_alloc& e) {
			delete[] compressed;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return;
		}
		int error = skanda::skanda_decompress(compressed, compressedSize, decompressed, decompressedSize, &progressCallback);
		delete[] compressed;
		if (error)
			progress->set_error(ERROR_BAD_FILE);
	}
	size_t skanda_estimate_memory(size_t size, int level) {
		return skanda::skanda_estimate_memory(size, level, 999) + skanda::skanda_compress_bound(size);
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
		progress->start_block(size);
		StriderProgressCallback progressCallback(progress);
		try {
			output = new uint8_t[strider::strider_compress_bound(size)];
		}
		catch (std::bad_alloc& e) {
			delete[] input;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		size_t compressedSize = strider::strider_compress(input, size, output, level, 999, &progressCallback);
		delete[] input;
		if (compressedSize == -1) {
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		return compressedSize;
	}
	void strider_decompress(uint8_t*& compressed, size_t compressedSize, uint8_t*& decompressed,
		size_t decompressedSize, ThreadCallback* progress)
	{
		progress->start_block(decompressedSize);
		StriderProgressCallback progressCallback(progress);
		try {
			decompressed = new uint8_t[decompressedSize];
		}
		catch (std::bad_alloc& e) {
			delete[] compressed;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return;
		}
		int error = strider::strider_decompress(compressed, compressedSize, decompressed, decompressedSize, &progressCallback);
		delete[] compressed;
		if (error)
			progress->set_error(ERROR_BAD_FILE);
	}
	size_t strider_estimate_memory(size_t size, int level) {
		return strider::strider_estimate_memory(size, level, 999) + strider::strider_compress_bound(size);
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
			if (bytes == preprocessedSize)
				backendCallback->progress(originalSize);
			else
				backendCallback->progress((float)bytes / preprocessedSize * originalSize);
		}
		int abort() {
			if (backendCallback)
				return backendCallback->abort();
			return false;
		}
	};

	size_t spectrum_strider_compress(uint8_t*& input, size_t size, uint8_t*& output, int level, ThreadCallback* progress)
	{
		progress->start_block(size);
		uint8_t* preprocessed;
		try {
			preprocessed = new uint8_t[spectrum::spectrum_bound(size)];
		}
		catch (std::bad_alloc& e) {
			delete[] input;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		size_t preprocessedSize = spectrum::spectrum_encode(input, size, preprocessed);
		delete[] input;
		if (preprocessedSize == -1) {
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}

		try {
			output = new uint8_t[strider::strider_compress_bound(preprocessedSize)];
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
		size_t compressedSize = strider::strider_compress(preprocessed, preprocessedSize, compressedBegin, level, 999, &progressCallback);
		delete[] preprocessed;
		if (compressedSize == -1) {
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return 0;
		}
		return compressedSize + (compressedBegin - output);
	}
	void spectrum_strider_decompress(uint8_t*& compressed, size_t compressedSize, uint8_t*& decompressed,
		size_t decompressedSize, ThreadCallback* progress)
	{
		//First we read preprocessed size
		size_t preprocessedSize;
		const uint8_t* compressedBegin = compressed;
		read_LEB128_ptr(compressedBegin, compressed + compressedSize, &preprocessedSize);

		progress->start_block(decompressedSize);
		SpectrumStriderProgressCallback progressCallback(progress, preprocessedSize, decompressedSize);
		uint8_t* preprocessed;
		try {
			preprocessed = new uint8_t[preprocessedSize];
		}
		catch (std::bad_alloc& e) {
			delete[] compressed;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return;
		}
		int error = strider::strider_decompress(compressedBegin, compressedSize, preprocessed, preprocessedSize, &progressCallback);
		delete[] compressed;
		if (error) {
			progress->set_error(ERROR_BAD_FILE);
			return;
		}
		try {
			decompressed = new uint8_t[decompressedSize];
		}
		catch (std::bad_alloc& e) {
			delete[] preprocessed;
			progress->set_error(ERROR_OUT_OF_MEMORY);
			return;
		}
		error = spectrum::spectrum_decode(preprocessed, preprocessedSize, decompressed, decompressedSize);
		delete[] preprocessed;
		if (error)
			progress->set_error(ERROR_BAD_FILE);
	}
	size_t spectrum_strider_estimate_memory(size_t size, int level) {
		return strider::strider_estimate_memory(size, level, 999) + strider::strider_compress_bound(spectrum::spectrum_bound(size));
	}

	size_t none_compress(uint8_t*& input, size_t size, uint8_t*& output, int level, ThreadCallback* progress) 
	{
		progress->start_block(size);
		output = input;
		if (progress)
			progress->progress(size);
		return size;
	}
	int none_decompress(uint8_t*& compressed, size_t compressedSize, uint8_t*& decompressed, 
		size_t decompressedSize, ThreadCallback* progress = nullptr) 
	{
		progress->start_block(decompressedSize);
		decompressed = compressed;
		if (progress)
			progress->progress(decompressedSize);
		return 0;
	}
	size_t none_estimate_memory(size_t size, int level) {
		return size;
	}

	struct CompressionMethod {
		CompressionMethodData data;
		//Both compress and decompress take a pointer to a memory location with the input data, and must allocate
		// the pointer to the output data. In all cases the input data must be freed.
		std::function<size_t(uint8_t*& input, size_t size, uint8_t*& output, int level, ThreadCallback* progress)> compress;
		std::function<void(uint8_t*& compressed, size_t compressedSize, uint8_t*& decompressed, size_t uncompressedSize, ThreadCallback* progress)> decompress;
		std::function<size_t(size_t size, int level)> estimate_memory;

		//To find the algorithm
		bool operator==(const string& other) const {
			return data.name == other;
		}
	};

	const vector<CompressionMethod> compressionMethods = {
		{ { string("none"), 0, 0 }, &none_compress, &none_decompress, &none_estimate_memory },
		{ { string("skanda"), 0, 10 }, &skanda_compress, &skanda_decompress, &skanda_estimate_memory },
		{ { string("strider"), 0, 10 }, &strider_compress, &strider_decompress, &strider_estimate_memory },
		{ { string("spectrum/strider"), 0, 10 }, &spectrum_strider_compress, &spectrum_strider_decompress, &spectrum_strider_estimate_memory },
	};

	vector<uint8_t> hash_none(string password, uint32_t salt) {
		return vector<uint8_t>();
	}
	void encrypt_none(uint8_t* data, size_t size, vector<uint8_t> hash) {
		return;
	}

	vector<uint8_t> hash_sha256(string password, uint32_t salt) {
		password.push_back((salt >> 0) & 0xFF);
		password.push_back((salt >> 8) & 0xFF);
		password.push_back((salt >> 16) & 0xFF);
		password.push_back((salt >> 24) & 0xFF);
		vector<uint8_t> hash(picosha2::k_digest_size);
		picosha2::hash256<string>(password, hash);
		return hash;
	}
	//Both encryptor and decryptor perform the same operations
	void encrypt_sha256(uint8_t* data, size_t size, vector<uint8_t> hash) {

		for (size_t i = 0; i < size; i++) {
			uint32_t baseHashIndex = i % 32;
			data[i] ^= hash[baseHashIndex];

			uint32_t mixHashIndex = rand32(i);
			hash[baseHashIndex] ^= hash[mixHashIndex % 32];
		}
	}

	struct EncryptionMethod {
		string name;
		std::function<vector<uint8_t>(string password, uint32_t salt)> hash;
		std::function<void(uint8_t* data, size_t size, vector<uint8_t> hash)> encrypt;
		std::function<void(uint8_t* data, size_t size, vector<uint8_t> hash)> decrypt;

		bool operator==(const string& other) const {
			return name == other;
		}
	};

	const vector<EncryptionMethod> encryptionMethods = {
		{ "none", &hash_none, &encrypt_none, &encrypt_none },
		{ "sha256", &hash_sha256, &encrypt_sha256, &encrypt_sha256 }
	};

	struct FileInfo {
		string absolutePath;
		string relativePath;
		string filename;
		size_t size;

		//For file sort. Placing similar files together can improve compression
		bool operator<(FileInfo& other) {
			
			string extensionA = filesystem::path(absolutePath).extension().string();
			string extensionB = filesystem::path(other.absolutePath).extension().string();

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

	void compress_block(uint8_t* input, CompressedBlock* compressedBlock, CompressionMethod compressionMethod, 
		int compressionLevel, EncryptionMethod encryptionMethod, vector<uint8_t> hash, ThreadCallback* callbacks)
	{
		compressedBlock->compressedSize = compressionMethod.compress(input, compressedBlock->originalSize, compressedBlock->data, compressionLevel, callbacks);
		if (callbacks->abort()) 
			return;
		compressedBlock->checksum = CRC::Calculate(compressedBlock->data, compressedBlock->compressedSize, CRC::CRC_32());
		encryptionMethod.encrypt(compressedBlock->data, compressedBlock->compressedSize, hash);
	}

	int read_directory_and_create_header(vector<string> inputFiles, fstream* outFile, 
		EncryptionMethod encryptionMethod, vector<uint8_t> hash, vector<FileInfo>* filesToCompress, bool useSolidBlock) {

		//Search for all archives
		vector<string> directories;
		std::vector<uint8_t> headerStream;
		try {
			for (size_t i = 0; i < inputFiles.size(); i++) {
				if (filesystem::is_directory(inputFiles[i])) {
					size_t relPathStart = inputFiles[i].rfind('\\') + 1;
					directories.push_back(inputFiles[i].substr(relPathStart));

					for (auto entry : filesystem::recursive_directory_iterator(inputFiles[i])) {
						if (entry.is_directory()) {
							directories.push_back(entry.path().string().substr(relPathStart));
						}
						else {
							string absPath = entry.path().string();
							string relPath = absPath.substr(relPathStart);
							string filename = entry.path().filename().string();
							size_t size = filesystem::file_size(absPath);
							filesToCompress->push_back({ absPath, relPath, filename, size });
						}
					}
				}
				else {
					string absPath = inputFiles[i];
					string relPath = filesystem::path(absPath).filename().string();
					string filename = relPath;
					size_t size = filesystem::file_size(absPath);
					filesToCompress->push_back({ absPath, relPath, filename, size });
				}
			}

			if (useSolidBlock)
				std::sort(filesToCompress->begin(), filesToCompress->end());

			size_t numberElements = directories.size() + filesToCompress->size();
			write_LEB128_vector(&headerStream, numberElements);

			for (size_t i = 0; i < directories.size(); i++) {
				//Directories are marked by starting with '\'
				headerStream.push_back('\\');
				for (size_t c = 0; c < directories[i].size(); c++)
					headerStream.push_back(directories[i][c]);
				headerStream.push_back('\0');
			}
			for (size_t i = 0; i < filesToCompress->size(); i++) {
				for (size_t c = 0; c < filesToCompress->at(i).relativePath.size(); c++)
					headerStream.push_back(filesToCompress->at(i).relativePath[c]);
				headerStream.push_back('\0');

				write_LEB128_vector(&headerStream, filesToCompress->at(i).size);
			}
		}
		catch (std::bad_alloc& e) {
			return ERROR_OUT_OF_MEMORY;
		}
		catch (std::filesystem::filesystem_error& e) {
			return ERROR_FILE_OPEN_FAILED;
		}

		uint32_t checksum = CRC::Calculate(headerStream.data(), headerStream.size(), CRC::CRC_32());
		encryptionMethod.encrypt(headerStream.data(), headerStream.size(), hash);
		write_LEB128_file(outFile, headerStream.size());
		outFile->write((char*)&checksum, 4);
		outFile->write((char*)headerStream.data(), headerStream.size());
		return 0;
	}

	int create_archive(vector<string> inputFiles, string archivePath, string compressionName, int compressionLevel,
		string encryptionName, string password, size_t blockSize, bool useSolidBlock, int threads, ArchiveCallback* callbacks) {

		ArchiveCallbackInternal callbacksInternal(callbacks);

		//Create the archive
		fstream outFile(archivePath, fstream::binary | fstream::out);
		outFile.write((char*)&FILE_MAGIC_NUMBER, 8);

		//Write compression method used
		auto compressionMethod = std::find(compressionMethods.begin(), compressionMethods.end(), compressionName);
		outFile.put(compressionMethod->data.name.size());
		outFile.write(compressionMethod->data.name.data(), compressionMethod->data.name.size());

		//Write encryption method used
		auto encryptionMethod = std::find(encryptionMethods.begin(), encryptionMethods.end(), encryptionName);
		outFile.put(encryptionMethod->name.size());
		outFile.write(encryptionMethod->name.data(), encryptionMethod->name.size());
		uint32_t salt = rand32(std::time(nullptr));
		outFile.write((char*)&salt, 4);
		vector<uint8_t> hash = encryptionMethod->hash(password, salt);

		//Directories
		vector<FileInfo> filesToCompress;
		int error = read_directory_and_create_header(inputFiles, &outFile, 
			*encryptionMethod, hash, &filesToCompress, useSolidBlock);
		if (error) {
			outFile.close();
			filesystem::remove(archivePath);
			return error;
		}

		size_t totalContainedSize = 0;
		for (auto it = filesToCompress.begin(); it != filesToCompress.end(); it++) 
			totalContainedSize += it->size;
		callbacksInternal.set_parameters(threads, totalContainedSize);

		//Compression
		fstream inFile;
		size_t readFiles = 0;
		
		thread* cpu = new thread[threads];
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
					callbacksInternal.set_internal_error(ERROR_OUT_OF_MEMORY);
					break;
				}

				do {
					if (readFiles == filesToCompress.size())
						break;

					if (!inFile.is_open())
						inFile.open(filesToCompress[readFiles].absolutePath, fstream::in | fstream::binary);
					size_t bytesToRead = std::min(blockSize - thisBlockSize, filesToCompress[readFiles].size);
					inFile.read((char*)inputBuffer + thisBlockSize, bytesToRead);

					thisBlockSize += bytesToRead;
					filesToCompress[readFiles].size -= bytesToRead;

					if (filesToCompress[readFiles].size == 0) {
						inFile.close();
						readFiles++;
					}
				} while (thisBlockSize < (useSolidBlock ? blockSize : 1));

				//This can happen when the last files have size 0
				if (thisBlockSize == 0) {
					delete[] inputBuffer;
					break;
				}

				size_t thisThreadID = startedThreads % threads;
				progress[thisThreadID].init(thisThreadID, &callbacksInternal);
				outBlocks[thisThreadID] = { nullptr, thisBlockSize, 0, 0 };
				cpu[thisThreadID] = thread(compress_block, inputBuffer, &outBlocks[thisThreadID], *compressionMethod,
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
		if (callbacksInternal.abort())
			filesystem::remove(archivePath);
		return callbacksInternal.get_internal_error();
	}

	struct DecompressedBlock {
		uint8_t* data = nullptr;
		size_t bytesToWrite = 0;
	};

	void decompress_block(uint8_t* input, uint8_t** output, size_t compressedSize, size_t originalSize, 
		CompressionMethod compressionMethod, EncryptionMethod encryptionMethod, uint32_t crc, 
		vector<uint8_t> hash, ThreadCallback* callbacks) 
	{
		encryptionMethod.decrypt(input, compressedSize, hash);
		uint32_t computedChecksum = CRC::Calculate(input, compressedSize, CRC::CRC_32());
		if (computedChecksum != crc) {
			delete[] input;
			callbacks->set_error(ERROR_BAD_CRC);
			return;
		}
		compressionMethod.decompress(input, compressedSize, *output, originalSize, callbacks);
	}

	int read_directory_header(fstream* inFile, EncryptionMethod encryptionMethod,
		vector<uint8_t> hash, vector<string>* directories, vector<FileInfo>* fileList, string path) {

		size_t headerSize = 0;
		if (read_LEB128_file(inFile, &headerSize))
			return ERROR_BAD_FILE;
		uint32_t storedChecksum;
		inFile->read((char*)&storedChecksum, 4);

		uint8_t* headerStream;
		try {
			headerStream = new uint8_t[headerSize];
		}
		catch (std::bad_alloc& e) {
			return ERROR_OUT_OF_MEMORY;
		}
		inFile->read((char*)headerStream, headerSize);
		encryptionMethod.decrypt(headerStream, headerSize, hash);
		uint32_t computedChecksum = CRC::Calculate(headerStream, headerSize, CRC::CRC_32());
		if (computedChecksum != storedChecksum) {
			delete[] headerStream;
			return ERROR_BAD_CRC;
		}
		const uint8_t* headerStreamIt = headerStream;
		const uint8_t* const headerStreamEnd = headerStream + headerSize;

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
				string relPath;
				relPath.push_back(*headerStreamIt++);
				//File names must be at least one byte long
				if (relPath[0] == '\0') {
					delete[] headerStream;
					return ERROR_BAD_FILE;
				}

				//Directories start with '\'
				if (relPath[0] == '\\') {
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
					directories->push_back(path + relPath);
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

					string absPath = path + '\\' + relPath;
					string filename = filesystem::path(absPath).filename().string();
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

	int extract_archive(string file, string outDir, string password, int threads, ArchiveCallback* callbacks) {

		ArchiveCallbackInternal callbacksInternal(callbacks);

		//Magic number
		fstream inFile(file, fstream::binary | fstream::in);
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

		//Compression method
		string compressionName;
		compressionName.resize(inFile.get());
		inFile.read(compressionName.data(), compressionName.size());
		auto compressionMethod = std::find(compressionMethods.begin(), compressionMethods.end(), compressionName);
		if (compressionMethod == compressionMethods.end()) 
			return ERROR_UNKNOWN_COMPRESSION;

		//Encryption method
		string encryptionName;
		encryptionName.resize(inFile.get());
		inFile.read(encryptionName.data(), encryptionName.size());
		auto encryptionMethod = std::find(encryptionMethods.begin(), encryptionMethods.end(), encryptionName);
		if (encryptionMethod == encryptionMethods.end())
			return ERROR_UNKNOWN_ENCRYPTION;
		uint32_t salt;
		inFile.read((char*)&salt, 4);
		
		vector<uint8_t> hash;
		hash = encryptionMethod->hash(password, salt);

		//Header
		vector<string> directories;
		vector<FileInfo> fileList;
		int error = read_directory_header(&inFile, *encryptionMethod, 
			hash, &directories, &fileList, outDir);
		if (error)
			return error;

		for (auto it = directories.begin(); it != directories.end(); it++) 
			filesystem::create_directories(*it);
		for (auto it = fileList.begin(); it != fileList.end(); it++) {
			fstream o(it->absolutePath, fstream::out | fstream::binary);
			o.close();
		}

		size_t totalContainedSize = 0;
		for (auto it = fileList.begin(); it != fileList.end(); it++) 
			totalContainedSize += it->size;
		callbacksInternal.set_parameters(threads, totalContainedSize);

		//Compressed data
		fstream outFile;
		size_t writtenFiles = 0;
		size_t remainingData = totalContainedSize;

		thread* cpu = new thread[threads];
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
					callbacksInternal.set_internal_error(ERROR_BAD_FILE);
					break;
				}
				size_t compressedSize;
				if (read_LEB128_file(&inFile, &compressedSize)) {
					callbacksInternal.set_internal_error(ERROR_BAD_FILE);
					break;
				}
				uint32_t storedChecksum;
				inFile.read((char*)&storedChecksum, 4);

				uint8_t* compressedData;
				try {
					compressedData = new uint8_t[compressedSize];
				}
				catch (std::bad_alloc& e) {
					callbacksInternal.set_internal_error(ERROR_OUT_OF_MEMORY);
					break;
				}
				inFile.read((char*)compressedData, compressedSize);
				remainingData -= originalSize;

				size_t thisThreadID = startedThreads % threads;
				progress[thisThreadID].init(thisThreadID, &callbacksInternal);
				outBlocks[thisThreadID] = { nullptr, originalSize };
				cpu[thisThreadID] = thread(decompress_block, compressedData, &outBlocks[thisThreadID].data, compressedSize, originalSize,
					*compressionMethod, *encryptionMethod, storedChecksum, hash, &progress[thisThreadID]);
			}

			if (callbacksInternal.abort())
				break;

			size_t thisThreadID = consumedThreads % threads;
			cpu[thisThreadID].join();

			size_t bytesWritten = 0;
			do {
				if (!outFile.is_open())
					outFile.open(fileList[writtenFiles].absolutePath, fstream::binary | fstream::out);

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
		delete[] cpu;
		delete[] outBlocks;
		delete[] progress;

		outFile.close();
		if (callbacksInternal.abort()) {
			for (auto it = fileList.begin(); it != fileList.end(); it++)
				filesystem::remove(it->absolutePath);
			for (auto it = directories.begin(); it != directories.end(); it++)
				filesystem::remove(*it);
		}
		return callbacksInternal.get_internal_error();
	}

	vector<CompressionMethodData> get_compression_methods() {
		vector<CompressionMethodData> list;
		for (auto method : compressionMethods)
			list.push_back(method.data);
		return list;
	}
	size_t estimate_memory(string compressionName, int compressionLevel, size_t blockSize, int threads) {
		auto compressionMethod = std::find(compressionMethods.begin(), compressionMethods.end(), compressionName);
		if (compressionMethod == compressionMethods.end())
			return 0;
		return (compressionMethod->estimate_memory(blockSize, compressionLevel) + blockSize) * threads;
	}
	int is_archive_encrypted(string file) {

		fstream inFile(file, fstream::binary | fstream::in);
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
		inFile.seekg(compressionNameSize, fstream::cur);

		string encryptionName;
		encryptionName.resize(inFile.get());
		inFile.read(encryptionName.data(), encryptionName.size());
		return encryptionName != "none";
	}
}

#endif  //ARCHIVER_IMPLEMENTATION

#endif  //__ARCHIVER__