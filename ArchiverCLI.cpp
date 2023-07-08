/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <unordered_map>
#include <thread>

#if defined(_WIN32)
	#define WIN32_LEAN_AND_MEAN
	#include <Windows.h>
	#undef min
	#undef max
	#undef NO_ERROR
	#undef ERROR_WRONG_PASSWORD
#elif defined(__linux__)
	#include <unistd.h>
	#include <sys/sysinfo.h>
#endif

#define ARCHIVER_IMPLEMENTATION
#include "Archiver.h"

const size_t MiB = (size_t)1024 * 1024;

const char* SIZE_SUFFIX[] = {
	"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"
};

archiver::Parameters DEFAULT_PARAMETERS[10] = {
	{ { }, 0, "", 0, false, 1 * MiB, 1 },
	{ { "spectrum", "strider" }, 0, "", 16, true, 8 * MiB, 1 },
	{ { "spectrum", "strider" }, 2, "", 16, true, 8 * MiB, 1 },
	{ { "spectrum", "strider" }, 3, "", 16, true, 16 * MiB, 1 },
	{ { "spectrum", "strider" }, 4, "", 16, true, 16 * MiB, 1 },
	{ { "spectrum", "strider" }, 5, "", 17, true, 32 * MiB, 1 },
	{ { "spectrum", "strider" }, 6, "", 17, true, 32 * MiB, 1 },
	{ { "spectrum", "strider" }, 7, "", 18, true, 64 * MiB, 1 },
	{ { "spectrum", "strider" }, 8, "", 19, true, 64 * MiB, 1 },
	{ { "spectrum", "strider" }, 9, "", 20, true, 128 * MiB, 1 },
};

size_t get_available_memory() {
#if defined(_WIN32)
	MEMORYSTATUSEX buffer;
	buffer.dwLength = sizeof(MEMORYSTATUSEX);
	GlobalMemoryStatusEx(&buffer);
	return buffer.ullTotalPhys;
#elif defined(__linux__)
	return get_phys_pages() * sysconf(_SC_PAGESIZE);
#else
	return UINT64_MAX;
#endif
}

class MyArchiveCallback : public archiver::ArchiveCallback {

	float speed = 0;
	std::chrono::time_point<std::chrono::high_resolution_clock> initTime = std::chrono::high_resolution_clock::now();
	std::chrono::time_point<std::chrono::high_resolution_clock> prevPrintTime = std::chrono::high_resolution_clock::now();

public:
	MyArchiveCallback() {}
	void progress(size_t total, size_t consumed, size_t compressed) {

		float newSpeed = consumed / ((std::chrono::high_resolution_clock::now() - initTime).count() / 1e9);
		speed = speed * 63 / 64 + newSpeed * 1 / 64;
		size_t prefixIndex = std::min(std::log2(speed) / 10, 6.0f);

		if (prevPrintTime == initTime || (std::chrono::high_resolution_clock::now() - prevPrintTime).count() > 100'000'000) {
			prevPrintTime = std::chrono::high_resolution_clock::now();
			for (int i = 0; i < 100; i++)
				std::cout << "\b";
			std::cout << std::fixed << std::setprecision(2);
			std::cout << "Progress " << (float)consumed / total * 100 << "%   ";
			std::cout << "Ratio " << (float)compressed / consumed * 100 << "%   ";
			std::cout << "Speed " << speed / std::pow(2, prefixIndex * 10) << SIZE_SUFFIX[prefixIndex];
			std::cout << "      ";
		}
	}
};

const std::string ERROR_MESSAGES[] = {
	"Invalid archive",
	"Unknown codec",
	"No available memory",
	"File open fail",
	"Corrupted data",
	"Invalid argument",
	"Incorrect password",
	"Unknown error"
};

std::string get_error_message(int code) {
	return ERROR_MESSAGES[-code - 1];
}

void print_help() {
	std::cout << "Archiver v0.2\n"
				 "\n"
				 "Add to archive: archiver a [<options>...] <archive path> [<files/directories paths>...]\n"
				 "Extract: archiver x [<options>...] <archive path> <output path>\n"
                 "\n"
                 "BASIC OPTIONS\n"
                 "-level=N          Compress at level N (default 5). Higher levels are slower\n"
				 "                   and use more memory, but provide higher ratios\n"
                 "-threads=N        Use N threads for compression or decompression.\n"
				 "                  Increases memory usage. (default as many as system memory allows)\n"
				 "-pass=password    Encrypt or decrypt the archive using the given password\n"
				 "\n"
				 "ADVANCED OPTIONS\n"
				 "These options will override whathever the selected level uses by default\n"
				 "--dedup-log=N     Amount of memory to be used by deduplicator, about 2048*2^N bytes.\n"
				 "                  Setting N to 0 disables deduplication\n"
				 "--block-log=N     Divide input into blocks of size 2^N bytes. Higher sizes increase\n"
				 "                   memory and compression.\n"
				 "--disable-solid-block\n"
				 "--disable-preprocessor\n";
}

int main(int argc, char* argv[])
{
    if (argc == 1) {
        print_help();
        return 0;
    }

	bool actionCompression;
	if (argv[1][0] == 'a')
		actionCompression = true;
	else if (argv[1][0] == 'x')
		actionCompression = false;
	else {
		std::cout << "Invalid parameter " << argv[1];
		return -1;
	}

	int argi = 2;
	int level = 5;
	int threads = 0;
	std::string password;
	int dedupLog = -1;
	int blockLog = -1;
	bool useSolidBlock = true;
	bool usePreprocessor = true;
	for (; argi < argc; argi++) {
		if (argv[argi][0] != '-')
			break;

		try {
			if (strncmp(argv[argi], "-level=", 7) == 0 && argv[argi][7] >= '0' && argv[argi][7] <= '9')
				level = argv[argi][7] - '0';
			else if (strncmp(argv[argi], "-threads=", 9) == 0) 
				threads = std::stoi(argv[argi] + 9);
			else if (strncmp(argv[argi], "-pass=", 6) == 0)
				password = argv[argi] + 6;
			else if (strncmp(argv[argi], "--dedup-log=", 12) == 0)
				dedupLog = std::stoi(argv[argi] + 12);
			else if (strncmp(argv[argi], "--block-log=", 12) == 0) 
				blockLog = std::stoi(argv[argi] + 12);
			else if (strcmp(argv[argi], "--disable-solid-block") == 0)
				useSolidBlock = false;
			else if (strcmp(argv[argi], "--disable-preprocessor") == 0)
				usePreprocessor = false;
			else {
				std::cout << "Invalid parameter " << argv[argi];
				return -1;
			}
		}
		//Error from std::stoi
		catch (...) {
			std::cout << "Invalid parameter " << argv[argi];
			return -1;
		}
	}

	if (argc - argi < 2) {
		std::cout << "Missing parameters";
		return -1;
	}

	std::string archivePath = argv[argi];
	argi++;

	std::vector<std::string> elementPaths;
	for (; argi < argc; argi++)
		elementPaths.push_back(argv[argi]);

	if (actionCompression) {
		archiver::Parameters parameters = DEFAULT_PARAMETERS[level];
		if (!password.empty())
			parameters.codecNameList.push_back("aes256");
		parameters.password = password;
		parameters.threads = threads;
		if (dedupLog >= 0)
			parameters.deduplicationMemoryLog = dedupLog;
		if (blockLog >= 0)
			parameters.maxBlockSize = 1 << blockLog;
		parameters.useSolidBlock = useSolidBlock;
		if (!usePreprocessor)
			parameters.codecNameList.erase(parameters.codecNameList.begin());

		if (parameters.threads == 0) {
			parameters.threads = std::thread::hardware_concurrency() + 1;
			size_t memory;
			do {
				parameters.threads--;
				memory = archiver::estimate_memory(parameters);
			} while (parameters.threads > 1 && memory > get_available_memory());
		}

		MyArchiveCallback callbacks;
		int error = archiver::create_archive(elementPaths, archivePath, parameters, &callbacks);
		if (error) {
			std::cout << "\nERROR: " << get_error_message(error);
			return -1;
		}
	}
	else {
		int isEncrypted = archiver::is_archive_encrypted(archivePath);
		if (isEncrypted < 0) {
			std::cout << "\nERROR: " << get_error_message(isEncrypted);
			return -1;
		}
		if (isEncrypted && password.empty()) {
			std::cout << "Archive is encrypted, but no password was provided";
			return -1;
		}

		archiver::Parameters parameters;
		parameters.threads = threads == 0 ? 2 : threads;
		parameters.password = std::string();

		MyArchiveCallback callbacks;
		int error = archiver::extract_archive(archivePath, elementPaths[0], parameters, &callbacks);
		if (error) {
			std::cout << "\nERROR: " << get_error_message(error);
			return -1;
		}
	}
}
