# Archiver

A small archiver thing, currently without a name (suggestions are welcome). It is unfinished right now, and current version might not be compatible with future ones.

# How to compile

It is a single cpp file and many header files. You will need a compiler with at least c++17 support, and preferably c++20. With gcc or clang you can use this command:
`g++ -std=c++17 -O3 ArchiverCLI.cpp -o ArchiverCLI`

# Benchmark

The following benchmarks were performed using the Benchmark.cpp program, compiled on Visual Studio 2022. The system uses Windows 11, a Ryzen 6900HX@3.3GHz, 32GB of DDR5 Ram and an NVMe drive.

VISUAL STUDIO 2019  (3.318.303.841 bytes)
| Command          |     Size      |  Time   |   Peak Mem     |
| ---------------  | ------------- | ------- | -------------- |
| 7z (22.01) -mx1  | 946,358,679   | 21.34   | 102,567,936    |
| 7z (22.01) -mx5  | 691,669,103   | 84.18   | 2,227,613,696  |
| 7z (22.01) -mx9  | 504,995,580   | 152.75  | 6,581,927,936  |
| rar (6.21) -m1   | 1,068,745,718 | 37.55   | 456,945,664    |
| rar (6.21) -m3   | 930,686,793   | 63.78   | 486,862,848    |
| rar (6.21) -m5   | 928,224,955   | 68.32   | 486,891,520    |
| archiver -1 (0.2)| 599,918,577   | 10.46   | 198,758,400    |
| archiver -5 (0.2)| 473,045,604   | 38.62   | 961,536,000    |
| archiver -9 (0.2)| 410,074,804   | 288.63  | 15,469,821,952 |

GARRY'S MOD  (4.456.090.746 bytes)
| Command          |     Size      |  Time   |   Peak Mem     |
| ---------------  | ------------- | ------- | -------------- |
| 7z (22.01) -mx1  | 2,211,140,074 | 43.67   | 90,488,832     |
| 7z (22.01) -mx5  | 1,948,700,331 | 113.85  | 2,462,396,416  |
| 7z (22.01) -mx9  | 1,918,004,627 | 181.97  | 8,393,986,048  |
| rar (6.21) -m1   | 2,194,777,860 | 42.49   | 451,186,688    |
| rar (6.21) -m3   | 2,022,774,162 | 100.48  | 481,951,744    |
| rar (6.21) -m5   | 2,018,031,365 | 139.92  | 481,898,496    |
| archiver -1 (0.2)| 1,910,701,050 | 22.51   | 214,159,360    |
| archiver -5 (0.2)| 1,752,304,981 | 90.43   | 1,068,584,960  |
| archiver -9 (0.2)| 1,667,598,063 | 718.51  | 14,441,230,336 |

# Libraries used

The following libraries are used inside this project. 
Picosha256: https://github.com/okdshin/PicoSHA2/tree/master
XXHash: https://github.com/Cyan4973/xxHash
CRCpp: https://github.com/d-bahr/CRCpp
TinyAES: https://github.com/kokke/tiny-AES-c
