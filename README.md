# Archiver

A small archiver thing, currently without a name (suggestions are welcome). It is unfinished right now, and current version might not be compatible with future ones.

# How to compile

It is a single cpp file and many header files. You will need a compiler with at least c++17 support, and preferably c++20. With gcc or clang you can use this command:
`clang++ -std=c++17 -O3 ArchiverCLI.cpp -o ArchiverCLI`

# Benchmark

The following benchmarks were performed using the Benchmark.cpp program, compiled on Visual Studio 2022. The system uses Windows 11, a Ryzen 6900HX@3.3GHz, 32GB of DDR5 Ram and an NVMe drive.
To avoid excessive writes to my SSD encoding was done from the SSD to a RAM disk, while decoding was from RAM disk to RAM disk.

VISUAL STUDIO 2019  (3.318.303.841 bytes)
| Command          |     Size      | Enc. Time |   Enc. Mem     | Dec. Time | Dec. Mem      |
| 7z (22.01) -mx1  | 946,358,679   | 21.34     | 102,567,936    | 7.69      | 46,858,240    |
| 7z (22.01) -mx3  | 826,703,785   | 33.78     | 923,598,848    | 7.15      | 431,591,424   |
| 7z (22.01) -mx5  | 691,669,103   | 87.78     | 2,227,494,912  | 7.50      | 1,469,296,640 |
| 7z (22.01) -mx7  | 633,436,817   | 127.73    | 4,220,297,216  | 8.46      | 2,464,956,416 |
| 7z (22.01) -mx9  | 504,995,580   | 166.96    | 6,582,087,680  | 10.36     | 2,271,916,032 |
| rar (6.21) -m1   | 1,068,745,718 | 38.89     | 457,383,936    | 18.05     | 53,358,592    |
| rar (6.21) -m2   | 946,676,689   | 43.41     | 486,838,272    | 18.47     | 53,633,024    |
| rar (6.21) -m3   | 930,686,793   | 63.46     | 487,190,528    | 18.12     | 53,592,064    |
| rar (6.21) -m4   | 928,824,242   | 66.92     | 487,436,288    | 18.33     | 53,522,432    |
| rar (6.21) -m5   | 928,224,955   | 70.15     | 487,436,288    | 18.07     | 53,452,800    |
| archiver -1 (0.3)| 607,409,069   | 5.78      | 231,653,376    | 3.82      | 214,654,976   |
| archiver -3 (0.3)| 535,226,889   | 18.24     | 375,865,344    | 3.64      | 376,975,360   |
| archiver -5 (0.3)| 481,905,234   | 31.13     | 839,770,112    | 3.52      | 778,678,272   |
| archiver -7 (0.3)| 438,620,146   | 111.46    | 2,353,844,224  | 3.54      | 1,276,014,592 |
| archiver -9 (0.3)| 414,681,287   | 247.46    | 10,314,358,784 | 3.59      | 1,980,465,152 |

GARRY'S MOD  (4.456.090.746 bytes)
| Command          |     Size      | Enc. Time |   Peak Mem     | Dec. Time | Dec. Mem      |
| 7z (22.01) -mx1  | 2,211,140,074 | 40.39     | 90,476,544     | 7.79      | 45,821,952    |
| 7z (22.01) -mx3  | 2,107,417,177 | 75.72     | 991,232,000    | 7.56      | 532,279,296   |
| 7z (22.01) -mx5  | 1,948,700,331 | 116.23    | 2,463,039,488  | 7.47      | 1,885,261,824 |
| 7z (22.01) -mx7  | 1,931,948,246 | 151.09    | 4,770,779,136  | 9.44      | 3,369,881,600 |
| 7z (22.01) -mx9  | 1,918,004,627 | 191.26    | 8,432,193,536  | 11.68     | 6,126,231,552 |
| rar (6.21) -m1   | 2,194,777,860 | 44.17     | 451,514,368    | 18.23     | 53,760,000    |
| rar (6.21) -m2   | 2,041,036,218 | 88.06     | 481,722,368    | 21.23     | 54,153,216    |
| rar (6.21) -m3   | 2,022,774,162 | 102.00    | 481,398,784    | 21.10     | 54,136,832    |
| rar (6.21) -m4   | 2,019,393,649 | 124.1     | 481,435,648    | 20.99     | 54,173,696    |
| rar (6.21) -m5   | 2,018,031,365 | 141.73    | 481,792,000    | 21.12     | 54,198,272    |
| archiver -1 (0.3)| 1,913,445,871 | 16.29     | 220,495,872    | 7.58      | 280,412,160   |
| archiver -3 (0.3)| 1,831,409,661 | 42.50     | 480,231,424    | 6.91      | 504,524,800   |
| archiver -5 (0.3)| 1,753,493,633 | 81.66     | 1,086,169,088  | 7.04      | 961,372,160   |
| archiver -7 (0.3)| 1,712,787,899 | 282.01    | 2,980,376,576  | 7.16      | 1,916,383,232 |
| archiver -9 (0.3)| 1,670,172,426 | 664.58    | 11,721,883,648 | 7.97      | 2,734,149,632 |

# Libraries used

The following libraries are used inside this project. 
Picosha256: https://github.com/okdshin/PicoSHA2/tree/master
XXHash: https://github.com/Cyan4973/xxHash
CRCpp: https://github.com/d-bahr/CRCpp
TinyAES: https://github.com/kokke/tiny-AES-c
