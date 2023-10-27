---
layout: post
title:  "Top 60 Compression Methods(RTC0021)"
author: redteamrecipe
categories: [ tutorial ]
tags: [red, blue]
image: assets/images/top60-compress.png
description: "Top 60 Compression Methods"
featured: true
hidden: true
rating: 4.5
---






# Compression Methods

| ID  | Compression Method        | Description                                                                                        | Best For                                                  |
| --- | ------------------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| 1   | ZIP                       | Widely used for compressing files, supported by WinZip and 7-Zip.                                  | General files                                             |
| 2   | RAR                       | A proprietary archive file format that supports data compression. Used primarily by WinRAR.        | Archiving, general files                                  |
| 3   | gzip                      | A software application based on the DEFLATE algorithm, primarily used in GNU systems.              | Text, web, UNIX files                                     |
| 4   | bzip2                     | High-compression file archiver.                                                                    | Text, source code                                         |
| 5   | LZMA                      | Known for a high compression ratio, supported by 7-Zip and LZMA SDK.                               | General files                                             |
| 6   | LZ77                      | A universal lossless data compression algorithm utilized by many tools, e.g., zlib.                | Text, general data                                        |
| 7   | Zstandard (zstd)          | Real-time compression algorithm, developed by Facebook.                                            | Real-time applications                                    |
| 8   | Brotli                    | Compression algorithm developed by Google, primarily for web fonts and HTTP compression.           | Web content                                               |
| 9   | DEFLATE                   | Lossless data compression algorithm used in zlib.                                                  | PNG images, web content                                   |
| 10  | LZW                       | Common in GIF format and the compress command in UNIX.                                             | Graphics (GIF)                                            |
| 11  | PAQ                       | A series of archivers with high compression ratios but slower speeds.                              | Archiving                                                 |
| 12  | xz                        | Uses the LZMA2 compression algorithm, great for distributing software packages.                    | Software packages                                         |
| 13  | LZO                       | Emphasizes speed over compression ratio.                                                           | Fast real-time compression                                |
| 14  | LZ4                       | Known for its extremely fast compression and decompression.                                        | Real-time applications                                    |
| 15  | Snappy                    | Developed by Google, prioritizes speed.                                                            | Large-scale data storage                                  |
| 16  | FLAC                      | Lossless audio codec.                                                                              | Audio files                                               |
| 17  | ALAC                      | Apple's lossless audio codec.                                                                      | Audio files on Apple devices                              |
| 18  | JPEG                      | Widely used lossy compression for digital images. Many tools available, like libjpeg and JPEGView. | Photographs                                               |
| 19  | JPEG 2000                 | An improved version of JPEG with better compression and quality.                                   | Digital cinema, medical imaging                           |
| 20  | PNG                       | Lossless compression for images. Ideal for web graphics with transparency.                         | Web graphics, images                                      |
| 21  | TIFF                      | Versatile format supporting various compression algorithms.                                        | High-quality images                                       |
| 22  | WebP                      | Developed by Google, supports both lossless and lossy compressions.                                | Web images                                                |
| 23  | VP8, VP9                  | Video codecs developed by Google, used in WebM format.                                             | Online streaming videos                                   |
| 24  | H.264/AVC                 | Widely used video compression standard. Supported by tools like x264 and HandBrake.                | Video streaming, broadcasting                             |
| 25  | H.265/HEVC                | Successor to H.264, offers better compression at the same quality level.                           | Ultra-HD video, streaming                                 |
| 26  | Opus                      | Audio codec designed for the internet, excellent at low bitrates.                                  | Internet audio, VoIP                                      |
| 27  | Vorbis                    | Open audio compression format under the Ogg format.                                                | Audio streaming                                           |
| 28  | WAVPACK                   | Hybrid lossless audio codec.                                                                       | High-fidelity audio archiving                             |
| 29  | APE                       | Monkey's Audio is a fast and powerful lossless audio compressor.                                   | Lossless audio compression                                |
| 30  | TAR                       | Archive format commonly used in UNIX environments. No compression, just grouping.                  | Grouping files on UNIX                                    |
| 31  | CAB                       | Microsoft's cabinet compressed archive format.                                                     | Windows installations, software packages                  |
| 32  | 7z                        | High-compression format supported by 7-Zip software.                                               | General archiving, high compression                       |
| 33  | SquashFS                  | Compressed read-only file system for Linux.                                                        | Embedded systems, Live CDs                                |
| 34  | CPIO                      | Old UNIX archiving tool.                                                                           | Archiving on UNIX                                         |
| 35  | ARJ                       | File archiver for DOS.                                                                             | Old DOS archives                                          |
| 36  | StuffIt                   | Popular on Mac OS before the rise of ZIP.                                                          | Old Mac OS archives                                       |
| 37  | ACE                       | Old but efficient compression tool, less popular nowadays.                                         | Legacy archives                                           |
| 38  | LHA/LZH                   | A compression algorithm commonly used in Japan.                                                    | Old Japanese archives                                     |
| 39  | JAR                       | Java Archive, used to package Java classes and associated metadata & resources.                    | Java applications                                         |
| 40  | Pack200                   | Java compression tool, part of the SDK, good for compressing Java archives.                        | Java archives (JAR)                                       |
| 41  | MTF                       | Microsoft Tape Format used for backups.                                                            | Windows backups                                           |
| 42  | ARC                       | Old archival format, predates ZIP. Supported by ARC and FreeARC.                                   | Legacy archives                                           |
| 43  | PAR2                      | Used to check and recover missing data for multi-part archives.                                    | Usenet archives, file recovery                            |
| 44  | ZPAQ                      | Highly efficient archiver with journaling capability.                                              | Efficient archiving                                       |
| 45  | PVM                       | Parallel Virtual Machine, not strictly compression but a middleware for parallel computing.        | Parallel computing (not compression)                      |
| 46  | HuffYUV                   | A very fast, lossless video codec.                                                                 | Lossless video compression                                |
| 47  | Apple ProRes              | Professional video codec developed by Apple.                                                       | Video editing on Apple devices                            |
| 48  | Cinepak                   | Early video codec by SuperMac Technologies, once common in early CD-ROM video games.               | Legacy video files                                        |
| 49  | Sorenson                  | Family of video codecs that were popular in early web video.                                       | Early web videos                                          |
| 50  | Indeo                     | Video codec developed by Intel.                                                                    | Legacy video applications                                 |
| 51  | LZ78                      | Successor to LZ77, basis for several other algorithms.                                             | General-purpose text compression.                         |
| 52  | BWT                       | Data transformation that prepares data for better compression.                                     | Full-text database indexes and large text datasets.       |
| 53  | Delta Encoding            | Represents data as differences between sequential data rather than complete files.                 | Version control databases and sequential log files.       |
| 54  | Dictionary Encoding       | Replaces repeated occurrences of data with references to a set dictionary.                         | Databases with redundant textual data.                    |
| 55  | Columnar Compression      | Compression method where data is stored as columns rather than rows, ideal for modern databases.   | Columnar databases, analytics databases.                  |
| 56  | Run-Length Encoding (RLE) | Represents sequences of identical bytes by a single byte and a count.                              | Simple textual databases with lots of repeated sequences. |
|  57   |Prefix Encoding |Represents common prefixes once to save space.|Databases with hierarchical textual data, like XML.                                                           |


![compress methods](/assets/images/compress-methods.png)



### SquashFS

```
mksquashfs mydir mydir.sqsh
```

### Run-Length Encoding (RLE)

```
def rle_encode(data):
    encoding = []
    prev_char = data[0]
    count = 1

    for char in data[1:]:
        if char == prev_char:
            count += 1
        else:
            encoding.append((prev_char, count))
            count = 1
            prev_char = char

    encoding.append((prev_char, count))
    return encoding

def rle_decode(data):
    return ''.join([char * count for char, count in data])

# Test
data = "AAABBBCCDAA"
encoded = rle_encode(data)
print(encoded) # [('A', 3), ('B', 3), ('C', 2), ('D', 1), ('A', 2)]
print(rle_decode(encoded)) # "AAABBBCCDAA"
```

### Bash

```
compress_rle() {
    input_file="$1"
    output_file="$2"

    prev_char=""
    count=0

    while IFS= read -r -n1 char; do
        if [[ "$char" == "$prev_char" ]]; then
            ((count++))
        else
            if [[ -n "$prev_char" ]]; then
                echo -n "$prev_char$count" >> "$output_file"
            fi
            count=1
            prev_char="$char"
        fi
    done < "$input_file"

    echo -n "$prev_char$count" >> "$output_file"
}

compress_rle "input.txt" "output.rle"
```


### Powershell


```
# Compress a folder using PowerShell
$sourceFolder = "C:\path\to\source\folder"
$destinationFile = "C:\path\to\destination\archive.zip"

Compress-Archive -Path $sourceFolder -DestinationPath $destinationFile
```


### 7zip


```
7z a output_archive_name.7z path_to_directory_or_file
```

or

```
7z a -t7z -v50m myarchive.7z C:\path\to\my\folder
```

or

```
7z a -t7z -v50m myarchive.7z C:\path\to\my\folder
```

### rar


```
rar a -v100m output_archive_name.rar path_to_directory_or_file
```

or

```
rar a -v50m myarchive.rar C:\path\to\my\folder
```



### zlib

```
import zlib
import sys

def compress_and_slice(input_file, output_base, slice_size):
    with open(input_file, 'rb') as f:
        data = f.read()
        compressed = zlib.compress(data)
        
        num_slices = (len(compressed) // slice_size) + (1 if len(compressed) % slice_size else 0)
        for i in range(num_slices):
            start = i * slice_size
            end = start + slice_size
            with open(f"{output_base}.{i:03}", 'wb') as out_f:
                out_f.write(compressed[start:end])

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python script_name.py input_file output_base slice_size_in_bytes")
        sys.exit(1)

    input_file = sys.argv[1]
    output_base = sys.argv[2]
    slice_size = int(sys.argv[3])

    compress_and_slice(input_file, output_base, slice_size)
```

python script_name.py input.txt compressed 100000

### tar

```
tar czvf - path_to_directory_or_file | split -b 100M - compressed.tar.gz.
```

or

```
tar cjvf - path_to_directory_or_file | split -b 100M - compressed.tar.bz2.
```
### gz

```
gzip -c input_file > output_file.gz
```

or

```
split -b 100M output_file.gz sliced_output.gz.
```
### Xpress Compression Algorithm

```

```

### MSZIP

```
makecab /D CompressionType=MSZIP input_file output_file.cab
```

or

```
makecab /D CompressionType=MSZIP /D MaxDiskSize=100M input_file output_file.cab
```


### LZMS

```
Dism /Capture-Image /ImageFile:"path_to_output.wim" /CaptureDir:"path_to_input_directory" /Name:"ImageName" /Compress:LZMS
```

### LZ4

https://github.com/lz4/lz4

```
lz4 file
```

or

```
#include "lz4.h"

int main() {
    char original_data[] = "data to be compressed";
    char compressed_data[128];
    char decompressed_data[128];
    
    int compressed_size = LZ4_compress_default(original_data, compressed_data, sizeof(original_data), sizeof(compressed_data));
    int decompressed_size = LZ4_decompress_safe(compressed_data, decompressed_data, compressed_size, sizeof(decompressed_data));
    
    return 0;
}
```


### IPFS

https://github.com/HadessCS/Zhina

### 3DES

encrypts with the  algorithm and a hardcoded key prior to exfiltration

```
7z a -v50m encrypted_slices.7z encrypted.7z
```

and

```
openssl enc -des-ede3-cbc -in myarchive.7z -out encrypted.7z -K yourhardcodedkey -iv yourinitializationvector
```

### LZMA


```
7z a -t7z -m0=lzma myarchive.7z /path/to/your/data
```

and

```
openssl enc -rc4 -in myarchive.7z -out myarchive_encrypted.7z -pass pass:YourPassword
```
### 
compress multiple documents on the DCCC and DNC


### cab


```
makecab C:\path\to\your\sourcefile.ext C:\destination\path\outputfile.cab
```

or 

```
.Set CabinetNameTemplate=outputfile.cab
.Set DiskDirectoryTemplate=C:\destination\path
.Set CompressionType=MSZIP
C:\path\to\file1.ext 
C:\path\to\file2.ext 
```

and run `makecab /F instructions.ddf`

### Snappy

```
snzip inputfile.txt
```

or

```
services.AddSnappyCompressor();
```

https://github.com/mjebrahimi/EasyCompressor

### Zstd

```
zstd inputfile.txt
```

or

```
services.AddZstdCompressor();
```

https://github.com/mjebrahimi/EasyCompressor

### Deflate


```
services.AddDeflateCompressor();
```

https://github.com/mjebrahimi/EasyCompressor
### Brotli

```
services.AddBrotliNetCompressor();
```

https://github.com/mjebrahimi/EasyCompressor
