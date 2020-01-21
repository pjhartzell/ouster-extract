# ouster-extract
## Description
Converts Ouster raw data in PCAP files to 3D points and saves them to LAS file(s). If you compile the command line executable, it takes three arguments:
1. PCAP filepath.
2. Intrinsic angle filepath (JSON format file).
3. Number of data packets to process at a time (chunk size). A value less than 1 will attempt to load and process the entire file in one go.

## Dependencies:
- winpcap
- json.hpp, a header only JSON library from https://github.com/nlohmann/json/releases
- pdal (a conda installation is sufficient)
