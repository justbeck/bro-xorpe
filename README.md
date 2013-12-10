bro-xorpe
=========

My first try at writing a Bro script to detect XOR'd Windows executable files over on the wire. 

## Files

Here's a description of the files in this repo:

- xorpe.bro - Bro script to detect XOR'd binaries
- bintools.bro - Simulates bitwise XOR with lookup table
- examples/sample_traffic.pcap - A PCAP containing the download of an XOR'd PE file and some web browsing traffic
- examples/xor_file.py - Python script to (de)XOR any file
