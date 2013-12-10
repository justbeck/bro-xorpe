bro-xorpe
=========

This is my first try at writing a Bro script. The goal is to be able to detect Windows executables (PE files) XOR'd with arbitrary keys as they go over the wire. 

## Example

I've included `examples/sample_traffic.pcap` which contains the download of an Windows Executable file that's been XOR'd. The script can be called from the command line. I'm using the -C option to ignore invalid TCP checksums:

```
$ bro -C  -r examples/sample_traffic.pcap xorpe.bro 
```

Once bro has processed the PCAP, we can use `bro-cut` to see the file in notice.log:

```
$ bro-cut fuid file_desc msg sub  < notice.log 
FNafFq4QjgnpbFblCe    http://justaplaceholder.s3.amazonaws.com/notabinary.jpg    XOR'd Binary Detected    deadbeefdeaf
```

The XOR key (deadbeefdeaf) is hex-encoded. We can use `examples/xor_file.py` to (de)XOR it:

```
$ python examples/xor_file.py --hex deadbeefdeaf extract-HTTP-FNafFq4QjgnpbFblCe 
XOR'd 114688 bytes. Saved file to:
extract-HTTP-FNafFq4QjgnpbFblCe.xor
```

Using the `file` command we can confirm the file is a Windows executable:

```
$ file extract-HTTP-FNafFq4QjgnpbFblCe.xor
extract-HTTP-FNafFq4QjgnpbFblCe.xor: PE32 executable for MS Windows (GUI) Intel 80386 32-bit
```

## Files

Here's a description of the files in this repo:

- xorpe.bro - Bro script to detect XOR'd binaries
- bintools.bro - Simulates bitwise XOR with lookup table
- examples/sample_traffic.pcap - A PCAP containing the download of an XOR'd PE file and some web browsing traffic
- examples/xor_file.py - Python script to (de)XOR any file

