# Simple program written in c++ using WinAPI to turn plaintext into base64 and decode base64 data into plaintext.

## Compilation

Used Visual Studio 2022 to develop this program.
Make sure to add `ws2_32.lib` and `crypt32.lib` to Additional Dependencies under project Properties -> Linker -> Input.

and finally compile the program into x64 binary.

## Usage

```bash
Usage : base64.exe [options]

Options

-i [path_to_file]        : Input data from a file.

-iS [input_data]         : Input data from command line.

-o [output_file_name]    : Output file name.

-oS                      : Output will be printed on screen.

-e                       : To encode the data to base64.

-d                       : To decode the data from base64.
```

### Examples

Encode the text "Hello, World!" into base64.

```bash
base64.exe -iS "Hello, World!" -oS -e
```

output will be

```bash
[+] Base64 encoded data size: 37 bytes.
[+] Encoded data : SABlAGwAbABvACwAIABXAG8AcgBsAGQAIQA=
```

Decode the text "SABlAGwAbABvACwAIABXAG8AcgBsAGQAIQA=" into plaintext.

```bash
base64.exe -iS "SABlAGwAbABvACwAIABXAG8AcgBsAGQAIQA=" -oS -d
```

output will be

```bash
[+] Decoded data size : 26 bytes.
[+] Decoded data : Hello, World!
```

Encode the file name `helloworld.txt` into base64. and write into `helloworld.encoded.txt` named file.

```bash
base64.exe -i helloworld.txt -o helloworld.encoded.txt -e
```

output will be

```bash
[+] Opened the file "helloworld.txt" successfully.
[+] Size of the file : 13 bytes.
[+] Read bytes from the input file : 13 bytes.
[+] Base64 encoded data size: 21 bytes.
[+] Written bytes to file "helloworld.encoded.txt": 40 bytes.
[+] Written size and actual size match.
[+] Successfully writen the Base64 encoded data to file.
```

Decode the file name `helloworld.encoded.txt` into plaintext. and write into `helloworld.decoded.txt` named file.

```bash
base64.exe -i helloworld.encoded.txt -o helloworld.decoded.txt -d
```

output will be

```bash
[+] Opened the file "helloworld.encoded.txt" successfully.
[+] Size of the file : 40 bytes.
[+] Read bytes from the input file : 40 bytes.
[+] Decoded data size : 14 bytes.
[+] Written bytes to file "helloworld.decoded.txt": 14 bytes.
[+] Written size and actual size match.
[+] Successfully writen the Base64 encoded data to file.
```

### Enjoy!
