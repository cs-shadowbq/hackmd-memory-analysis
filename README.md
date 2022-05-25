# Working with Application Memory Dumps (MINIDUMPS)

[![hackmd-github-sync-badge](https://hackmd.io/zBbmriwURj6LjFeR0Rma1A/badge)](https://hackmd.io/zBbmriwURj6LjFeR0Rma1A)


This example dump was pulled from the `LiteAgent.exe` process from the running instance in AWS from a Windows Server 2019 using CrowdStrike Falcon Real Time Response `memdump`.

## Table of contents

- [Working with Application Memory Dumps (MINIDUMPS)](#working-with-application-memory-dumps-minidumps)
  - [What Are Mini Dumps](#what-are-mini-dumps)
  - [Application Dump - MDMP (minidump)](#application-dump---mdmp-minidump)
    - [Magic Number](#magic-number)
  - [System](#system)
    - [Aquisition via RTR - Crowdstrike](#aquisition-via-rtr---crowdstrike)
  - [Analysis Tools](#analysis-tools)
    - [Linux - Dump to Unicode with Strings](#linux---dump-to-unicode-with-strings)
    - [Yara](#yara)
    - [`minidump.py` Analysis](#minidumppy-analysis)
    - [WinDbg - UserMode Analysis](#windbg---usermode-analysis)
    - [Google BreakPad](#google-breakpad)
    - [Rust-minidump](#rust-minidump)
    - [MinidumpExplorer](#minidumpexplorer)
    - [Custom Code - Kaitai](#custom-code---kaitai)
  - [Dead Ends](#dead-ends)
    - [Immunity Debugger (Unsupported)](#immunity-debugger-unsupported)
    - [Volatility (Broken)](#volatility-broken)
  - [Training](#training)
    - [Blog References](#blog-references)
    - [Videos](#videos)
    - [Minidump Creation Code References](#minidump-creation-code-references)

## What Are Mini Dumps

A process dump is often a much smaller file(MBs) than a complete memory dump (GBs), it is focused on one process. 

Actually there are many different types of MINIDUMPS. They all stem from the documented process on MSDN. These dumps can be created from tools such as Microsoft's `userdump.exe`, process-hackers, etc.

## Application Dump - MDMP (minidump)

### Magic Number

![](https://i.imgur.com/E2I0I0Q.png)

https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_type
```
typedef enum _MINIDUMP_TYPE {
  MiniDumpNormal = 0x00000000,
  MiniDumpWithDataSegs = 0x00000001,
  MiniDumpWithFullMemory = 0x00000002,
  MiniDumpWithHandleData = 0x00000004,
  MiniDumpFilterMemory = 0x00000008,
  MiniDumpScanMemory = 0x00000010,
  MiniDumpWithUnloadedModules = 0x00000020,
  MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
  MiniDumpFilterModulePaths = 0x00000080,
  MiniDumpWithProcessThreadData = 0x00000100,
  MiniDumpWithPrivateReadWriteMemory = 0x00000200,
  MiniDumpWithoutOptionalData = 0x00000400,
  MiniDumpWithFullMemoryInfo = 0x00000800,
  MiniDumpWithThreadInfo = 0x00001000,
  MiniDumpWithCodeSegs = 0x00002000,
  MiniDumpWithoutAuxiliaryState = 0x00004000,
  MiniDumpWithFullAuxiliaryState = 0x00008000,
  MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
  MiniDumpIgnoreInaccessibleMemory = 0x00020000,
  MiniDumpWithTokenInformation = 0x00040000,
  MiniDumpWithModuleHeaders = 0x00080000,
  MiniDumpFilterTriage = 0x00100000,
  MiniDumpWithAvxXStateContext = 0x00200000,
  MiniDumpWithIptTrace = 0x00400000,
  MiniDumpScanInaccessiblePartialPages = 0x00800000,
  MiniDumpFilterWriteCombinedMemory,
  MiniDumpValidTypeFlags = 0x01ffffff
} MINIDUMP_TYPE;
```

![](https://i.imgur.com/w5OcAn6.png)


## System in Example

Here is the information about the system this PID 2828 is pulled from.

![](https://i.imgur.com/gRhhO2x.png)


### Aquisition of MINIDUMP via RTR - Crowdstrike 

In this example, `memdump 2828` I used CrowdStrike `memdump` collect the small process only sector memory aquistion.

![](https://i.imgur.com/tpGsT3V.png)

The file from crowdstrike comes as

`Pid-2828.dmp.7z` - 7zip encrypted with `infected` in a containing folder


## Analysis Tools


### Linux - Dump to Unicode with Strings

Dumping Strings to UNICODE

```shell=
bash> strings -a -t d -r l Pid-2828.dmp > String_unicode.txt
```

usecase: `memdump` a hollowed process, you can just run 'strings' and possibly identify a C2 callback/ip/domain

### Yara 

Using yara looking for C2 ip callback (172.17.0.21) strings in a hollowed process Pid-6624 after migration from meterpeter 

![](https://i.imgur.com/4EmKh4H.png)

example sigs: [tools/yara-sigs/ip.yar](tools/yara-sigs/ip.yar)

### `minidump.py` Analysis

https://pastebin.com/raw/AZD1HCty

Original Blog: http://moyix.blogspot.com/2008/05/parsing-windows-minidumps.html

![](https://i.imgur.com/L3IbKmN.png)


### WinDbg - UserMode Analysis

https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools

#### Opening the files

![](https://i.imgur.com/NNDanKC.png)


#### Analyze the memory dump

`!analyze -v` - Execute the analyze tool.

![](https://i.imgur.com/VOg6IsW.png)


### Google BreakPad

https://www.chromium.org/developers/crash-reports/#working-with-minidumps

`minidump_stackwalk` prints the stack trace for all of the threads in the minidump. Note that without Breakpad symbol files, placed in a special directory structure, this will not symbolize the stack. It will merely print the %EIP, %EBP, and %ESP (or the x64 equivalent) for each frame and the code module in which the frame resides. `minidump_dump` outputs the stack memory for each thread as a hexadecimal string.


#### Compiling BreakPad

Google Has BreakPad can analyse minidumps too. You need to add the lss linux call support. 

```shell
mkdir sandbox && cd sandbox
git clone https://github.com/google/breakpad.git
cd breakpad
git clone https://chromium.googlesource.com/linux-syscall-support src/third_party/lss
./configure
make
```

#### Running Breakpad

The command(s) to run would be `minidump_stackwalk` and `minidump_dump`


```shell
ec2-user@kali:~/sandbox/breakpad/src/processor$ ./minidump_stackwalk ~/Pid-2828.dmp 2>/dev/null
Operating system: Windows NT
                  10.0.17763
CPU: amd64
     family 6 model 79 stepping 1
     2 CPUs

GPU: UNKNOWN

No crash
Process uptime: 3765103 seconds

Thread 0
 0  ntdll.dll + 0x9fa74
    rax = 0x0000000000000004   rdx = 0x0000000000000000
    rcx = 0x0000000000000114   rbx = 0x0000000000000000
    rsi = 0x0000000000000000   rdi = 0x0000000000000114
    rbp = 0x000000a1dd2ffaf0   rsp = 0x000000a1dd2ff808
     r8 = 0x00007ff8ce7f14d2    r9 = 0x00007ff8cdf40000
    r10 = 0x0000000000000000   r11 = 0x00007ff8cdf4ad00
    r12 = 0x000000a1dd2ffa50   r13 = 0x000000a1dd2ffa70
    r14 = 0x0000000000000114   r15 = 0x000002709a463b50
    rip = 0x00007ff8ceaafa74
    Found by: given as instruction pointer in context

Thread 1
 0  ntdll.dll + 0xa0544
    rax = 0x000000000000005b   rdx = 0x000000a1dd5ff970
    rcx = 0x0000000000000003   rbx = 0x0000000000000003
    rsi = 0x0000000000000001   rdi = 0x0000000000000003
    rbp = 0x0000000000000000   rsp = 0x000000a1dd5ff618
     r8 = 0xffffffffffffffff    r9 = 0x0000000000000130
    r10 = 0x0000000000000000   r11 = 0x0000000000000246
    r12 = 0x000000000000ea60   r13 = 0x000000a1dd5ff970
    r14 = 0x000000a1dd5ff670   r15 = 0x0000000000000000
    rip = 0x00007ff8ceab0544
    Found by: given as instruction pointer in context

Loaded modules:
0x7ff70bb90000 - 0x7ff70bbfffff  LiteAgent.exe  8.2.7.5  (main)
0x7ff8ca790000 - 0x7ff8ca7b8fff  devobj.dll  10.0.17763.2145
0x7ff8ca9f0000 - 0x7ff8caa4cfff  powrprof.dll  10.0.17763.1
0x7ff8caa80000 - 0x7ff8caa91fff  msasn1.dll  10.0.17763.1
0x7ff8caaa0000 - 0x7ff8cac94fff  crypt32.dll  10.0.17763.2268
0x7ff8caca0000 - 0x7ff8cae3bfff  gdi32full.dll  10.0.17763.2452
0x7ff8cb5b0000 - 0x7ff8cb6a9fff  ucrtbase.dll  10.0.17763.1490
0x7ff8cb6b0000 - 0x7ff8cb6d5fff  bcrypt.dll  10.0.17763.2090
0x7ff8cb6e0000 - 0x7ff8cb973fff  KERNELBASE.dll  10.0.17763.2686
0x7ff8cba30000 - 0x7ff8cba90fff  wintrust.dll  10.0.17763.2510
0x7ff8cbaa0000 - 0x7ff8cbae9fff  cfgmgr32.dll  10.0.17763.1
0x7ff8cbaf0000 - 0x7ff8cbb0ffff  win32u.dll  10.0.17763.1
0x7ff8cbba0000 - 0x7ff8cbc3ffff  msvcp_win.dll  10.0.17763.348
0x7ff8cbc40000 - 0x7ff8cbc68fff  gdi32.dll  10.0.17763.1697
0x7ff8cbc90000 - 0x7ff8cc105fff  setupapi.dll  10.0.17763.404
0x7ff8cc240000 - 0x7ff8cc3d6fff  user32.dll  10.0.17763.2213
0x7ff8cc580000 - 0x7ff8cc626fff  advapi32.dll  10.0.17763.2452
0x7ff8cc630000 - 0x7ff8cc6e3fff  kernel32.dll  10.0.17763.2686
0x7ff8cde00000 - 0x7ff8cde9dfff  msvcrt.dll  7.0.17763.475
0x7ff8cdf40000 - 0x7ff8ce05cfff  rpcrt4.dll  10.0.17763.2452
0x7ff8ce770000 - 0x7ff8ce80efff  sechost.dll  10.0.17763.2686
0x7ff8cea10000 - 0x7ff8cebfcfff  ntdll.dll  10.0.17763.2686  (WARNING: No symbols, ntdll.pdb, 54935064E481ADB0A9F43CEC5BF5DA651)
```

`minidump_dump`

This command will create a full hex dump and analysis stack..

```
ec2-user@kali:~/sandbox/breakpad/src/processor$ ./minidump_dump -x ~/Pid-2828.dmp 2>/dev/null
MDRawHeader
  signature            = 0x504d444d
  version              = 0xa063a793
  stream_count         = 11
  stream_directory_rva = 0x20
  checksum             = 0x0
  time_date_stamp      = 0x6285bfce 2022-05-19 03:55:58
  flags                = 0x2

mDirectory[0]
MDRawDirectory
  stream_type        = 0x3 (MD_THREAD_LIST_STREAM)
  location.data_size = 100
  location.rva       = 0x630

[..snip..]
```

### Rust-minidump 

This project provides type definitions, parsing, and analysis for the minidump file format.

It's fairly heavily modeled after Google Breakpad for historical reasons, but there is no fundamental interoperability requirement between the two beyond the fact that they fundamentally handle the same inputs. 

https://github.com/rust-minidump/rust-minidump

This is specifically designed to provide a compatible interface to mozilla's `minidump-stackwalk` which is itself similar to google-breakpad's `minidump-stackwalk`.

### MinidumpExplorer

View stream data contained within a minidump

https://github.com/GregTheDev/MinidumpExplorer

![](https://i.imgur.com/bibX2Bh.png)


### Custom Code - Kaitai

https://formats.kaitai.io/windows_minidump/index.html

KS implementation details License: CC0-1.0

The file itself is a container, which contains a number of typed "streams", which contain some data according to its type attribute.

The has formal specification of Windows MiniDump using Kaitai Struct. This specification can be automatically translated into a variety of programming languages to get a parsing library.

Supported Languages:

    C++11/STL
    C++98/STL
    C#
    GraphViz
    Java
    JavaScript
    Lua
    Nim
    Perl
    PHP
    Python
    Ruby
    
Example using the `ruby` lang `kaitai-struct` gem: 

![](https://i.imgur.com/kAzhjbo.png)

    
## Dead Ends

### Immunity Debugger (Unsupported)

Immunity Debugger doesn't support loading of minidumps directly.

### Volatility (Broken)

Volatility (`vol.py`) can't handle just app space memory.

* Feature/Bug Request: https://github.com/volatilityfoundation/volatility/issues/443

Try to open an MDMP in `Vol.py` will cause an error as the Kernel pagememory is not present.

Note both image or crashdump 

```shell
$> volatility -f Pid-2828.dmp --profile=Win10x64_10586 crashinfo
Volatility Foundation Volatility Framework 2.6
ERROR   : volatility.debug    : Memory Image could not be identified as ['WindowsCrashDumpSpace32', 'WindowsCrashDumpSpace64', 'WindowsCrashDumpSpace64BitMap']
```

```shell=
$>volatility -f Pid-2828.dmp --profile=Win10x64_10586 imageinfo
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : No suggestion (Instantiated with no profile)
                     AS Layer1 : FileAddressSpace (/home/ec2-user/Pid-2828.dmp)
                      PAE type : No PAE

```

Same reason here.. (regarding v3)

![](https://i.imgur.com/2RMtXzC.png)

## Training 

### Blog References

* Using minidumpexplorer - https://gregsplaceontheweb.wordpress.com/
* Analysis of a minidump - https://diablohorn.com/2015/09/04/discovering-the-secrets-of-a-pageant-minidump/
* Use of Minidump in lsass (mimikatz) - https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/
* minidump of lsass hits by AVs - https://www.bussink.net/lsass-minidump-file-seen-as-malicious-by-mcafee-av/

### Videos 

![](https://i.imgur.com/cc0110o.png)

https://www.youtube.com/watch?v=pKQ_Io_8lTc

### Minidump Creation Code References

Note that the minidump module does not need administrative privileges to work properly which means that a normal user can run this module. To dump another user's process, you must be running from an elevated prompt (e.g to dump lsass).


* MSDN Dump - https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump

  * PowerShellMafia/PowerSploit (Calls native minidumpwritedump) - https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1

    * Empire (wraps PSM) - https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/powershell/collection/minidump.yaml

  * Metasploit (Calls native minidumpwritedump)  - https://github.com/rapid7/metasploit-framework/blob/master//modules/post/windows/gather/memory_dump.rb#L109

* procdump - Windows powershell tools - https://docs.microsoft.com/en-us/sysinternals/downloads/procdump

    * HAFNIUM Styled- Use of procdump / LotL in wild - https://www.rapid7.com/blog/post/2021/03/23/defending-against-the-zero-day-analyzing-attacker-behavior-post-exploitation-of-microsoft-exchange/