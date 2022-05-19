# Working with Application Memory Dumps



This example dump was pulled from the `LiteAgent.exe` process from the running instance in AWS from a Windows Server 2019. 

## System

![](https://i.imgur.com/gRhhO2x.png)


## Aquisition via RTR - Crowdstrike 

`memdump 2828`

![](https://i.imgur.com/tpGsT3V.png)

The file from crowdstrike comes as

`Pid-2828.dmp.7z` - 7zip encrypted with `infected` in a containing folder




## Application Dump - MDMP 

### Magic Number

![](https://i.imgur.com/E2I0I0Q.png)

### Volatility can't handle just app space memory.

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

### Linux - Dump to Unicode

Dumping Strings to UNICODE

```shell=
bash> strings -a -t d -r l Pid-2828.dmp > String_unicode.txt
```

## WinDbg - UserMode Analysis

https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools

### Opening the files

![](https://i.imgur.com/NNDanKC.png)


### Analyse Them

![](https://i.imgur.com/VOg6IsW.png)


### Training - Videos 


![](https://i.imgur.com/cc0110o.png)

https://www.youtube.com/watch?v=pKQ_Io_8lTc