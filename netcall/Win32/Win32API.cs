using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using netcall.Win32.Structs;

namespace netcall.Win32
{
    internal class Win32API
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFileMapping(
            IntPtr hFile,
            IntPtr lpFileMappingAttributes,
            MemoryProtection flProtect, 
            uint dwMaximumSizeHigh,
            uint dwMaximumSizeLow, 
            string lpName
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr MapViewOfFile(
            IntPtr hFileMappingObject,
            FileMapAccess dwDesiredAccess,
            UInt32 dwFileOffsetHigh,
            UInt32 dwFileOffsetLow,
            UIntPtr dwNumberOfBytesToMap
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern int VirtualQuery(
            ref UIntPtr lpAddress,
            ref MEMORY_BASIC_INFORMATION lpBuffer,
            int dwLength
        );

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress, 
            uint dwSize, 
            AllocationType flAllocationType, 
            MemoryProtection flProtect
        );

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UIntPtr dwSize,
            MemoryProtection flNewProtect,
            out MemoryProtection lpflOldProtect
        );
    }
}
