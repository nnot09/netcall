using System.Runtime.InteropServices;
using System.Security;

namespace netcall
{
    [SuppressUnmanagedCodeSecurity]
    public static class SyscallStub
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate int NtClose(IntPtr hObject);
    }
}
