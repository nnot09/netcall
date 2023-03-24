using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace netcall
{
    [SuppressUnmanagedCodeSecurity]
    public static class SyscallStub
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate int NtClose(IntPtr hObject);
    }
}
