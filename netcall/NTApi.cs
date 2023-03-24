using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace netcall
{
    internal class NtApi<T> : INTAPI
    {
        public bool Success { get; set; }
        public string Name { get; set; }
        public IntPtr Address { get; set; }
        public IntPtr SecureAddress { get; set; }
        public int Size { get; set; }
        public T Function { get; set; }
        public Type Type { get; set; }

        /// <summary>
        /// Internal use. Will get invoked later through reflection.
        /// </summary>
        public void SetMethod()
        {
            this.Function = Marshal.GetDelegateForFunctionPointer<T>(this.SecureAddress);
        }
    }
}
