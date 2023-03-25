using System.Runtime.InteropServices;

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
        public byte[] Restore { get; set; }

        /// <summary>
        /// Internal use. Will get invoked later through reflection.
        /// </summary>
        public void SetMethod()
        {
            this.Function = Marshal.GetDelegateForFunctionPointer<T>(this.SecureAddress);
        }
    }
}
