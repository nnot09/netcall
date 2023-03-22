using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace netcall
{
    internal class NtApi
    {
        public string Name { get; set; }
        public IntPtr Address { get; set; }
        public IntPtr SecureAddress { get; set; }
        public int Size { get; set; }

        public override string ToString()
        {
            return this.Name;
        }
    }
}
