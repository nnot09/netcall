using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace netcall
{
    internal interface INTAPI
    {
        bool Success { get; set; }
        string Name { get; set; }
        IntPtr Address { get; set; }
        IntPtr SecureAddress { get; set; }
        int Size { get; set; }
        Type Type { get; set; }
    }
}
