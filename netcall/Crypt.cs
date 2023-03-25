using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace netcall
{
    internal class Crypt
    {
        public static Crypt Shared { get; } = new Crypt();

        public byte[] Key { get; } = new byte[8];

        public Crypt()
        {
            using RandomNumberGenerator rng = RandomNumberGenerator.Create();

            rng.GetBytes(this.Key);
        }

        public void Xor(IntPtr address, int size)
        {
            for (int i = 0; i < size; i++) 
            {
                byte b = Marshal.ReadByte(address, i);
                
                b ^= Key[i % 8];

                Marshal.WriteByte(address, i, b);
            }
        }

        public void Xor(byte[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                data[i] ^= Key[i % 8];
            }
        }
    }
}
