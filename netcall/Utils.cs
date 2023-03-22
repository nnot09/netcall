using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace netcall
{
    public static class Utils
    {
        public static long ToAlignedSize(this long value, int alignment)
        {
            var rest = (value % alignment);
            return value += rest;
        }

        public static string Dump(this byte[] value)
        {
            StringBuilder sb = new StringBuilder();

            foreach ( var item in value ) 
            {
                sb.AppendFormat("{0:x2}", item);
                sb.Append(" ");
            }

            Console.WriteLine(sb.ToString());

            return sb.ToString();
        }
    }
}
