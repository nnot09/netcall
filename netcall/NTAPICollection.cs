using netcall.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace netcall
{
    internal class NTAPICollection : List<INTAPI>
    {
        public void AddAPI<T>(string name) where T : Delegate
        {
            this.Add(new NtApi<T>()
            {
                Name = name,
                Type = typeof(T)
            });
        }

        public T GetFunction<T>()
        {
            var type = typeof(T);

            var api = this.FirstOrDefault(i => i.Type == type);

            if ( api == null )
            {
                Console.WriteLine("[!!!] Function of type {0} not found.", type.Name);
                return default;
            }

            return ((NtApi<T>)api).Function;
        }
    }
}
