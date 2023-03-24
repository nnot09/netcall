using System.Diagnostics;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace netcall
{
    internal class Program
    {
        static void Main(string[] args)
        {
            ImportStub import = new ImportStub();

            NTAPICollection apiCollection = new NTAPICollection();

            apiCollection.AddAPI<SyscallStub.NtClose>("NtClose");

            if (import.Import(apiCollection))
            {
                var handle = File.OpenHandle(@"C:\Users\Developer\Desktop\test.txt", FileMode.Open, FileAccess.Read, FileShare.Read);

                var nativeHandle = handle.DangerousGetHandle();

                var NtClose = apiCollection.GetFunction<SyscallStub.NtClose>();

                NtClose(nativeHandle);
            }

            Console.Read();
        }
    }
}