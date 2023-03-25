namespace netcall
{
    internal class Program
    {
        static void Main(string[] args)
        {
            ConsoleEx.DisableLogging();

            NTAPICollection apiCollection = new NTAPICollection();

            apiCollection.AddAPI<SyscallStub.NtClose>("NtClose");

            Netcall netcall = new Netcall();

            if (netcall.Import(apiCollection))
            {
                netcall.EnsureIntegrity();

                var handle = File.OpenHandle(@"C:\Users\Developer\Desktop\test.txt", FileMode.Open, FileAccess.Read, FileShare.Read);

                var nativeHandle = handle.DangerousGetHandle();

                var NtClose = apiCollection.GetFunction<SyscallStub.NtClose>();

                NtClose(nativeHandle);

                netcall.Release();
            }

            Console.Read();
        }
    }
}