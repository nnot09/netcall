namespace netcall
{
    internal class Program
    {
        static void Main(string[] args)
        {
            ImportStub import = new ImportStub();

            import.Import(new[]
            {
                "NtClose",
                "NtQuerySystemInformation",
                "NtAccessCheck",
                "NtQuerySecurityObject",
                "NtSetSecurityObject",
                "NtDichGibbetsNicht",
                "NtDisplayString"
            });
        }
    }
}