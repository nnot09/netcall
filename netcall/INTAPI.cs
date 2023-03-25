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
        byte[] Restore { get; set; }
    }
}
