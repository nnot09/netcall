# netcall (WIP)

netcall is (probably) your (most) friendly library to execute manual syscalls from .NET

### Few Notes
* Supports x86/wow64/x64
* Very easy-to-use wrapper
* Tested on Windows 10 x64 22H2

### Example usage

#### 1. Define your delegates in SyscallStub.cs
```c#
[SuppressUnmanagedCodeSecurity]
public static class SyscallStub
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int NtClose(IntPtr hObject);
}
```

####  2. Create a new NTAPICollection and add your API
```c#
NTAPICollection apiCollection = new NTAPICollection();

apiCollection.AddAPI<SyscallStub.NtClose>("NtClose");
```

#### 3. Create a new instance of ImportStub and import your APIs
```c#
ImportStub import = new ImportStub();

if (import.Import(apiCollection))
{
    // Do something here.
}
```

#### 4. Use GetFunction in NTAPICollection to get the referenced delegate to your syscall stub.
```c#
var NtClose = apiCollection.GetFunction<SyscallStub.NtClose>();
```

#### 5. Use it.
```c#
NtClose(nativeHandle);
```


#### Now all together.
```c#            
NTAPICollection apiCollection = new NTAPICollection();

apiCollection.AddAPI<SyscallStub.NtClose>("NtClose");

ImportStub import = new ImportStub();

if (import.Import(apiCollection))
{
    var handle = File.OpenHandle(@"C:\Users\Developer\Desktop\test.txt", FileMode.Open, FileAccess.Read, FileShare.Read);

    var nativeHandle = handle.DangerousGetHandle();

    var NtClose = apiCollection.GetFunction<SyscallStub.NtClose>();

    NtClose(nativeHandle);
}

It's that easy, isn't it?

