using netcall.Win32.Structs;
using netcall.Win32;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.IO;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace netcall
{
    internal class PEUtils : IDisposable
    {
        public bool IsInitialized { get; private set; }
        public IntPtr ImageBase { get; private set; }

        private PEReader pe;
        private DirectoryEntry export;
        private unsafe IMAGE_EXPORT_DIRECTORY* expdir;

        private int[] functionsTableArray;
        private short[] ordinalsTableArray;
        private int[] namesTableArray;

        private IntPtr functionsTable;
        private IntPtr nameOrdinalsTable;
        private IntPtr namesTable;

        public PEUtils(IntPtr baseAddress)
        {
            this.ImageBase = baseAddress;

            if (!TryInit(out var regionSize))
            {
                Console.WriteLine("[!!!] Initialization failed (1).");
                return;
            }

            if (!TryReadPE(regionSize))
            {
                Console.WriteLine("[!!!] Initialization failed (2).");
                return;
            }

            if (!TryReadInitials())
            {
                Console.WriteLine("[!!!] Initalization failed (3).");
                return;
            }

            this.IsInitialized = true;
        }

        private bool TryInit(out nint regionSize)
        {
            var baseAddr = (nuint)this.ImageBase;

            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
            regionSize = 0;
            int mbiSize = 0;

            unsafe
            {
                mbiSize = sizeof(MEMORY_BASIC_INFORMATION);
            }

            int querySuccess = Win32API.VirtualQuery(
                ref baseAddr,
                ref mbi,
                mbiSize
            );

            if (querySuccess == 0)
            {
                Console.WriteLine("[!!!] VirtualQuery failed at 0x{0:x2}");
                return false;
            }

            regionSize = mbi.RegionSize;

            return true;
        }
        private bool TryReadPE(nint regionSize)
        {
            unsafe
            {
                pe = new PEReader((byte*)this.ImageBase, (int)regionSize);

                if (!pe.IsEntireImageAvailable)
                {
                    Console.WriteLine("[!!!] Failed to read PE image.");
                    return false;
                }
            }

            return true;
        }
        private bool TryReadInitials()
        {
            export = pe.PEHeaders.PEHeader.ExportTableDirectory;

            if (!pe.PEHeaders.TryGetDirectoryOffset(export, out var exportOffset))
            {
                Console.WriteLine("[!!!] Failed to get export offset");
                return false;
            }

            unsafe
            {
                var exportDirAddress = (byte*)(this.ImageBase + exportOffset);

                expdir = (IMAGE_EXPORT_DIRECTORY*)exportDirAddress;

                if (expdir->Base <= 0)
                {
                    Console.WriteLine("[!!!] Invalid export directory.");
                    return false;
                }

                functionsTableArray = new int[expdir->NumberOfFunctions];
                namesTableArray = new int[expdir->NumberOfNames];
                ordinalsTableArray = new short[expdir->NumberOfNames];

                functionsTable = this.ImageBase + GetOffsetFromRVA(pe.PEHeaders.SectionHeaders, (nint)expdir->AddressOfFunctions);
                nameOrdinalsTable = this.ImageBase + GetOffsetFromRVA(pe.PEHeaders.SectionHeaders, (nint)expdir->AddressOfNameOrdinals);
                namesTable = this.ImageBase + GetOffsetFromRVA(pe.PEHeaders.SectionHeaders, (nint)expdir->AddressOfNames);

                Marshal.Copy(functionsTable, functionsTableArray, 0, (int)expdir->NumberOfFunctions);
                Marshal.Copy(nameOrdinalsTable, ordinalsTableArray, 0, (int)expdir->NumberOfNames);
                Marshal.Copy(namesTable, namesTableArray, 0, (int)expdir->NumberOfNames);
            }

            return true;
        }
        private int CalculateStubSize(IntPtr address)
        {
            IntPtr start = address;
            IntPtr end = address;

            byte opcode = 0;

            while ( opcode != 0xC3 && opcode != 0xC2 )
            {
                opcode = Marshal.ReadByte(end++);

                if (opcode == 0xC2)
                    break;
            }

            if (opcode == 0xC2) // ret IMM16
                end += 2;

            return (int)(end - start);
        }
        private IntPtr GetOffsetFromRVA(ImmutableArray<SectionHeader> sections, IntPtr rva)
        {
            int sectionIndex = pe.PEHeaders.GetContainingSectionIndex((int)rva);

            if (sectionIndex == -1)
                return IntPtr.Zero;

            var section = sections[sectionIndex];
            var relativeOffset = rva - section.VirtualAddress;

            return section.PointerToRawData + relativeOffset;
        }
        public NtApi? ResolveAPIExportAddress(string name)
        {
            if (!this.IsInitialized)
            {
                Console.WriteLine("[!!!] Resolve cancelled: PE not (fully) initialized.");
                return null;
            }

            unsafe
            {
                for (int i = 0; i < expdir->NumberOfNames; i++ /*+= sizeof(short)*/)
                {
                    // var ordinal = Marshal.ReadInt16(this.nameOrdinalsTable + i);
                    var ordinal = ordinalsTableArray[i];

                    if (ordinal >= expdir->NumberOfFunctions)
                    {
                        Console.WriteLine("[!!!] Invalid ordinal for API '{0}'", name);
                        return null;
                    }

                    // var func = Marshal.ReadInt32(functionsTable, ordinal);
                    var func = functionsTableArray[ordinal];

                    if (func < export.RelativeVirtualAddress || func >= export.RelativeVirtualAddress)
                    {
                        // int nameRva = Marshal.ReadInt32(namesTable, i);
                        var nameRva = namesTableArray[i];
                        uint nameOffset = (uint)GetOffsetFromRVA(pe.PEHeaders.SectionHeaders, nameRva);

                        if (nameOffset == 0)
                            continue;

                        IntPtr nameBuf = (IntPtr)(this.ImageBase + nameOffset);

                        string? apiName = Marshal.PtrToStringAnsi(nameBuf);

                        if (apiName == null)
                            continue;

                        if (apiName.Equals(name, StringComparison.OrdinalIgnoreCase))
                        {
                            IntPtr exportedApiAddressOffset = GetOffsetFromRVA(pe.PEHeaders.SectionHeaders, (nint)func);

                            IntPtr exportedAddress = this.ImageBase + exportedApiAddressOffset;

                            Console.WriteLine("Found '{0}' at 0x{1:x2}", name, exportedAddress);

                            return new NtApi()
                            {
                                Name = name,
                                Address = exportedAddress,
                                Size = CalculateStubSize(exportedAddress)
                            };
                        }
                    }
                }
            }

            Console.WriteLine("API '{0}' was not found.", name);

            return null;
        }
        public void Dispose()
        {
            if (this.pe != null)
                pe.Dispose();
        }
    }
}
