﻿using netcall.Win32.Structs;
using netcall.Win32;
using System.Collections.Immutable;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;

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
            ConsoleEx.WriteLine("initializing PE helper...");

            this.ImageBase = baseAddress;

            if (!TryInit(out var regionSize))
            {
                ConsoleEx.WriteLine(ConsoleState.Failed,"initialization failed (1).");
                return;
            }

            if (!TryReadPE(regionSize))
            {
                ConsoleEx.WriteLine(ConsoleState.Failed, "initialization failed (2).");
                return;
            }

            if (!TryReadInitials())
            {
                ConsoleEx.WriteLine(ConsoleState.Failed, "initalization failed (3).");
                return;
            }

            this.IsInitialized = true;

            ConsoleEx.WriteLine(ConsoleState.Success, "initialized");
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
                ConsoleEx.WriteLine(ConsoleState.Failed, "VirtualQuery failed at 0x{0:x2}");
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
                    ConsoleEx.WriteLine(ConsoleState.Failed, "failed to read PE image.");
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
                ConsoleEx.WriteLine(ConsoleState.Failed, "failed to get export offset");
                return false;
            }

            unsafe
            {
                var exportDirAddress = (byte*)(this.ImageBase + exportOffset);

                expdir = (IMAGE_EXPORT_DIRECTORY*)exportDirAddress;

                if (expdir->Base <= 0)
                {
                    ConsoleEx.WriteLine(ConsoleState.Failed, "invalid export directory.");
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
        public int CalculateStubSize(IntPtr address)
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

            if ( !Environment.Is64BitOperatingSystem )
            {
                // scan & fix length KiFastSystemCall

                byte[] nextData = new byte[5];

                Marshal.Copy(end + 1, nextData, 0, 5);

                for ( int i = 0; i < nextData.Length; i++ )
                {
                    // sysenter
                    // retn
                    if (nextData[i] == 0x0F && nextData[i + 1] == 0x34 
                        && nextData[i + 2] == 0xC3)
                    {
                        for (int fix = 0; nextData[fix] != 0xC3; fix++)
                            end++;

                        end += 2;
                        break;
                    }
                }
            }

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
        public IntPtr ResolveAPIExportAddress(string name)
        {
            if (!this.IsInitialized)
            {
                ConsoleEx.WriteLine(ConsoleState.Failed, "resolve cancelled: PE not (fully) initialized.");
                return IntPtr.Zero;
            }

            unsafe
            {
                for (int i = 0; i < expdir->NumberOfNames; i++ /*+= sizeof(short)*/)
                {
                    // var ordinal = Marshal.ReadInt16(this.nameOrdinalsTable + i);
                    var ordinal = ordinalsTableArray[i];

                    if (ordinal >= expdir->NumberOfFunctions)
                    {
                        ConsoleEx.WriteLine(ConsoleState.Failed, "invalid ordinal for API '{0}'", name);
                        return IntPtr.Zero;
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

                            return exportedAddress;
                        }
                    }
                }
            }

            ConsoleEx.WriteLine(ConsoleState.Alert, "resolve fail: API '{0}' was not found.", name);

            return IntPtr.Zero;
        }
        public void Dispose()
        {
            if (this.pe != null)
                pe.Dispose();
        }
    }
}
