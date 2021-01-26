using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;

//https://github.com/cobbr/SharpSploit/tree/master/SharpSploit/Execution/DynamicInvoke
//using SharpSploit.Execution.DynamicInvoke;

namespace DInvoke
{
    class ProcessEnum
    {
        enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //public delegate IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(
                ref string DestinationString,
                [MarshalAs(UnmanagedType.LPWStr)]
                string SourceString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool WTSEnumerateProcesses(
            IntPtr serverHandle,        // Handle to a terminal server.
            Int32 reserved,             // Must be 0.
            Int32 version,              // Must be 1.
            ref IntPtr ppProcessInfo,   // Pointer to array of WTS_PROCESS_INFO.
            ref Int32 pCount            // Pointer to number of processes.
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void WTSFreeMemory(IntPtr pMemory);

        //[DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        //static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        //private static extern bool ConvertSidToStringSid(processListing->pUserSid, &stringSID);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool ConvertSidToStringSid(
            IntPtr pSid,
            out IntPtr ptrSid
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool LookupAccountSid(
            string lpSystemName,
            //[MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
            IntPtr pSid,
            System.Text.StringBuilder lpName,
            ref uint cchName,
            System.Text.StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SID_NAME_USE peUse
        );

        public struct WTS_PROCESS_INFO
        {
            public int SessionID;
            public int ProcessID;
            public IntPtr ProcessName;  // Pointer to string.
            public IntPtr UserSid;
        }

        private static IntPtr WTS_CURRENT_SERVER_HANDLE = (IntPtr)null;

        public static WTS_PROCESS_INFO[] ProcessEnumerator()
        {
            IntPtr pProcessInfo = IntPtr.Zero;
            int processCount = 0;

            // Enumerate processes.
            var dynamic_pointer = GetLibraryAddress("wtsapi32.dll", "WTSEnumerateProcessesW"); //Must add A to have ASCII load ya dummy.
            var wts_enumerate_processes = Marshal.GetDelegateForFunctionPointer(dynamic_pointer, typeof(WTSEnumerateProcesses)) as WTSEnumerateProcesses;
            if (!wts_enumerate_processes(
                WTS_CURRENT_SERVER_HANDLE,
                0,
                1,
                ref pProcessInfo,
                ref processCount))
            {
                return null;
            }

            //Parse processes.
            IntPtr pMemory = pProcessInfo;
            WTS_PROCESS_INFO[] processInfos = new WTS_PROCESS_INFO[processCount];
            Console.WriteLine("PID\t\tProcess Name\t\tSession ID\tSID\tDOMAIN\\USER\n");

            var convert_pointer = GetLibraryAddress("advapi32.dll", "ConvertSidtoStringSidW");
            for (int i = 0; i < processCount; i++)
            {
                processInfos[i] = (WTS_PROCESS_INFO)Marshal.PtrToStructure(pProcessInfo, typeof(WTS_PROCESS_INFO));
                pProcessInfo = (IntPtr)((long)pProcessInfo + Marshal.SizeOf(processInfos[i]));
                Console.Write("{0}\t\t{1}\t\t{2}\t ", processInfos[i].ProcessID, Marshal.PtrToStringAuto(processInfos[i].ProcessName), processInfos[i].SessionID);

                //Convert SID to StringSID.
                IntPtr ptrsSid = Marshal.AllocHGlobal(1000); // How long is SID going to be? Just guessing...
                string sidString;
                var convert_sid_to_string_sid = Marshal.GetDelegateForFunctionPointer(convert_pointer, typeof(ConvertSidToStringSid)) as ConvertSidToStringSid;
                try
                {
                    if (convert_sid_to_string_sid(processInfos[i].UserSid, out ptrsSid))
                    {
                        try
                        {
                            sidString = Marshal.PtrToStringAuto(ptrsSid);
                            Console.Write("{0}\t", sidString);
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(ptrsSid);
                        }
                    }
                    else
                    {
                        Console.Write("-\n");
                    }
                }
                catch
                {
                    Console.Write("Convert Sid to StringSid bug...\t");
                    //Console.Write("-\n");
                }

                StringBuilder userName = new StringBuilder();
                //uint userSize = (uint)userName.Capacity;
                uint userSize = (uint)100;
                StringBuilder domainName = new StringBuilder();
                uint domainSize = (uint)domainName.Capacity;
                SID_NAME_USE sidUse;
                // Lookup Domain and Account name from StringSID.
                var lookup_pointer = GetLibraryAddress("advapi32.dll", "LookupAccountSidW");
                var lookup_account_sid = Marshal.GetDelegateForFunctionPointer(lookup_pointer, typeof(LookupAccountSid)) as LookupAccountSid;
                if (!lookup_account_sid(
                    null,
                    processInfos[i].UserSid,
                    userName,
                    ref userSize,
                    domainName,
                    ref domainSize,
                    out sidUse
                    ))
                {
                    Console.Write("-\\-\n");
                }
                else
                {
                    Console.Write("{0}\\{1}\n", domainName, userName);
                }
            }

            //Free memory.
            var pointer = GetLibraryAddress("wtsapi32.dll", "WTSFreeMemory");
            var free_memory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(WTSFreeMemory)) as WTSFreeMemory;
            free_memory(pMemory);
            return processInfos;
        }

        static void Main(string[] args)
        {
            ProcessEnumerator();
        }

        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName)
        {
            // Try to find base address of loaded module.
            IntPtr hModule = IntPtr.Zero;
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    hModule = Mod.BaseAddress;
                }
            }

            // If we don't find our module, let's try to load it.
            if (hModule == IntPtr.Zero)
            {
                Console.WriteLine("{0} Module not found, must be loaded...\n", DLLName);
                //hModule = LoadModuleFromDisk(DLLName);
                //NTSTATUS is 32-bit int -> long.
                //string uModuleName = DLLName;
                //long CallResult = Native.LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule); //Consider LoadLibraryEx?
                //var load_library_pointer = GetLibraryAddress("wtsapi32.dll", "WTSFreeMemory");
                //var load_library = Marshal.GetDelegateForFunctionPointer(load_library_pointer, typeof(LoadLibrary)) as LoadLibrary;
                hModule = LoadLibrary(DLLName);

                // Check for the base address again.
                //ProcModules = Process.GetCurrentProcess().Modules;
                //foreach (ProcessModule Mod in ProcModules)
                //{
                //    if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                //    {
                //        hModule = Mod.BaseAddress;
                //    }
                //}

                if (hModule == IntPtr.Zero)
                {
                    Console.WriteLine("Module was not loaded and failed to load.\n");
                }
            }

            // If we don't have our module base address, we're going to crash+burn.
            // Get Function's Export Address by walking the PE and RVA structure. Some bit-magic going on.
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(hModule.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(hModule.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = hModule.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(hModule.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(hModule.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(hModule.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(hModule.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(hModule.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(hModule.ToInt64() + ExportRVA + 0x24));
                // Loop the array of export name RVA's
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionIteration = Marshal.PtrToStringAnsi((IntPtr)(hModule.ToInt64() + Marshal.ReadInt32((IntPtr)(hModule.ToInt64() + NamesRVA + i * 4))));
                    //System.Console.WriteLine("{0} == {1} Check...\t", FunctionIteration, FunctionName);
                    if (FunctionIteration.Equals(FunctionName, StringComparison.OrdinalIgnoreCase))
                    {
                        //System.Console.WriteLine("{0} Match!\n", FunctionName);
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(hModule.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(hModule.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)hModule + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports.");
            }
            if (FunctionPtr == IntPtr.Zero)
            {
                // Export not found
                throw new MissingMethodException(DLLName + ", export not found.");
            }
            return FunctionPtr;
        }

        // SHARPSPLOIT IMPLEMENTATION

        //public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        //{
        //    IntPtr hModule = GetLoadedModuleAddress(DLLName);
        //    if (hModule == IntPtr.Zero && CanLoadFromDisk)
        //    {
        //        hModule = LoadModuleFromDisk(DLLName);
        //        if (hModule == IntPtr.Zero)
        //        {
        //            throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
        //        }
        //    }
        //    else if (hModule == IntPtr.Zero)
        //    {
        //        throw new DllNotFoundException(DLLName + ", Dll was not found.");
        //    }
        //    return GetExportAddress(hModule, FunctionName);
        //}

        //public static IntPtr GetLoadedModuleAddress(string DLLName)
        //{
        //    ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
        //    foreach (ProcessModule Mod in ProcModules)
        //    {
        //        if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
        //        {
        //            return Mod.BaseAddress;
        //        }
        //    }
        //    return IntPtr.Zero;
        //}

        //public static IntPtr LoadModuleFromDisk(string DLLPath)
        //{
        //    Execute.Native.UNICODE_STRING uModuleName = new Execute.Native.UNICODE_STRING();
        //    Native.RtlInitUnicodeString(ref uModuleName, DLLPath);
        //    IntPtr hModule = IntPtr.Zero;
        //    Execute.Native.NTSTATUS CallResult = Native.LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
        //    if (CallResult != Execute.Native.NTSTATUS.Success || hModule == IntPtr.Zero)
        //    {
        //        return IntPtr.Zero;
        //    }
        //    return hModule;
        //}

        //public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        //{
        //    IntPtr FunctionPtr = IntPtr.Zero;
        //    try
        //    {
        //        // Traverse the PE header in memory
        //        Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
        //        Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
        //        Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
        //        Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
        //        Int64 pExport = 0;
        //        if (Magic == 0x010b)
        //        {
        //            pExport = OptHeader + 0x60;
        //        }
        //        else
        //        {
        //            pExport = OptHeader + 0x70;
        //        }

        //        // Read -> IMAGE_EXPORT_DIRECTORY
        //        Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
        //        Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
        //        Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
        //        Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
        //        Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
        //        Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
        //        Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
        //
        //        // Loop the array of export name RVA's
        //        for (int i = 0; i < NumberOfNames; i++)
        //        {
        //            string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
        //            if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
        //            {
        //                Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
        //                Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
        //                FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
        //                break;
        //            }
        //        }
        //    }
        //    catch
        //    {
        //        // Catch parser failure
        //        throw new InvalidOperationException("Failed to parse module exports.");
        //    }

        //    if (FunctionPtr == IntPtr.Zero)
        //    {
        //        // Export not found
        //        throw new MissingMethodException(ExportName + ", export not found.");
        //    }
        //    return FunctionPtr;
        //}
    }
}
