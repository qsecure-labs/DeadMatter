using System;
using System.Runtime.InteropServices;
using static Deadmatter.Helpers;

namespace Deadmatter.Templates
{
    public class dpapi
    {
        private const Int32 ANYSIZE_ARRAY = 1;

        public struct DpapiTemplate
        {
            public byte[] signature;
            public int first_entry_offset;
            public object list_entry;
        }

        

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_MASTERKEY_CACHE_ENTRY
        {
            public long Flink;
            public long Blink;
            public LUID LogonId;
            public Guid KeyUid;
            public FILETIME insertTime;
            public uint keySize;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
            public byte[] key;
        }
    }
}