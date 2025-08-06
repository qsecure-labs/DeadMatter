using System;
using System.Runtime.InteropServices;
using static Deadmatter.Helpers;

namespace Deadmatter.Templates
{
    public class msv
    {
        public struct MsvTemplate
        {
            public byte[] signature;
            public int first_entry_offset;
            public int LogonSessionListCountOffset;
            public int ListTypeSize;
            public int LocallyUniqueIdentifierOffset;
            public int LogonTypeOffset;
            public int SessionOffset;
            public int UserNameListOffset;
            public int DomainOffset;
            public int CredentialsOffset;
            public int pSidOffset;
            public int CredentialManagerOffset;
            public int LogonTimeOffset;
            public int LogonServerOffset;
            public int MSV1CredentialsOffset;
            public int MSV1PrimaryOffset;
            public int LogonDomainNameOffset;
            public int UserNameOffset;
            public int LmOwfPasswordOffset;
            public int NtOwfPasswordOffset;
            public int ShaOwPasswordOffset;
            public int DPAPIProtectedOffset;
            public Type PrimaryCredentialType;
            public Type list_entry;
            public Type credential_entry;
            public int PasswordOffset;
        }

        public static MsvTemplate GetTemplate(string arch, int buildNum)
        {
            var template = new MsvTemplate();

            int WIN_XP = 2500;
            int WIN_2K3 = 3000;
            int WIN_VISTA = 5000;
            int WIN_7 = 7000;
            int WIN_8 = 8000;
            int WIN_BLUE = 9400;
            int WIN_10 = 9800;
            int WIN_10_1507 = 10240;
            int WIN_10_1511 = 10586;
            int WIN_10_1607 = 14393;
            int WIN_10_1703 = 15063;
            int WIN_10_1803 = 17134;
            int WIN_10_1809 = 17763;
            int WIN_10_1903 = 18362;
            int WIN_11_24H2 = 26100;

            template.MSV1CredentialsOffset = FieldOffset<KIWI_MSV1_0_PRIMARY_CREDENTIALS>("Credentials");
            template.MSV1PrimaryOffset = FieldOffset<KIWI_MSV1_0_PRIMARY_CREDENTIALS>("Primary");
            template.PasswordOffset = 0;

            
            if (buildNum < WIN_10_1507)
            {
                if (Globals.debug) { Console.WriteLine($"[*] Using Primary Credential struct before  Win10 1507"); }
                template.credential_entry = typeof(MSV1_0_PRIMARY_CREDENTIAL);
            }
            else if (buildNum < WIN_10_1511)
            {
                if (Globals.debug) { Console.WriteLine($"[*] Using Primary Credential struct of Win10 1507"); }
                template.credential_entry = typeof(MSV1_0_PRIMARY_CREDENTIAL_10_OLD);
            }
            else if (buildNum < WIN_10_1607)
            {
                if (Globals.debug) { Console.WriteLine($"[*] Using Primary Credential struct of Win10 1511"); }
                template.credential_entry = typeof(MSV1_0_PRIMARY_CREDENTIAL_10);
            }
            else if (buildNum < WIN_11_24H2)
            {
                if (Globals.debug) { Console.WriteLine($"[*] Using Primary Credential struct of Win10 1607 - Win11 23H1"); }
                template.credential_entry = typeof(MSV1_0_PRIMARY_CREDENTIAL_10_1607);
                template.PasswordOffset = -2;
            }
            else
            {
                if (Globals.debug) { Console.WriteLine($"[*] Using Primary Credential struct of Win11 24H1"); }
                template.credential_entry = typeof(MSV1_0_PRIMARY_CREDENTIAL_11_24H2);
                template.PasswordOffset = -2;
            }

            template.LogonDomainNameOffset = StructFieldOffset(template.credential_entry, "LogonDomainName");
            template.UserNameOffset = StructFieldOffset(template.credential_entry, "UserName");
            template.LmOwfPasswordOffset = StructFieldOffset(template.credential_entry, "LmOwfPassword") + template.PasswordOffset;
            template.NtOwfPasswordOffset = StructFieldOffset(template.credential_entry, "NtOwfPassword") + template.PasswordOffset;
            template.ShaOwPasswordOffset = StructFieldOffset(template.credential_entry, "ShaOwPassword") + template.PasswordOffset;

            if (template.credential_entry != typeof(MSV1_0_PRIMARY_CREDENTIAL_10_1607))
            {
                template.DPAPIProtectedOffset = 0;
            }
            else
            {
                if (Globals.debug) { Console.WriteLine($"[*] Our Primary Credential struct contains a DPAPIProtected entry"); }
                template.DPAPIProtectedOffset = FieldOffset<MSV1_0_PRIMARY_CREDENTIAL_10_1607>("DPAPIProtected");
            }

            if (arch == "x64")
            {
                if (WIN_XP <= buildNum && buildNum < WIN_2K3)
                {
                    //Console.WriteLine($"[*] Using logonsession signature pattern for WinXP and Win2K3 for AMD64");
                    template.signature = new byte[] { 0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8 };
                    template.first_entry_offset = -4;
                    template.LogonSessionListCountOffset = 0;
                }
                else if (WIN_2K3 <= buildNum && buildNum < WIN_VISTA)
                {
                    //Console.WriteLine($"[*] Using logonsession signature pattern for Win2K3 and WinVista for AMD64");
                    template.signature = new byte[] { 0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8 };
                    template.first_entry_offset = -4;
                    template.LogonSessionListCountOffset = -45;
                }
                else if (WIN_VISTA <= buildNum && buildNum < WIN_7)
                {
                    //Console.WriteLine($"[*] Using logonsession signature pattern for WinVista and Win7 for AMD64");
                    template.signature = new byte[] { 0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84 };
                    template.first_entry_offset = 21;
                    template.LogonSessionListCountOffset = -4;
                }
                else if (WIN_7 <= buildNum && buildNum < WIN_8)
                {
                    //Console.WriteLine($"[*] Using logonsession signature pattern for Win7 and Win8 for AMD64");
                    template.signature = new byte[] { 0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84 };
                    template.first_entry_offset = 19;
                    template.LogonSessionListCountOffset = -4;
                }
                else if (WIN_8 <= buildNum && buildNum < WIN_BLUE)
                {
                    //Console.WriteLine($"[*] Using logonsession signature pattern for Win8 and WinBlue for AMD64");
                    template.signature = new byte[] { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
                    template.first_entry_offset = 16;
                    template.LogonSessionListCountOffset = -4;
                }
                else if (WIN_BLUE <= buildNum && buildNum < WIN_10_1507)
                {
                    //Console.WriteLine($"[*] Using logonsession signature pattern for WinBlue and Win10 before 1507 for AMD64");
                    template.signature = new byte[] { 0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05 };
                    template.first_entry_offset = 36;
                    template.LogonSessionListCountOffset = -6;
                }
                else if (WIN_10_1507 <= buildNum && buildNum < WIN_10_1703)
                {
                    //1503 and 1603
                    //Console.WriteLine($"[*] Using logonsession signature pattern for Win10 1503 and 1603 for AMD64");
                    template.signature = new byte[] { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
                    template.first_entry_offset = 16;
                    template.LogonSessionListCountOffset = -4;
                }
                else if (WIN_10_1703 <= buildNum && buildNum < WIN_10_1803)
                {
                    //1703
                    //Console.WriteLine($"[*] Using logonsession signature pattern for Win10 1703 for AMD64");
                    template.signature = new byte[] { 0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
                    template.first_entry_offset = 23;
                    template.LogonSessionListCountOffset = -4;
                }
                else if (WIN_10_1803 <= buildNum && buildNum < WIN_10_1903)
                {
                    //1803
                    //Console.WriteLine($"[*] Using logonsession signature pattern for Win10 1803 for AMD64");
                    template.signature = new byte[] { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
                    template.first_entry_offset = 23;
                    template.LogonSessionListCountOffset = -4;
                }
                else
                {
                    //1903
                    //Console.WriteLine($"[*] Using logonsession signature pattern for Win10 1903 for AMD64");
                    template.signature = new byte[] { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
                    template.first_entry_offset = 23;
                    template.LogonSessionListCountOffset = -4;
                }
            }
            else if (arch == "x86")
            {
                if (WIN_XP <= buildNum && buildNum < WIN_2K3)
                {
                    //Console.WriteLine($"[*] Using logonsession signature pattern for WinXP and Win2K3 for Intel");
                    template.signature = new byte[] { 0xff, 0x50, 0x10, 0x85, 0xc0, 0x0f, 0x84 };
                    template.first_entry_offset = 24;
                    template.LogonSessionListCountOffset = 0;
                }
                else if (WIN_2K3 <= buildNum && buildNum < WIN_VISTA)
                {
                    //Console.WriteLine($"[*] Using logonsession signature pattern for Win2K3 and WinVista for Intel");
                    template.signature = new byte[] { 0x89, 0x71, 0x04, 0x89, 0x30, 0x8d, 0x04, 0xbd };
                    template.first_entry_offset = -11;
                    template.LogonSessionListCountOffset = -43;
                }
                else if (WIN_VISTA <= buildNum && buildNum < WIN_8)
                {
                    //Console.WriteLine($"[*] Using logonsession signature pattern for WinVist and Win8 for Intel");
                    template.signature = new byte[] { 0x89, 0x71, 0x04, 0x89, 0x30, 0x8d, 0x04, 0xbd };
                    template.first_entry_offset = -11;
                    template.LogonSessionListCountOffset = -42;
                }
                else if (WIN_8 <= buildNum && buildNum < WIN_BLUE)
                {
                    //Console.WriteLine($"[*] Using logonsession signature pattern for Win8 and WinBlue for Intel");
                    template.signature = new byte[] { 0x8b, 0x45, 0xf8, 0x8b, 0x55, 0x08, 0x8b, 0xde, 0x89, 0x02, 0x89, 0x5d, 0xf0, 0x85, 0xc9, 0x74 };
                    template.first_entry_offset = 18;
                    template.LogonSessionListCountOffset = -4;
                }
                else if (WIN_BLUE <= buildNum && buildNum < WIN_10_1507)
                {
                    //Console.WriteLine($"[*] Using logonsession signature pattern for WinBlue and Win10 before 1507 for Intel");
                    template.signature = new byte[] { 0x8b, 0x4d, 0xe4, 0x8b, 0x45, 0xf4, 0x89, 0x75, 0xe8, 0x89, 0x01, 0x85, 0xff, 0x74 };
                    template.first_entry_offset = 16;
                    template.LogonSessionListCountOffset = -4;
                }
                else if ((int)buildNum >= WIN_10_1507)
                {
                    //Console.WriteLine($"[*] Using logonsession signature pattern for Win10 after 1503 for Intel");
                    template.signature = new byte[] { 0x8b, 0x4d, 0xe8, 0x8b, 0x45, 0xf4, 0x89, 0x75, 0xec, 0x89, 0x01, 0x85, 0xff, 0x74 };
                    template.first_entry_offset = 16;
                    template.LogonSessionListCountOffset = -4;
                }
                else
                {
                    throw new Exception($"[-] Could not identify template! {buildNum}");
                }
            }
            else
            {
                throw new Exception($"[-] Unknown architecture! {arch}");
            }
            return template;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LIST_ENTRY
    {
        public IntPtr Flink;
        public IntPtr Blink;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_MSV1_0_PRIMARY_CREDENTIALS
    {
        public long next;
        public UNICODE_STRING Primary;
        public UNICODE_STRING Credentials;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_MSV1_0_CREDENTIALS
    {
        public IntPtr next;
        public uint AuthenticationPackageId;
        public IntPtr PrimaryCredentials;
    }

    //KIWI_MSV1_0_LIST_XX
    public struct KIWI_MSV1_0_LIST_51
    {
        public IntPtr Flink;
        public IntPtr Blink;
        public LUID LocallyUniqueIdentifier;
        public UNICODE_STRING UserName;
        public UNICODE_STRING Domain;
        public IntPtr unk0;
        public IntPtr unk1;
        public IntPtr pSid;
        public uint LogonType;
        public uint Session;
        public LARGE_INTEGER LogonTime;
        public UNICODE_STRING LogonServer;
        public IntPtr Credentials;
        public ulong unk19;
        public IntPtr unk20;
        public IntPtr unk21;
        public IntPtr unk22;
        public ulong unk23;
        public IntPtr CredentialManager;
    }

    public struct KIWI_MSV1_0_LIST_52
    {
        public IntPtr Flink;
        public IntPtr Blink;
        public LUID LocallyUniqueIdentifier;
        public UNICODE_STRING UserName;
        public UNICODE_STRING Domain;
        public IntPtr unk0;
        public IntPtr unk1;
        public IntPtr pSid;
        public uint LogonType;
        public uint Session;
        public LARGE_INTEGER LogonTime;
        public UNICODE_STRING LogonServer;
        public IntPtr Credentials;
        public ulong unk19;
        public IntPtr unk20;
        public IntPtr unk21;
        public ulong unk22;
        public IntPtr CredentialManager;
    }

    public struct KIWI_MSV1_0_LIST_60
    {
        public IntPtr Flink;
        public IntPtr Blink;
        public IntPtr unk0;
        public uint unk1;
        public IntPtr unk2;
        public uint unk3;
        public uint unk4;
        public uint unk5;
        public IntPtr hSemaphore6;
        public IntPtr unk7;
        public IntPtr hSemaphore8;
        public IntPtr unk9;
        public IntPtr unk10;
        public uint unk11;
        public uint unk12;
        public IntPtr unk13;
        public LUID LocallyUniqueIdentifier;
        public LUID SecondaryLocallyUniqueIdentifier;

        public UNICODE_STRING UserName;

        public UNICODE_STRING Domain;
        public IntPtr unk14;
        public IntPtr unk15;
        public IntPtr pSid;
        public uint LogonType;
        public uint Session;
        public LARGE_INTEGER LogonTime;
        public UNICODE_STRING LogonServer;
        public IntPtr Credentials;
        public ulong unk19;
        public IntPtr unk20;
        public IntPtr unk21;
        public IntPtr unk22;
        public IntPtr CredentialManager;
    }

    public struct KIWI_MSV1_0_LIST_61
    {
        public IntPtr Flink;
        public IntPtr Blink;
        public IntPtr unk0;
        public uint unk1;
        public IntPtr unk2;
        public uint unk3;
        public uint unk4;
        public uint unk5;
        public IntPtr hSemaphore6;
        public IntPtr unk7;
        public IntPtr hSemaphore8;
        public IntPtr unk9;
        public IntPtr unk10;
        public uint unk11;
        public uint unk12;
        public IntPtr unk13;
        public LUID LocallyUniqueIdentifier;
        public LUID SecondaryLocallyUniqueIdentifier;

        public UNICODE_STRING UserName;

        public UNICODE_STRING Domain;
        public IntPtr unk14;
        public IntPtr unk15;
        public IntPtr pSid;
        public uint LogonType;
        public uint Session;
        public LARGE_INTEGER LogonTime;
        public UNICODE_STRING LogonServer;
        public IntPtr Credentials;
        public IntPtr unk19;
        public IntPtr unk20;
        public IntPtr unk21;
        public uint unk22;
        public IntPtr CredentialManager;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ
    {
        public IntPtr Flink;
        public IntPtr Blink;
        public IntPtr unk0;
        public uint unk1;
        public IntPtr unk2;
        public uint unk3;
        public uint unk4;
        public uint unk5;
        public IntPtr hSemaphore6;
        public IntPtr unk7;
        public IntPtr hSemaphore8;
        public IntPtr unk9;
        public IntPtr unk10;
        public uint unk11;
        public uint unk12;
        public IntPtr unk13;
        public LUID LocallyUniqueIdentifier;
        public LUID SecondaryLocallyUniqueIdentifier;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
        public byte[] waza;

        public UNICODE_STRING UserName;

        public UNICODE_STRING Domain;
        public IntPtr unk14;
        public IntPtr unk15;
        public IntPtr pSid;
        public uint LogonType;
        public uint Session;
        public LARGE_INTEGER LogonTime;
        public UNICODE_STRING LogonServer;
        public IntPtr Credentials;
        public IntPtr unk19;
        public IntPtr unk20;
        public IntPtr unk21;
        public uint unk22;
        public IntPtr CredentialManager;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_MSV1_0_LIST_62
    {
        public IntPtr Flink;
        public IntPtr Blink;
        public IntPtr unk0;
        public uint unk1;
        public IntPtr unk2;
        public uint unk3;
        public uint unk4;
        public uint unk5;
        public IntPtr hSemaphore6;
        public IntPtr unk7;
        public IntPtr hSemaphore8;
        public IntPtr unk9;
        public IntPtr unk10;
        public uint unk11;
        public uint unk12;
        public IntPtr unk13;
        public LUID LocallyUniqueIdentifier;
        public LUID SecondaryLocallyUniqueIdentifier;

        public UNICODE_STRING UserName;

        public UNICODE_STRING Domain;
        public IntPtr unk14;
        public IntPtr unk15;
        public UNICODE_STRING Type;
        public IntPtr pSid;
        public uint LogonType;
        public IntPtr unk18;
        public uint Session;
        public LARGE_INTEGER LogonTime;
        public UNICODE_STRING LogonServer;
        public IntPtr Credentials;
        public IntPtr unk19;
        public IntPtr unk20;
        public IntPtr unk21;
        public uint unk22;
        public uint unk23;
        public uint unk24;
        public uint unk25;
        public uint unk26;
        public IntPtr unk27;
        public IntPtr unk28;
        public IntPtr unk29;
        public IntPtr CredentialManager;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_MSV1_0_LIST_63
    {
        public IntPtr Flink;
        public IntPtr Blink;
        public IntPtr unk0;
        public uint unk1;
        public IntPtr unk2;
        public uint unk3;
        public uint unk4;
        public uint unk5;
        public IntPtr hSemaphore6;
        public IntPtr unk7;
        public IntPtr hSemaphore8;
        public IntPtr unk9;
        public IntPtr unk10;
        public uint unk11;
        public uint unk12;
        public IntPtr unk13;
        public LUID LocallyUniqueIdentifier;
        public LUID SecondaryLocallyUniqueIdentifier;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
        public byte[] waza;

        public UNICODE_STRING UserName;

        public UNICODE_STRING Domain;
        public IntPtr unk14;
        public IntPtr unk15;
        public UNICODE_STRING Type;
        public IntPtr pSid;
        public uint LogonType;
        public IntPtr unk18;
        public uint Session;
        public LARGE_INTEGER LogonTime;
        public UNICODE_STRING LogonServer;
        public IntPtr Credentials;
        public IntPtr unk19;
        public IntPtr unk20;
        public IntPtr unk21;
        public uint unk22;
        public uint unk23;
        public uint unk24;
        public uint unk25;
        public uint unk26;
        public IntPtr unk27;
        public IntPtr unk28;
        public IntPtr unk29;
        public IntPtr CredentialManager;
    }

    //KIWI_X_PRIMARY_CREDENTIAL
    [StructLayout(LayoutKind.Sequential)]
    public struct KIWI_GENERIC_PRIMARY_CREDENTIAL
    {
        public UNICODE_STRING Domain;
        public UNICODE_STRING UserName;
        public UNICODE_STRING Password;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSV1_0_PRIMARY_CREDENTIAL
    {
        private readonly UNICODE_STRING LogonDomainName;
        private readonly UNICODE_STRING UserName;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
        private readonly byte[] NtOwfPassword;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
        private readonly byte[] LmOwfPassword;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
        private readonly byte[] ShaOwPassword;

        private readonly byte isNtOwfPassword;
        private readonly byte isLmOwfPassword;
        private readonly byte isShaOwPassword;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSV1_0_PRIMARY_CREDENTIAL_10_OLD
    {
        private readonly UNICODE_STRING LogonDomainName;
        private readonly UNICODE_STRING UserName;
        private readonly byte isIso;
        private readonly byte isNtOwfPassword;
        private readonly byte isLmOwfPassword;
        private readonly byte isShaOwPassword;
        private readonly byte align0;
        private readonly byte align1;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
        private readonly byte[] NtOwfPassword;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
        private readonly byte[] LmOwfPassword;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
        private readonly byte[] ShaOwPassword;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSV1_0_PRIMARY_CREDENTIAL_10
    {
        private readonly UNICODE_STRING LogonDomainName;
        private readonly UNICODE_STRING UserName;
        private readonly byte isIso;
        private readonly byte isNtOwfPassword;
        private readonly byte isLmOwfPassword;
        private readonly byte isShaOwPassword;
        private readonly byte align0;
        private readonly byte align1;
        private readonly byte align2;
        private readonly byte align3;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
        private readonly byte[] NtOwfPassword;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
        private readonly byte[] LmOwfPassword;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
        private readonly byte[] ShaOwPassword;

        /* buffer */
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSV1_0_PRIMARY_CREDENTIAL_10_1607
    {
        private readonly UNICODE_STRING LogonDomainName;
        private readonly UNICODE_STRING UserName;
        private readonly uint pNtlmCredIsoInProc;   //changed IntPtr because it gets allocated a different size (length of bytes) in Debug and Release versions
        private readonly byte isIso;
        private readonly byte isNtOwfPassword;
        private readonly byte isLmOwfPassword;
        private readonly byte isShaOwPassword;
        private readonly byte isDPAPIProtected;
        private readonly byte align0;
        private readonly byte align1;
        private readonly byte align2;
        private readonly byte align4;   //I needed to push the rest of the structure 4 bytes fwd (could have done it using the template.PasswordOffset)
        private readonly byte align5;   //I needed to push the rest of the structure 4 bytes fwd (could have done it using the template.PasswordOffset)
        private readonly byte align6;   //I needed to push the rest of the structure 4 bytes fwd (could have done it using the template.PasswordOffset)
        private readonly byte align7;   //I needed to push the rest of the structure 4 bytes fwd (could have done it using the template.PasswordOffset)


        private readonly uint unkD;         // 00000000
        private readonly ushort isoSize;    // 0000

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
        private readonly byte[] DPAPIProtected;

        private readonly uint align3;       // 00000000

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
        private readonly byte[] NtOwfPassword;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
        private readonly byte[] LmOwfPassword;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
        private readonly byte[] ShaOwPassword;

        /* buffer */
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSV1_0_PRIMARY_CREDENTIAL_11_24H2
    {
        private readonly UNICODE_STRING LogonDomainName;
        private readonly UNICODE_STRING UserName;
        private readonly uint pNtlmCredIsoInProc;   //changed IntPtr because it gets allocated a different size (length of bytes) in Debug and Release versions
        private readonly byte isIso;
        private readonly byte isNtOwfPassword;
        private readonly byte isLmOwfPassword;
        private readonly byte isShaOwPassword;
        private readonly byte isDPAPIProtected;
        private readonly byte align0;
        private readonly byte align1;
        private readonly byte align2;

        private readonly uint unkD;         // 00000000
        private readonly ushort isoSize;    // 0000

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
        private readonly byte[] DPAPIProtected;

        private readonly uint align3;       // 00000000

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
        private readonly byte[] NtOwfPassword;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = LM_NTLM_HASH_LENGTH)]
        private readonly byte[] LmOwfPassword;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = SHA_DIGEST_LENGTH)]
        private readonly byte[] ShaOwPassword;

        /* buffer */
    }
}