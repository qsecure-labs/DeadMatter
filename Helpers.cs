using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Deadmatter
{
    public class Helpers
    {
        public const int LM_NTLM_HASH_LENGTH = 16;
        public const int SHA_DIGEST_LENGTH = 20;

        [StructLayout(LayoutKind.Sequential)]
        public struct LARGE_INTEGER
        {
            public int LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public long Buffer;
        }



        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool ConvertSidToStringSid(
            [MarshalAs(UnmanagedType.LPArray)] byte[] pSID, out IntPtr ptrSid);

        public static DateTime ToDateTime(FILETIME time)
        {
            var fileTime = ((long)time.dwHighDateTime << 32) | (uint)time.dwLowDateTime;

            try
            {
                return DateTime.FromFileTime(fileTime);
            }
            catch
            {
                return DateTime.FromFileTime(0xFFFFFFFF);
            }
        }

                
        public static long SearchSignature(Program.DeadMatter deadmatter, byte[] pattern, long pos = 0, long length = 0)
        {
            int chunksize = (1000 * 1024);
            if (length == 0)
            {
                length = deadmatter.fileBinaryReader.BaseStream.Length;
            }

            try
            {
                deadmatter.fileBinaryReader.BaseStream.Seek(pos, SeekOrigin.Begin);
                while (pos != length)
                {
                    byte[] data = deadmatter.fileBinaryReader.ReadBytes(chunksize);

                    int offset = PatternAt(data, pattern);
                    if (offset != -1)
                    {
                        return (pos + offset);
                    }
                    
                    pos = deadmatter.fileBinaryReader.BaseStream.Position;
                    deadmatter.fileBinaryReader.BaseStream.Seek(pos, 0);

                }
                return 0;
            }
            catch (EndOfStreamException e)
            {
                Console.WriteLine("[-] Error reading data: {0}.", e.GetType().Name);
                return -1;
            }
        }

        public static List<long> SearchSignatureTillEnd(Program.DeadMatter deadmatter, byte[] pattern, long pos = 0, long length = 0)
        {
            List<long> addrList = new List<long>();
            List<long> tempAddrList = new List<long>();

            long chunkNum = 0;
            int chunkSize = 1000 * 1024;
            if (length == 0)
            {
                length = deadmatter.fileBinaryReader.BaseStream.Length;
            }

            try
            {
                deadmatter.fileBinaryReader.BaseStream.Seek(pos, SeekOrigin.Begin);
                while (pos != length)
                {
                    byte[] data = deadmatter.fileBinaryReader.ReadBytes(chunkSize);

                    tempAddrList = AllPatternAt(data, pattern);
                    if (tempAddrList.Count != 0)
                    {
                        foreach (long addr in tempAddrList)
                        {
                            long actualAddr = (chunkNum * chunkSize) + addr;
                            if (actualAddr >= 0 && actualAddr < length - 90)
                            {
                                addrList.Add(actualAddr);
                            }
                        }
                    }
                    
                    chunkNum = chunkNum + 1;
                    pos = deadmatter.fileBinaryReader.BaseStream.Position;
                    deadmatter.fileBinaryReader.BaseStream.Seek(pos, 0);

                }
                return addrList;
            }
            catch (EndOfStreamException e)
            {
                Console.WriteLine("[-] Error reading data: {0}.", e.GetType().Name);
                return addrList;
            }
        }

        public static List<long> ValidateKeyListRetKeyAddr(Program.DeadMatter deadmatter, List<long> candidateAddrList)
        {
            List<long> addrList = new List<long>();

            foreach (long pos in candidateAddrList)
            {
                //Console.WriteLine("Validating address: " + pos.ToString("X"));
                try
                {
                    long fileLength = deadmatter.fileBinaryReader.BaseStream.Length;
                    if (pos < fileLength - 90 && pos > 0)
                    {
                        //This 4-byte Int preceeding RUUU is the size of the rest of the KIWI_BCRYPT_HANDLE_KEY data struct
                        deadmatter.fileBinaryReader.BaseStream.Seek(pos - 4, SeekOrigin.Begin);
                        var KBHKsize = deadmatter.fileBinaryReader.ReadBytes(4);
                        //Console.WriteLine("KBHKsize position is: " + (pos - 4).ToString("X"));
                        //Console.WriteLine("KBHKsize preceeding RUUU is: " + BitConverter.ToInt32(KBHKsize, 0));
                        if (BitConverter.ToInt32(KBHKsize, 0) == 32)
                        {
                            //Console.WriteLine("Found interesting KIWI_BCRYPT_HANDLE_KEY record 32 bytes in size. Processing....");

                            //Entering section for KSSM pattern checks
                            byte[] KSSMpattern = new byte[] { 0x4B, 0x53, 0x53, 0x4D };     //KSSM
                            deadmatter.fileBinaryReader.BaseStream.Seek(pos + 32, SeekOrigin.Begin);
                            var KSSMbytes = deadmatter.fileBinaryReader.ReadBytes(4);

                            if (CompareUsingSequenceEqual(KSSMpattern, KSSMbytes))
                            {
                                //Console.WriteLine("Found RUUU pattern at: " + (string.Format("{0:X}", (pos))));
                                //Console.WriteLine("Found KSSM pattern at: " + (string.Format("{0:X}", (pos + 32))));

                                // This 4-byte Int before KSSM is the size of the KIWI_BCRYPT_KEY81 data struct
                                deadmatter.fileBinaryReader.BaseStream.Seek(pos + 28, SeekOrigin.Begin);
                                var KBK81size = deadmatter.fileBinaryReader.ReadBytes(4);
                                //Console.WriteLine("KBK81size position is: " + (pos + 28).ToString("X"));
                                //Console.WriteLine("The size of the KIWI_BCRYPT_KEY81 data struct in Hex: " + (string.Format("{0:X}", BitConverter.ToInt32(KBK81size, 0))));

                                //Entering section for KIWI_HARD_KEY checks
                                //This 4-byte Int 48 bytes after KSSM is the size of the  Key
                                deadmatter.fileBinaryReader.BaseStream.Seek(pos + 36 + 48, SeekOrigin.Begin);
                                var keySize = deadmatter.fileBinaryReader.ReadBytes(4);
                                //Console.WriteLine("The size of the Key in Hex: " + (string.Format("{0:X}", BitConverter.ToInt32(keySize, 0))));
                                //Console.WriteLine("KBK81size in Dec: " + (BitConverter.ToInt32(KBK81size, 0)));
                                //Console.WriteLine("keySize in Dec: " + (BitConverter.ToInt32(keySize, 0)));
                                if ((BitConverter.ToInt32(KBK81size, 0) >= 400 && BitConverter.ToInt32(KBK81size, 0) <= 700) && (BitConverter.ToInt32(keySize, 0) == 24 || BitConverter.ToInt32(keySize, 0) == 16))
                                {
                                    if (Globals.debug) { Console.WriteLine("[*] Adding validated key address to the list: " + (string.Format("{0:X}", (long)(pos + 36 + 52)))); }
                                    addrList.Add((long)(pos + 36 + 52));
                                }
                            }
                        }
                    }
                }
                catch (EndOfStreamException e)
                {
                    Console.WriteLine("[-] Error reading data: {0}.", e.GetType().Name);
                    return addrList;
                }
            }
            return addrList;
        }

        public static List<long> ValidateKeyListRetKBHKAddr(Program.DeadMatter deadmatter, List<long> candidateAddrList)
        {
            List<long> addrList = new List<long>();
                        
            foreach (long pos in candidateAddrList)
            {
                //Console.WriteLine("Validating address: " + pos.ToString("X"));
                try
                {
                    long fileLength = deadmatter.fileBinaryReader.BaseStream.Length;
                    if (pos < fileLength - 90 && pos > 0)
                    {
                        //This 4-byte Int preceeding RUUU is the size of the rest of the KIWI_BCRYPT_HANDLE_KEY data struct
                        deadmatter.fileBinaryReader.BaseStream.Seek(pos - 4, SeekOrigin.Begin);
                        var KBHKsize = deadmatter.fileBinaryReader.ReadBytes(4);
                        //Console.WriteLine("KBHKsize position is: " + (pos - 4).ToString("X"));
                        //Console.WriteLine("KBHKsize preceeding RUUU is: " + BitConverter.ToInt32(KBHKsize, 0));
                        if (BitConverter.ToInt32(KBHKsize, 0) == 32)
                        {
                            //Console.WriteLine("Found interesting KIWI_BCRYPT_HANDLE_KEY record 32 bytes in size. Processing....");

                            //Entering section for KSSM pattern checks
                            byte[] KSSMpattern = new byte[] { 0x4B, 0x53, 0x53, 0x4D };     //KSSM
                            deadmatter.fileBinaryReader.BaseStream.Seek(pos + 32, SeekOrigin.Begin);
                            var KSSMbytes = deadmatter.fileBinaryReader.ReadBytes(4);

                            if (CompareUsingSequenceEqual(KSSMpattern, KSSMbytes))
                            {
                                //Console.WriteLine("Found RUUU pattern at: " + (string.Format("{0:X}", (pos))));
                                //Console.WriteLine("Found KSSM pattern at: " + (string.Format("{0:X}", (pos + 32))));

                                // This 4-byte Int before KSSM is the size of the KIWI_BCRYPT_KEY81 data struct
                                deadmatter.fileBinaryReader.BaseStream.Seek(pos + 28, SeekOrigin.Begin);
                                var KBK81size = deadmatter.fileBinaryReader.ReadBytes(4);
                                //Console.WriteLine("KBK81size position is: " + (pos + 28).ToString("X"));
                                //Console.WriteLine("The size of the KIWI_BCRYPT_KEY81 data struct in Hex: " + (string.Format("{0:X}", BitConverter.ToInt32(KBK81size, 0))));

                                //Entering section for KIWI_HARD_KEY checks
                                //This 4-byte Int 48 bytes after KSSM is the size of the  Key
                                deadmatter.fileBinaryReader.BaseStream.Seek(pos + 36 + 48, SeekOrigin.Begin);
                                var keySize = deadmatter.fileBinaryReader.ReadBytes(4);
                                //Console.WriteLine("The size of the Key in Hex: " + (string.Format("{0:X}", BitConverter.ToInt32(keySize, 0))));
                                //Console.WriteLine("KBK81size in Dec: " + (BitConverter.ToInt32(KBK81size, 0)));
                                //Console.WriteLine("keySize in Dec: " + (BitConverter.ToInt32(keySize, 0)));
                                if ((BitConverter.ToInt32(KBK81size, 0) >= 400 && BitConverter.ToInt32(KBK81size, 0) <= 700) && (BitConverter.ToInt32(keySize, 0) == 24 || BitConverter.ToInt32(keySize, 0) == 16))
                                {
                                    if (Globals.debug) { Console.WriteLine("[*] Adding validated key's KIWI_BCRYPT_HANDLE_KEY data struct address to the list: " + (string.Format("{0:X}", (long)(pos - 4)))); }
                                    addrList.Add((long)(pos - 4));
                                }
                                else
                                {
                                    if (Globals.debug) { Console.WriteLine("[*] Discarding address: " + (string.Format("{0:X}", (long)(pos - 4)))); }
                                }
                            }
                        }
                    }
                }
                catch (EndOfStreamException e)
                {
                    Console.WriteLine("[-] Error reading data: {0}.", e.GetType().Name);
                    return addrList;
                }
            }
            return addrList;
        }

        //Try to check the values of the 24 bytes preceeding the Primary string position
        public static List<long> ValidatePrimCredsList(Program.DeadMatter deadmatter, List<long> candidateAddrList)
        {
            List<long> addrList = new List<long>();
            byte[] msvStructVirtAddrBytes;
            byte[] primaryStringVirtAddrBytes;
            byte[] maxLengthMsvStructBytes;
            byte[] actualLengthMsvStructBytes;
            byte[] maxLengthStringPrimaryBytes;
            byte[] actualLengthStringPrimaryBytes;
            long msvStructVirtAddr;
            long primaryStringVirtAddr;
            int maxLengthMsvStruct;
            int actualLengthMsvStruct;
            int maxLengthStringPrimary;
            int actualLengthStringPrimary;

            foreach (long pos in candidateAddrList)
            {
                //Console.WriteLine("Validating address: " + pos.ToString("X"));
                try
                {
                    //Getting the virtual address of the MSV Credentials struct
                    deadmatter.fileBinaryReader.BaseStream.Seek(pos - 8, SeekOrigin.Begin);
                    msvStructVirtAddrBytes = deadmatter.fileBinaryReader.ReadBytes(8);
                    //Array.Reverse(msvStructVirtAddrBytes);
                    //Console.WriteLine("Virtual Address of MSV Credentials struct: " + PrintHexBytes(msvStructVirtAddrBytes));
                    msvStructVirtAddr = BitConverter.ToInt64(msvStructVirtAddrBytes, 0);

                    //Getting the virtual address of the "Primary" text string
                    deadmatter.fileBinaryReader.BaseStream.Seek(pos - 24, SeekOrigin.Begin);
                    primaryStringVirtAddrBytes = deadmatter.fileBinaryReader.ReadBytes(8);
                    //Array.Reverse(primaryStringVirtAddrBytes);
                    //Console.WriteLine("Virtual Address of Primary string: " + PrintHexBytes(primaryStringVirtAddrBytes));
                    primaryStringVirtAddr = BitConverter.ToInt64(primaryStringVirtAddrBytes, 0);

                    //Getting the maxlength of the MSV Credentials struct
                    deadmatter.fileBinaryReader.BaseStream.Seek(pos - 14, SeekOrigin.Begin);
                    maxLengthMsvStructBytes = deadmatter.fileBinaryReader.ReadBytes(2);
                    maxLengthMsvStruct = BitConverter.ToInt16(maxLengthMsvStructBytes, 0);

                    //Getting the actual length of the MSV Credentials struct
                    deadmatter.fileBinaryReader.BaseStream.Seek(pos - 16, SeekOrigin.Begin);
                    actualLengthMsvStructBytes = deadmatter.fileBinaryReader.ReadBytes(2);
                    actualLengthMsvStruct = BitConverter.ToInt16(actualLengthMsvStructBytes, 0);

                    //Getting the maxlength of the string "Primary"
                    deadmatter.fileBinaryReader.BaseStream.Seek(pos - 30, SeekOrigin.Begin);
                    maxLengthStringPrimaryBytes = deadmatter.fileBinaryReader.ReadBytes(2);
                    maxLengthStringPrimary = BitConverter.ToInt16(maxLengthStringPrimaryBytes, 0);

                    //Getting the actual length of the string "Primary"
                    deadmatter.fileBinaryReader.BaseStream.Seek(pos - 32, SeekOrigin.Begin);
                    actualLengthStringPrimaryBytes = deadmatter.fileBinaryReader.ReadBytes(2);
                    actualLengthStringPrimary = BitConverter.ToInt16(actualLengthStringPrimaryBytes, 0);

                    //Console.WriteLine("Virtual Address of MSV Credentials struct in Hex: " + (string.Format("{0:X}", msvStructVirtAddr)));
                    //Console.WriteLine("Virtual Address of Primary string in Hex: " + (string.Format("{0:X}", primaryStringVirtAddr)));
                    //Console.WriteLine("Max length of the MSV Credentials struct: " + maxLengthMsvStruct);
                    //Console.WriteLine("Actual length of the MSV Credentials struct: " + actualLengthMsvStruct);
                    //Console.WriteLine("Max length of the string Primary: " + maxLengthStringPrimary);
                    //Console.WriteLine("Actual length of the string Primary: " + actualLengthStringPrimary);
                    //Console.WriteLine("-----------");

                    if ((msvStructVirtAddr - primaryStringVirtAddr) <= 32 &&
                        (msvStructVirtAddr - primaryStringVirtAddr) > 0 &&
                        (maxLengthMsvStruct - actualLengthMsvStruct) <= 32 &&
                        (maxLengthMsvStruct - actualLengthMsvStruct) > 0 &&
                        maxLengthStringPrimary == 8 &&
                        actualLengthStringPrimary == 7)
                    {
                        if (Globals.debug) { Console.WriteLine("[*] FOUND GOOD CANDIDATE!!!"); }
                        if (Globals.debug) { Console.WriteLine("[*] Result of address subtraction: " + (msvStructVirtAddr - primaryStringVirtAddr)); }
                        if (Globals.debug) { Console.WriteLine("[*] Virtual Address of MSV Credentials struct in Hex: " + (string.Format("{0:X}", (BitConverter.ToInt64(msvStructVirtAddrBytes, 0))))); }
                        if (Globals.debug) { Console.WriteLine("[*] Virtual Address of Primary string in Hex: " + (string.Format("{0:X}", (BitConverter.ToInt64(primaryStringVirtAddrBytes, 0))))); }
                        if (Globals.debug) { Console.WriteLine("[*] Virtual Address of MSV Credentials struct in Dec: " + msvStructVirtAddr); }
                        if (Globals.debug) { Console.WriteLine("[*] Virtual Address of Primary string in Dec: " + primaryStringVirtAddr); }
                        if (Globals.debug) { Console.WriteLine("[*] Checking actual and max length of MSV Credentials struct "); }
                        if (Globals.debug) { Console.WriteLine("[*] Actual length of MSV Credentials struct in Dec: " + actualLengthMsvStruct); }
                        if (Globals.debug) { Console.WriteLine("[*] Max length of MSV Credentials struct in Dec: " + maxLengthMsvStruct); }
                        if ((maxLengthMsvStruct - actualLengthMsvStruct) <= 32)
                        {
                            if (Globals.debug) { Console.WriteLine("[*] THE CANDIDATE LOOKS VALID!!! Adding the address " + (string.Format("{0:X}", (long)(pos - 40))) + " to the list..."); }
                            addrList.Add((long)(pos - 40));
                        }
                    }
                    else
                    {
                        //Console.WriteLine("Discarding address: " + (string.Format("{0:X}", (long)(pos))));
                    }
                        
                    
                }
                catch (EndOfStreamException e)
                {
                    Console.WriteLine("[-] Error reading data: {0}.", e.GetType().Name);
                    return addrList;
                }
            }
            if (Globals.debug) { Console.WriteLine("[*] Total valid addresses found " + addrList.Count); }
            return addrList;
        }

        //Returns the address of the 3DES key's KIWI_BCRYPT_HANDLE_KEY structure (not the key's address)
        //Use with vvalidate_key_list_ret_KBHK_addr() which returns KIWI_BCRYPT_HANDLE_KEY structure addresses
        public static List<long> GetDESKeyKBHKList(Program.DeadMatter deadmatter, List<long> validatedAddrList)
        {
            List<long> addrList = new List<long>();

            foreach (long pos in validatedAddrList)
            {
                if (Globals.debug) { Console.WriteLine("[*] Checking address: " + pos.ToString("X")); }
                try
                {
                    //KIWI_HARD_KEY Section
                    //This 4-byte Int before the Key (and 48 bytes after KSSM) is the size of the Key
                    deadmatter.fileBinaryReader.BaseStream.Seek(pos + 4 + 36 + 48, SeekOrigin.Begin);
                    var keySize = deadmatter.fileBinaryReader.ReadBytes(4);
                    if (Globals.debug) { Console.WriteLine("[*] The size of the Key in Hex: " + (string.Format("{0:X}", BitConverter.ToInt32(keySize, 0)))); }
                    if (Globals.debug) { Console.WriteLine("[*] keySize in Dec: " + (BitConverter.ToInt32(keySize, 0))); }
                    if (BitConverter.ToInt32(keySize, 0) == 24)
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Adding validated 3DES key's KIWI_BCRYPT_HANDLE_KEY address to the list: " + (string.Format("{0:X}", (long)(pos - 4)))); }
                        addrList.Add((long)(pos));
                    }

                }
                catch (EndOfStreamException e)
                {
                    Console.WriteLine("[-] Error reading data: {0}.", e.GetType().Name);
                    return addrList;
                }
            }
            return addrList;
        }


        //Returns the address of the 3DES key's address
        //Use with validate_key_list_ret_key_addr() which returns key addresses
        public static List<long> GetDESKeyList(Program.DeadMatter deadmatter, List<long> validatedAddrList)
        {
            List<long> addrList = new List<long>();

            foreach (long pos in validatedAddrList)
            {
                if (Globals.debug) { Console.WriteLine("[*] Checking address: " + pos.ToString("X")); }
                try
                {
                    //KIWI_HARD_KEY Section
                    //This 4-byte Int before the Key (and 48 bytes after KSSM) is the size of the Key
                    deadmatter.fileBinaryReader.BaseStream.Seek(pos - 4, SeekOrigin.Begin);
                    var keySize = deadmatter.fileBinaryReader.ReadBytes(4);
                    if (Globals.debug) { Console.WriteLine("[*] The size of the Key in Hex: " + (string.Format("{0:X}", BitConverter.ToInt32(keySize, 0)))); }
                    if (Globals.debug) { Console.WriteLine("[*] keySize in Dec: " + (BitConverter.ToInt32(keySize, 0))); }
                    if (BitConverter.ToInt32(keySize, 0) == 24)
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Adding validated 3DES key address to the list: " + (string.Format("{0:X}", (long)(pos - 4)))); }
                        addrList.Add((long)(pos - 4));
                    }
                        
                    
                }
                catch (EndOfStreamException e)
                {
                    Console.WriteLine("[-] Error reading data: {0}.", e.GetType().Name);
                    return addrList;
                }
            }
            return addrList;
        }


        //Returns the address of the AES key's KIWI_BCRYPT_HANDLE_KEY structure (not the key's address)
        //Use with vvalidate_key_list_ret_KBHK_addr() which returns KIWI_BCRYPT_HANDLE_KEY structure addresses
        public static List<long> GetAESKeyKBHKList(Program.DeadMatter deadmatter, List<long> validatedAddrList)
        {
            List<long> addrList = new List<long>();

            foreach (long pos in validatedAddrList)
            {
                if (Globals.debug) { Console.WriteLine("[*] Checking address: " + pos.ToString("X")); }
                try
                {
                    //KIWI_HARD_KEY Section
                    //This 4-byte Int before the Key (and 48 bytes after KSSM) is the size of the Key
                    deadmatter.fileBinaryReader.BaseStream.Seek(pos + 4 + 36 + 48, SeekOrigin.Begin);
                    var keySize = deadmatter.fileBinaryReader.ReadBytes(4);
                    if (Globals.debug) { Console.WriteLine("[*] The size of the Key in Hex: " + (string.Format("{0:X}", BitConverter.ToInt32(keySize, 0)))); }
                    if (Globals.debug) { Console.WriteLine("[*] keySize in Dec: " + (BitConverter.ToInt32(keySize, 0))); }
                    if (BitConverter.ToInt32(keySize, 0) == 16)
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Adding validated AES key's KIWI_BCRYPT_HANDLE_KEY address to the list: " + (string.Format("{0:X}", (long)(pos - 4)))); }
                        addrList.Add((long)(pos));
                    }

                }
                catch (EndOfStreamException e)
                {
                    Console.WriteLine("[-] Error reading data: {0}.", e.GetType().Name);
                    return addrList;
                }
            }
            return addrList;
        }


        public static byte[] DecryptDES_ECB_NoPadding(byte[] cipherText, byte[] key)
        {
            using (DES des = DES.Create())
            {
                des.Key = key;
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;  // No padding

                using (ICryptoTransform decryptor = des.CreateDecryptor())
                {
                    // Since no padding, ciphertext length must be a multiple of 8 bytes
                    return decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                }
            }
        }

        public static byte[] DecryptAES_CBC_NoPadding(byte[] cipherText, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.None;  // No padding

                using (ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                {
                    // Since no padding, ciphertext length must be a multiple of block size (16 bytes)
                    return decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                }
            }
        }

        public static bool CompareUsingSequenceEqual(byte[] firstArray, byte[] secondArray)
        {
            return firstArray.SequenceEqual(secondArray);
        }

       

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("0x{0:x2} ", b);
            return hex.ToString();
        }

        public static int PatternAt(byte[] src, byte[] pattern)
        {
            int maxFirstCharSlot = src.Length - pattern.Length + 1;
            for (int i = 0; i < maxFirstCharSlot; i++)
            {
                if (src[i] != pattern[0]) // compare only first byte
                    continue;

                // found a match on first byte, now try to match rest of the pattern
                for (int j = pattern.Length - 1; j >= 1; j--)
                {
                    if (src[i + j] != pattern[j]) break;
                    if (j == 1) return i;
                }
            }
            return -1;
        }

        public static List<long> AllPatternAt(byte[] src, byte[] pattern)
        {
            List<long> list = new List<long>();
            int maxFirstCharSlot = src.Length - pattern.Length + 1;
            for (int i = 0; i < maxFirstCharSlot; i++)
            {
                if (src[i] != pattern[0]) // compare only first byte
                    continue;

                // found a match on first byte, now try to match rest of the pattern
                for (int j = pattern.Length - 1; j >= 1; j--)
                {
                    if (src[i + j] != pattern[j]) break;
                    if (j == 1) list.Add(i);
                }
            }       
            return list;
        }

        public static long FindByteSequence(byte[] data, byte[] searchSequence)
        {
            int sequenceLength = searchSequence.Length;

            for (long i = 0; i <= data.Length - sequenceLength; i++)
            {
                bool match = true;

                for (int j = 0; j < sequenceLength; j++)
                {
                    if (data[(int)i + j] != searchSequence[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    // Return the index of the byte following the sequence
                    return i + sequenceLength;
                }
            }

            return -1; // Sequence not found
        }


        public static bool isHexDigit(byte b)
        {
            // '0 - 9' or 'a - f' or 'A - F' 
            if ((b >= 48 && b <= 57) || (b >= 97 && b <= 102) || (b >= 65 && b <= 70))
            {
                return true;
            }
            return false;
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            if (hex.Length % 2 != 0)
                throw new ArgumentException("[-] Error: Hex string must have an even length to a hex byte array.");

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        //https://github.com/skelsec/pypykatz/blob/bd1054d1aa948133a697a1dfcb57a5c6463be41a/pypykatz/commons/common.py#L168
        public static ulong GetPtrWithOffset(BinaryReader fileBinaryReader, long pos, string arch)
        {
            if (arch == "x64")
            {
                if (Globals.debug) { Console.WriteLine($"[*] Reading the value at postion: {pos.ToString("X")}"); }
                fileBinaryReader.BaseStream.Seek(pos, SeekOrigin.Begin);
                UInt32 ptr = Deadmatter.Helpers.ReadUInt32(fileBinaryReader);
                if (Globals.debug) { Console.WriteLine($"[*] The value (ptr) is: {((long)ptr).ToString("X")}"); }
                if (Globals.debug) { Console.WriteLine($"[*] The new position (pos + 4 + ptr) is:  {(pos + 4 + ptr).ToString("X")}"); }
                return (ulong)(pos + 4 + ptr);
            }
            else
            {
                //Console.WriteLine($"Reading the value at postion: " + pos.ToString("X"));
                fileBinaryReader.BaseStream.Seek(pos, SeekOrigin.Begin);
                UInt16 ptr = Deadmatter.Helpers.ReadUInt16(fileBinaryReader);
                //Console.WriteLine($"The new position (ptr) is:  {ptr}.ToString("X")");
                return ptr;
            }
        }

        
        public static T ReadStruct<T>(byte[] array) where T : struct
        {
            var handle = GCHandle.Alloc(array, GCHandleType.Pinned);
            var mystruct = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return mystruct;
        }

        

        public static UNICODE_STRING ExtractUnicodeString(BinaryReader fileStreamReader)
        {
            UNICODE_STRING str;

            byte[] strBytes = fileStreamReader.ReadBytes(Marshal.SizeOf(typeof(UNICODE_STRING)));
            //Console.WriteLine($"This should be the address: " + Helpers.ByteArrayToString(strBytes));
            str = ReadStruct<UNICODE_STRING>(strBytes);
            //Console.WriteLine($"This address length: {str.Length}");
            //Console.WriteLine($"This address maxlength: {str.MaximumLength}");
            //Console.WriteLine($"This address buffer: {str.Buffer.ToString("X")}");

            return str;
        }


        public static string PrintHexBytes(byte[] byteArray)
        {
            var res = new StringBuilder(byteArray.Length * 3);
            for (var i = 0; i < byteArray.Length; i++)
                res.AppendFormat(NumberFormatInfo.InvariantInfo, "{0:x2} ", byteArray[i]);
            return res.ToString();
        }

        public static int FieldOffset<T>(string fieldName)
        {
            return Marshal.OffsetOf(typeof(T), fieldName).ToInt32();
        }

        public static int StructFieldOffset(Type s, string field)
        {
            var ex = typeof(Helpers);
            var mi = ex.GetMethod("FieldOffset");
            var miConstructed = mi.MakeGenericMethod(s);
            object[] args = { field };
            return (int)miConstructed.Invoke(null, args);
        }

        public static UNICODE_STRING ExtractUnicodeString(BinaryReader fileStreamReader, long offset)
        {
            UNICODE_STRING str;
            fileStreamReader.BaseStream.Seek(offset, 0);
            byte[] strBytes = fileStreamReader.ReadBytes(Marshal.SizeOf(typeof(UNICODE_STRING)));
            str = ReadStruct<UNICODE_STRING>(strBytes);

            return str;
        }

        public static byte[] GetBytes(byte[] source, long startindex, int length)
        {
            var resBytes = new byte[length];
            Array.Copy(source, startindex, resBytes, 0, resBytes.Length);
            return resBytes;
        }

        public static string PrintHashBytes(byte[] byteArray)
        {
            if (byteArray == null)
                return string.Empty;

            var res = new StringBuilder(byteArray.Length * 2);
            for (var i = 0; i < byteArray.Length; i++)
                res.AppendFormat(NumberFormatInfo.InvariantInfo, "{0:x2}", byteArray[i]);
            return res.ToString();
        }

        public static string ExtractANSIStringString(Program.DeadMatter deadmatter, UNICODE_STRING str)
        {
            if (str.MaximumLength == 0) return null;
            //if (Globals.debug) { Console.WriteLine($"[*] Primary word string buffer physical address in Hex: " + (string.Format("{0:X}", (str.Buffer)))); }

            deadmatter.fileBinaryReader.BaseStream.Seek(str.Buffer, 0);
            byte[] resultBytes = deadmatter.fileBinaryReader.ReadBytes(str.MaximumLength);
            var pinnedArray = GCHandle.Alloc(resultBytes, GCHandleType.Pinned);
            var tmp_p = pinnedArray.AddrOfPinnedObject();
            var result = Marshal.PtrToStringAnsi(tmp_p);
            pinnedArray.Free();

            return result;
        }

       

        public static string ReadString(BinaryReader fileBinaryReader, int Length)
        {
            var data = fileBinaryReader.ReadBytes(Length);
            Array.Reverse(data);
            return Encoding.Unicode.GetString(data);
        }

        public static Int16 ReadInt16(BinaryReader fileBinaryReader)
        {
            var data = fileBinaryReader.ReadBytes(2);
            //Array.Reverse(data);
            return BitConverter.ToInt16(data, 0);
        }

        public static Int32 ReadInt32(BinaryReader fileBinaryReader)
        {
            var data = fileBinaryReader.ReadBytes(4);
            //Array.Reverse(data);
            return BitConverter.ToInt32(data, 0);
        }

        public static Int64 ReadInt64(BinaryReader fileBinaryReader)
        {
            var data = fileBinaryReader.ReadBytes(8);
            //Array.Reverse(data);
            return BitConverter.ToInt64(data, 0);
        }

        public static uint ReadInt8(BinaryReader fileBinaryReader)
        {
            byte data = fileBinaryReader.ReadBytes(1)[0];
            //Array.Reverse(data);
            return data;
        }

        public static UInt16 ReadUInt16(BinaryReader fileBinaryReader)
        {
            var data = fileBinaryReader.ReadBytes(2);
            //Array.Reverse(data);
            return BitConverter.ToUInt16(data, 0);
        }

        public static UInt32 ReadUInt32(BinaryReader fileBinaryReader)
        {
            var data = fileBinaryReader.ReadBytes(4);
            //Array.Reverse(data);
            return BitConverter.ToUInt32(data, 0);
        }

        public static UInt64 ReadUInt64(BinaryReader fileBinaryReader)
        {
            var data = fileBinaryReader.ReadBytes(8);
            //Array.Reverse(data);
            return BitConverter.ToUInt64(data, 0);
        }

        public static Int16 ReadInt16(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(2);
            //Array.Reverse(data);
            return BitConverter.ToInt16(data, 0);
        }

        public static Int32 ReadInt32(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(4);
            //Array.Reverse(data);
            return BitConverter.ToInt32(data, 0);
        }

        public static Int64 ReadInt64(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(8);
            //Array.Reverse(data);
            return BitConverter.ToInt64(data, 0);
        }

        public static uint ReadInt8(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            byte data = fileBinaryReader.ReadBytes(1)[0];
            //Array.Reverse(data);
            return data;
        }

        public static UInt16 ReadUInt16(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(2);
            //Array.Reverse(data);
            return BitConverter.ToUInt16(data, 0);
        }

        public static UInt32 ReadUInt32(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(4);
            //Array.Reverse(data);
            return BitConverter.ToUInt32(data, 0);
        }

        public static UInt64 ReadUInt64(BinaryReader fileBinaryReader, long offset)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(8);
            //Array.Reverse(data);
            return BitConverter.ToUInt64(data, 0);
        }

        public static byte[] ReadBytes(BinaryReader fileBinaryReader, long offset, int length)
        {
            fileBinaryReader.BaseStream.Seek(offset, 0);
            var data = fileBinaryReader.ReadBytes(length);
            //Array.Reverse(data);
            return data;
        }
    }
}