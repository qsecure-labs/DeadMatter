using Deadmatter.Templates;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace Deadmatter.Decryptor
{
    public class LsaDecryptor_NT6
    {
        public struct IV_LCD_ECD_Addresses
        {
            public long addrLCD;
            public long distanceECD;
        }

        public static List<LsaDecryptor.LsaKeys> LsaDecryptor(Program.DeadMatter deadmatter, lsaTemplate_NT6.LsaTemplate_NT6 template)
        {
            List<LsaDecryptor.LsaKeys> lsakeysList = new List<LsaDecryptor.LsaKeys>();

            AcquireCryptoMaterial(deadmatter, template, ref lsakeysList);

            return lsakeysList;
        }

        public static void AcquireCryptoMaterial(Program.DeadMatter deadmatter, lsaTemplate_NT6.LsaTemplate_NT6 template, ref List<LsaDecryptor.LsaKeys> lsakeysList)
        {
            if (Globals.debug) { Console.WriteLine(" "); }
            Console.WriteLine("[*] Acquiring crypto stuff...");
            if (Globals.debug) { Console.WriteLine("[*] Searching for signature pattern " + Helpers.ByteArrayToString(template.key_pattern.signature)); }

            
            //Search for the IV based on the current template's pattern
            long sigpos = FindSignature(deadmatter, template);
            if (sigpos == 0)
            {
                Console.WriteLine("[-] Error: IV signature pattern not found but who cares... We don't need it for the decryption of NTLM hashes anyway.");
            }
            else
            {
                if (Globals.debug) { Console.WriteLine("[*] Found IV signature pattern at position " + (sigpos).ToString("X")); }
                deadmatter.fileBinaryReader.BaseStream.Seek(sigpos, 0);
            }

            //Retrieve the IV foudn based on the current template's pattern
            byte[] iv = new byte[16];
            iv = GetIV(deadmatter, sigpos, template);


            /*
            //Get the IV list based on a search of all the IV patterns
            List<IV_Addresses> IVAddrList = new List<IV_Addresses>();
            IVAddrList = search_IVs(deadmatter, Globals.IVsignaturesList);

            Console.WriteLine("[*] Displaying list of valid IV addresses found:");
            if (IVAddrList.Count != 0)
            {
                foreach (IV_Addresses IVAddr in IVAddrList)
                {
                    Console.WriteLine("\t[*] Found IV of " + IVAddr.lsaVersion + " at position " + (IVAddr.address).ToString("X"));
                }
            }
            */

            //Get the list of DES keys found
            List<byte[]> DESkeysList = new List<byte[]>();
            DESkeysList = GetDESKeys(deadmatter);

            //Get the list of AES keys found
            List<byte[]> AESkeysList = new List<byte[]>();
            AESkeysList = GetAESKeys(deadmatter);


            //Add the list of DES and AES keys to the LsaKeys structure list 
            LsaDecryptor.LsaKeys LsaKeys = new LsaDecryptor.LsaKeys();
            foreach (byte[] deskey in DESkeysList)
            {
                LsaKeys.iv = iv;
                LsaKeys.des_key = deskey;
                LsaKeys.aes_key = new byte[0];
                lsakeysList.Add(LsaKeys);
            }

            foreach (byte[] aeskey in AESkeysList)
            {
                LsaKeys.iv = iv;
                LsaKeys.des_key = new byte[0];
                LsaKeys.aes_key = aeskey;
                lsakeysList.Add(LsaKeys);
            }

        }

        //search for a single IV pattern
        public static long FindSignature(Program.DeadMatter deadmatter, lsaTemplate_NT6.LsaTemplate_NT6 template)
        {
            Console.WriteLine("[*] Looking for IV signature pattern...");
            long fl = Helpers.SearchSignature(deadmatter, template.key_pattern.signature);
            if (fl == 0)
            {
                //Console.WriteLine("[-] IV signature not found! ");
                //System.Environment.Exit(0);
            }
            return fl;
        }

        //Loop through all the IV patterns and locate the IV for each of them
        public static List<IV_Addresses> SearchIVs(Program.DeadMatter deadmatter, List<IV_Signatures> IVsignaturesList)
        {
            List<IV_Addresses> validIVsAddrList = new List<IV_Addresses>();
            IV_Addresses validIVAddress = new IV_Addresses();
            foreach (IV_Signatures IVSigItem in IVsignaturesList)
            {
                long IVpos= Helpers.SearchSignature(deadmatter, IVSigItem.signature);
                if (IVpos != 0)
                {
                    Console.WriteLine("[*] Found IV signature pattern " + IVSigItem.lsaVersion + " at position " + (IVpos).ToString("X"));
                    validIVAddress.address = IVpos;
                    validIVAddress.lsaVersion = IVSigItem.lsaVersion;
                    validIVsAddrList.Add(validIVAddress);
                }
            }
            return(validIVsAddrList);
        }

        public static byte[] GetIV(Program.DeadMatter deadmatter, long pos, lsaTemplate_NT6.LsaTemplate_NT6 template)
        {
            Console.WriteLine(" ");
            Console.WriteLine("[*] Reading IV");
            long offset = (pos + template.key_pattern.offset_to_IV_ptr);
            if (Globals.debug) { Console.WriteLine("[*] IV offset from position based on version template is Dec: " + template.key_pattern.offset_to_IV_ptr); }
            if (Globals.debug) { Console.WriteLine("[*] IV JMP offset found at position: " + (offset).ToString("X")); }

            long ptr_iv = (long)Helpers.GetPtrWithOffset(deadmatter.fileBinaryReader, (long)offset, deadmatter.ARCHITECTURE);
            if (Globals.debug) { Console.WriteLine("[*] IV found at position: " + (ptr_iv).ToString("X")); }

            deadmatter.fileBinaryReader.BaseStream.Seek(ptr_iv, 0);
            byte[] data = deadmatter.fileBinaryReader.ReadBytes(template.key_pattern.IV_length);
            Console.WriteLine("[+] IV: " + Helpers.ByteArrayToString(data));

            return data.Take(16).ToArray();
        }

        

        public static List<byte[]> GetDESKeys(Program.DeadMatter deadmatter)
        {
            List<long> addrList = new List<long>();
            List<long> validAddrList = new List<long>();
            List<long> desAddrList = new List<long>();
            byte[] RUUUpattern = new byte[] { 0x52, 0x55, 0x55, 0x55 };

            Console.WriteLine(" ");
            Console.WriteLine("[*] Searching for encryption keys...");

            //Searching for RUUU (little endian) which is actually UUUR (KIWI_BCRYPT_HANDLE_KEY data struct)
            if (Globals.debug) { Console.WriteLine("[*] Searching for candidate KIWI_BCRYPT_HANDLE_KEY data structures."); }
            addrList = Helpers.SearchSignatureTillEnd(deadmatter, RUUUpattern);
            if (addrList.Count == 0)
            {
                if (Globals.debug) { Console.WriteLine("[-] Error: Could not find any KIWI_BCRYPT_HANDLE_KEY data structures... Quitting"); }
                System.Environment.Exit(0);
            }

            if (Globals.debug) { Console.WriteLine("[*] Validating candidate KIWI_BCRYPT_HANDLE_KEY data structures found."); }
            validAddrList = Helpers.ValidateKeyListRetKBHKAddr(deadmatter, addrList);
            if (validAddrList.Count == 0)
            {
                if (Globals.debug) { Console.WriteLine("[-] Error: Could not find any valid key addresses... Quitting"); }
                System.Environment.Exit(0);
            }

            if (Globals.debug) { Console.WriteLine(" "); }
            Console.WriteLine("[*] Acquiring DES keys...");
            int count = 0;
            List<byte[]> listDESkeys = new List<byte[]>();
            desAddrList = Helpers.GetDESKeyKBHKList(deadmatter, validAddrList);
            if (desAddrList.Count == 0)
            {
                Console.WriteLine("[-] Error: Could not find any valid candidate DES key addresses... Quitting");
                System.Environment.Exit(0);
            }
            else
            {
                foreach (long aaddr in desAddrList)
                {
                    if (Globals.debug) { Console.WriteLine("[*] Valid candidate DES key address: " + (string.Format("{0:X}", aaddr))); }
                    deadmatter.fileBinaryReader.BaseStream.Seek(desAddrList[count], 0);

                    byte[] h3DesKeyBytes1 = deadmatter.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_BCRYPT_HANDLE_KEY)));
                    //Console.WriteLine(Helpers.ByteArrayToString(h3DesKeyBytes1));
                    KIWI_BCRYPT_HANDLE_KEY h3DesKey1 = Helpers.ReadStruct<KIWI_BCRYPT_HANDLE_KEY>(h3DesKeyBytes1);

                    byte[] extracted3DesKeyByte1 = deadmatter.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_BCRYPT_KEY81)));
                    KIWI_BCRYPT_KEY81 extracted3DesKey1 = Helpers.ReadStruct<KIWI_BCRYPT_KEY81>(extracted3DesKeyByte1);
                    //Console.WriteLine(Helpers.ByteArrayToString(extracted3DesKeyByte1));
                    Console.WriteLine("[+] Valid candidate DES key: " + Helpers.ByteArrayToString(extracted3DesKey1.hardkey.data.Take(24).ToArray()));

                    listDESkeys.Add(extracted3DesKey1.hardkey.data.Take(24).ToArray());
                    count++;
                }
                
            }

            //We set the Global var so that get_aes_key() can use it and avoid searching the entire memdump for the KIWI_BCRYPT_HANDLE_KEY data structure again
            Globals.gValidAddrList = validAddrList;
            return listDESkeys;
        }

        public static List<byte[]> GetAESKeys(Program.DeadMatter deadmatter)
        {
            List<long> validAddrList = new List<long>();
            List<long> aesAddrList = new List<long>();
            Console.WriteLine(" ");
            Console.WriteLine("[*] Acquiring AES keys...");

            validAddrList = Globals.gValidAddrList;
            if (Globals.debug) { Console.WriteLine("[*] Searching validated addresses for AES keys"); }
            if (Globals.debug) { Console.WriteLine("[*] Getting AES key's KIWI_BCRYPT_HANDLE_KEY data structure addresses."); }
            int count = 0;
            List<byte[]> listAESkeys = new List<byte[]>();
            aesAddrList = Helpers.GetAESKeyKBHKList(deadmatter, validAddrList);
            if (aesAddrList.Count == 0)
            {
                Console.WriteLine("[-] Error: Could not find any valid candidate AES key addresses... Quitting");
                System.Environment.Exit(0);
            }
            else
            {
                foreach (long baddr in aesAddrList)
                {
                    if (Globals.debug) { Console.WriteLine("[*] Valid candidate AES key address: " + (string.Format("{0:X}", baddr))); }
                    deadmatter.fileBinaryReader.BaseStream.Seek(aesAddrList[count], 0);

                    byte[] hAesKeyBytes1 = deadmatter.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_BCRYPT_HANDLE_KEY)));
                    KIWI_BCRYPT_HANDLE_KEY hAesKey1 = Helpers.ReadStruct<KIWI_BCRYPT_HANDLE_KEY>(hAesKeyBytes1);

                    byte[] extractedAesKeyBytes1 = deadmatter.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_BCRYPT_KEY81)));
                    KIWI_BCRYPT_KEY81 extractedAesKey1 = Helpers.ReadStruct<KIWI_BCRYPT_KEY81>(extractedAesKeyBytes1);
                    Console.WriteLine("[+] Valid candidate AES key: " + Helpers.ByteArrayToString(extractedAesKey1.hardkey.data.Take(16).ToArray()));

                    listAESkeys.Add(extractedAesKey1.hardkey.data.Take(16).ToArray());
                    count++;
                }
            }

            return listAESkeys;
        }

        public static List<IV_LCD_ECD_Addresses> LocateCandidateIVSegments(Program.DeadMatter deadmatter)
        {
            List<IV_LCD_ECD_Addresses> listIVSegments = new List<IV_LCD_ECD_Addresses>();
            IV_LCD_ECD_Addresses LCD_ECD_addr = new IV_LCD_ECD_Addresses();
            List<long> patternAddrListIV = new List<long>();
            int blobSizeToSeachForECD = 16384;

            //Local Credential Data pattern UTF16LE
            byte[] bytesLCDPattern = {
                0x4C, 0x00, 0x6F, 0x00, 0x63, 0x00, 0x61, 0x00,
                0x6C, 0x00, 0x20, 0x00, 0x43, 0x00, 0x72, 0x00,
                0x65, 0x00, 0x64, 0x00, 0x65, 0x00, 0x6E, 0x00,
                0x74, 0x00, 0x69, 0x00, 0x61, 0x00, 0x6C, 0x00,
                0x20, 0x00, 0x44, 0x00, 0x61, 0x00, 0x74, 0x00,
                0x61};

            //Enterprise Credential Data pattern UTF16LE
            byte[] bytesECDPattern = {
                0x45, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00,
                0x72, 0x00, 0x70, 0x00, 0x72, 0x00, 0x69, 0x00,
                0x73, 0x00, 0x65, 0x00, 0x20, 0x00, 0x43, 0x00,
                0x72, 0x00, 0x65, 0x00, 0x64, 0x00, 0x65, 0x00,
                0x6E, 0x00, 0x74, 0x00, 0x69, 0x00, 0x61};

            //search for the LCD pattern
            patternAddrListIV = Helpers.SearchSignatureTillEnd(deadmatter, bytesLCDPattern);

            if (Globals.debug) { Console.WriteLine("[*] Total IV LCD patterns found: " + patternAddrListIV.Count); }

            if (patternAddrListIV.Count > 0)
            {
                foreach (long paddr in patternAddrListIV)
                {
                    if (Globals.debug) { Console.WriteLine("[*] IV LCD pattern found at address: " + (string.Format("{0:X}", (paddr)))); }

                    //Get the 16KB after the LCD pattern
                    deadmatter.fileBinaryReader.BaseStream.Seek(paddr, 0);
                    byte[] tempECDChunk = deadmatter.fileBinaryReader.ReadBytes(blobSizeToSeachForECD);

                    //Search the 16KB for the ECD pattern. It should be located shortly after the LCD pattern
                    List<long> tempECDAddrList = new List<long>();
                    tempECDAddrList = Helpers.AllPatternAt(tempECDChunk, bytesECDPattern);

                    if (tempECDAddrList.Count > 0)
                    {
                        foreach (long ecdaddr in tempECDAddrList)
                        {
                            if (Globals.debug) { Console.WriteLine("[*] Found IV ECD pattern after LCD pattern. LCD segment looks valid."); }
                            LCD_ECD_addr.addrLCD = paddr;
                            LCD_ECD_addr.distanceECD = ecdaddr;
                            listIVSegments.Add(LCD_ECD_addr);
                            if (Globals.debug) { Console.WriteLine("[*] Adding " + (string.Format("{0:X}", (paddr + ecdaddr))) + " to the list of valid IV segments"); }
                        }
                    }
                }
            }

            return listIVSegments;
        }


        public static List<long> DeepSearchIVSegments(Program.DeadMatter deadmatter)
        {
            List<long> listIVSegments = new List<long>();
            List<long> patternAddrListIV = new List<long>();
            int blobSizeToSeachForFF00Pattern = 512;
            bool segmentFound = false;

            //Pattern found in Win11 24H2 IV segment containing 0x47, 0x02 and 0x01 bytes
            byte[] bytes470201Pattern = { 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };

            //Pattern with 12 * 0xFF + 4 * 0x00
            byte[] bytesFF00Pattern = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };

            if (Globals.debug) { Console.WriteLine(""); }
            Console.WriteLine("[*] Deep searching for the IV using Win11 24H2 patterns");

            //search for the 470201 Win11 24H2 IV segment pattern
           patternAddrListIV = Helpers.SearchSignatureTillEnd(deadmatter, bytes470201Pattern);

            if (Globals.debug) { Console.WriteLine("[*] Total Win11 24H2 IV segment candidate patterns found: " + patternAddrListIV.Count); }

            if (patternAddrListIV.Count > 0)
            {
                foreach (long paddr in patternAddrListIV)
                {
                    //if (Globals.debug) { Console.WriteLine("[*] IV 0xFF+0x00 pattern found at address: " + (string.Format("{0:X}", (paddr)))); }

                    //Get the 512 bytes after the 470201 Win11 24H2 IV segment pattern
                    deadmatter.fileBinaryReader.BaseStream.Seek(paddr, 0);
                    byte[] tempByteChunk = deadmatter.fileBinaryReader.ReadBytes(blobSizeToSeachForFF00Pattern);

                    //Search the 512 bytes for the 0xFF+0x00 pattern. It should be located around 240 bytes after the 470201 Win11 24H2 IV segment pattern
                    List<long> tempFF00PatternAddrList = new List<long>();
                    tempFF00PatternAddrList = Helpers.AllPatternAt(tempByteChunk, bytesFF00Pattern);

                    if (tempFF00PatternAddrList.Count > 0)
                    {
                        foreach (long ff00PatternAddr in tempFF00PatternAddrList)
                        {  
                            if (ff00PatternAddr >= 200 && ff00PatternAddr <= 300)
                            {
                                //Found 0xFF+0x00 pattern after the IV Win11 24H2 470201 pattern
                                if (Globals.debug) { Console.WriteLine("[*] Found the deep search patterns within " + ff00PatternAddr + " bytes of each other."); }

                                //Get the 144 bytes before the 470201 Win11 24H2 IV segment pattern
                                deadmatter.fileBinaryReader.BaseStream.Seek(paddr - 144, 0);
                                byte[] tempByteChunkBefore470201 = deadmatter.fileBinaryReader.ReadBytes(160);
                                if (Globals.debug)
                                {
                                    //Uncomment the code section below to display the blob preceding the Win11 24H2 470201 pattern 
                                    /*
                                    Console.WriteLine("[*] The blob found before the Win11 24H2 470201 pattern is:");
                                    Console.WriteLine(Helpers.PrintHexBytes(tempByteChunkBefore470201));
                                    Console.WriteLine("[*] Byte 5 of blob is: " + string.Format("{0:X}", (tempByteChunkBefore470201[5])));
                                    Console.WriteLine("[*] Byte 5 + 24 of blob is: " + string.Format("{0:X}", (tempByteChunkBefore470201[29])));
                                    Console.WriteLine("[*] Byte 5 + 32 of blob is: " + string.Format("{0:X}", (tempByteChunkBefore470201[37])));
                                    Console.WriteLine("[*] Byte 5 + 48 of blob is: " + string.Format("{0:X}", (tempByteChunkBefore470201[53])));
                                    Console.WriteLine("[*] Byte 5 + 64 of blob is: " + string.Format("{0:X}", (tempByteChunkBefore470201[69])));
                                    */
                                }

                                if (tempByteChunkBefore470201[5] == 0x7F &&
                                    tempByteChunkBefore470201[5 + 24] == 0x7F &&
                                    tempByteChunkBefore470201[5 + 32] == 0x7F &&
                                    tempByteChunkBefore470201[5 + 48] == 0x7F &&
                                    tempByteChunkBefore470201[5 + 64] == 0x7F)
                                {
                                    if (Globals.debug)
                                    {
                                        Console.WriteLine("[*] Found a VERY GOOD CANDIDATE BLOB that may hold the IV !!!!!!");
                                        Console.WriteLine("[+] Adding " + string.Format("{0:X}", (paddr)) + " to the list of candidate IV segments");
                                    }
                                    listIVSegments.Add(paddr);
                                    segmentFound = true;
                                }
                            }
                        }
                    }
                }
            }

            if (segmentFound)
            {
                return listIVSegments;
            }
            else
            {
                Console.WriteLine("[*] No good candidate blobs found. Will brute-force search the entire list of " + patternAddrListIV.Count + " blobs.");
                return patternAddrListIV;
            }

        }

    }
}