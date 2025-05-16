using Deadmatter.Crypto;
using Deadmatter.Templates;
using System;
using System.Collections.Generic;
using System.Text;
using static Deadmatter.Helpers;

namespace Deadmatter.Decryptor
{
    public class Dpapi_
    {
        public static int FindCredentials(Program.DeadMatter deadmatter)
        {
            List<long> patternAddrListSystem = new List<long>();
            List<long> patternAddrListUser = new List<long>();

            string dpapiLocalMachinePattern = @"C:\Windows\system32\Microsoft\Protect\S-1-5-18\";
            string dpapiSysUserPattern = @"C:\Windows\system32\Microsoft\Protect\S-1-5-18\User\";
            string dpapiUserPattern = @"\AppData\Roaming\Microsoft\Protect\S-";


            byte[] bytesDpapiKeySizePattern = { 0x40, 0x00, 0x00, 0x00 }; //key size 0x40 = 64 bytes
            byte[] userStringBytes = { 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x5C }; // UTF16 - User plus a backslash
            byte[] utf16leBytesDpapiLocalMachinePattern = Encoding.Unicode.GetBytes(dpapiLocalMachinePattern);
            byte[] utf16leBytesDpapiUserPattern = Encoding.Unicode.GetBytes(dpapiUserPattern);

            Console.WriteLine("\n[*] Searching for DPAPI data structures");
            patternAddrListSystem = Helpers.SearchSignatureTillEnd(deadmatter, utf16leBytesDpapiLocalMachinePattern);
            foreach (long paddr in patternAddrListSystem)
            {
                if (paddr == 0)
                    continue;

                if (Globals.debug) { Console.WriteLine("--------------------------------------------------------------------------"); }
                if (Globals.debug) { Console.WriteLine("[*] System level pattern found at address: " + (string.Format("{0:X}", (paddr)))); }
                
                List<long> keySizePatternAddrList = new List<long>();

                //lets check if the key size pattern is found 80 bytes before the Local Machine pattern
                if (paddr > 80)
                {
                    deadmatter.fileBinaryReader.BaseStream.Seek(paddr - 80, 0);
                    byte[] tempChunk = deadmatter.fileBinaryReader.ReadBytes(4);
                    if (Globals.debug) { Console.WriteLine("[*] TempChunk data holding potential key size value: " + Helpers.ByteArrayToString(tempChunk)); }
                    
                    keySizePatternAddrList = AllPatternAt(tempChunk, bytesDpapiKeySizePattern);

                    if (keySizePatternAddrList.Count > 0)
                    {
                        if (Globals.debug) { Console.WriteLine("[*] DPAPI System level account structure passed key size validation check."); }

                        //Get the 10 bytes after the Local Machine pattern to check if it is the System User's DPAPI struct found
                        deadmatter.fileBinaryReader.BaseStream.Seek(paddr + 93, 0);
                        byte[] localMachineAfterBytes = deadmatter.fileBinaryReader.ReadBytes(10);
                        if (Globals.debug) { Console.WriteLine("[*] Bytes following the Local Machine pattern found are: " + Helpers.ByteArrayToString(localMachineAfterBytes)); }

                        if (PrintHexBytes(localMachineAfterBytes) == PrintHexBytes(userStringBytes))
                        {
                            if (Globals.debug)
                            {
                                Console.WriteLine("[*] DPAPI System level account structure is for System User not Local Machine");
                                Console.WriteLine("[*] System User pattern found is: " + dpapiSysUserPattern);
                                Console.WriteLine("--------------------------------------------------------------------------");
                                Console.WriteLine("[*] SID: S-1-5-18");
                                Console.WriteLine("[*] System User DPAPI structure bytes:");
                            }
                            //Get the encrypted DPAPI structure
                            deadmatter.fileBinaryReader.BaseStream.Seek(paddr - 128, 0);
                            byte[] dpapiStructBytes = deadmatter.fileBinaryReader.ReadBytes(120);
                            if (Globals.debug) { Console.WriteLine(Helpers.ByteArrayToString(dpapiStructBytes)); }

                            dpapi.KIWI_MASTERKEY_CACHE_ENTRY dpapiEntry = ReadStruct<dpapi.KIWI_MASTERKEY_CACHE_ENTRY>(dpapiStructBytes);
                            //PrintProperties(dpapiEntry);

                            if (dpapiEntry.keySize > 1)
                            {

                                foreach (LsaDecryptor.LsaKeys lsaKeys in deadmatter.lsakeysList)
                                {
                                    if (lsaKeys.des_key.Length > 0)
                                    {
                                        deadmatter.lsakeys.des_key = lsaKeys.des_key;
                                        deadmatter.lsakeys.iv = lsaKeys.iv;

                                        byte[] dec_masterkey = BCrypt.DecryptCredentials(dpapiEntry.key, deadmatter.lsakeys);
                                        Dpapi dpapi = new Dpapi();
                                        dpapi.luid = $"{dpapiEntry.LogonId.HighPart}:{dpapiEntry.LogonId.LowPart}";
                                        dpapi.masterkey = BitConverter.ToString(dec_masterkey).Replace("-", "");
                                        dpapi.insertTime = $"{ToDateTime(dpapiEntry.insertTime):yyyy-MM-dd HH:mm:ss}";
                                        dpapi.key_size = dpapiEntry.keySize.ToString();
                                        dpapi.key_guid = dpapiEntry.KeyUid.ToString();
                                        dpapi.masterkey_sha = BCrypt.GetHashSHA1(dec_masterkey);

                                        if (Globals.debug)
                                        {
                                            Console.WriteLine("[*] Decryption using DES Key:");
                                            Console.WriteLine(Helpers.ByteArrayToString(lsaKeys.des_key));
                                            Console.WriteLine("[*] Decryption using IV:");
                                            Console.WriteLine(Helpers.ByteArrayToString(lsaKeys.iv));
                                        }

                                        Console.WriteLine($" ");
                                        Console.WriteLine($"=========================================================================");
                                        Console.WriteLine("Decrypted Credentials");
                                        Console.WriteLine("\tDPAPI :");
                                        Console.WriteLine($"\t * SID\t\t: " + "S-1-5-18");
                                        Console.WriteLine($"\t * Username\t: " + "(System User)");
                                        Console.WriteLine($"\t * Logon ID\t: " + dpapi.luid);
                                        Console.WriteLine($"\t * Logon Time\t: " + dpapi.insertTime);
                                        Console.WriteLine($"\t * Key Size\t: " + dpapi.key_size);
                                        Console.WriteLine($"\t * Key GUID\t: " + dpapi.key_guid);
                                        Console.WriteLine($"\t * SHA1(key)\t: " + dpapi.masterkey_sha);
                                        if (Globals.boolValidIV == true)
                                        {
                                            Console.WriteLine($"\t * Master Key\t: " + dpapi.masterkey);
                                        }
                                        else
                                        {
                                            Console.WriteLine($"\t * Master Key\t: " + "<INVALID 8BYTES>" + dpapi.masterkey.Substring(16));
                                        }
                                        Console.WriteLine($"=========================================================================");


                                    }
                                }
                            }
                        }
                        else
                        {
                            if (Globals.debug)
                            {
                                Console.WriteLine("[*] Local Machine pattern found is: " + dpapiLocalMachinePattern);
                                Console.WriteLine("--------------------------------------------------------------------------");
                                Console.WriteLine("[*] SID: S-1-5-18");
                                Console.WriteLine("[*] Local Machine DPAPI structure bytes:");
                            }
                            //Get the encrypted DPAPI structure
                            deadmatter.fileBinaryReader.BaseStream.Seek(paddr - 128, 0);
                            byte[] dpapiStructBytes = deadmatter.fileBinaryReader.ReadBytes(120);
                            if (Globals.debug) { Console.WriteLine(Helpers.ByteArrayToString(dpapiStructBytes)); }

                            dpapi.KIWI_MASTERKEY_CACHE_ENTRY dpapiEntry = ReadStruct<dpapi.KIWI_MASTERKEY_CACHE_ENTRY>(dpapiStructBytes);
                            //PrintProperties(dpapiEntry);
                        
                            if (dpapiEntry.keySize > 1)
                            {

                                foreach (LsaDecryptor.LsaKeys lsaKeys in deadmatter.lsakeysList)
                                {
                                    if (lsaKeys.des_key.Length > 0)
                                    {
                                        deadmatter.lsakeys.des_key = lsaKeys.des_key;
                                        deadmatter.lsakeys.iv = lsaKeys.iv;

                                        byte[] dec_masterkey = BCrypt.DecryptCredentials(dpapiEntry.key, deadmatter.lsakeys);
                                        Dpapi dpapi = new Dpapi();
                                        dpapi.luid = $"{dpapiEntry.LogonId.HighPart}:{dpapiEntry.LogonId.LowPart}";
                                        dpapi.masterkey = BitConverter.ToString(dec_masterkey).Replace("-", "");
                                        dpapi.insertTime = $"{ToDateTime(dpapiEntry.insertTime):yyyy-MM-dd HH:mm:ss}";
                                        dpapi.key_size = dpapiEntry.keySize.ToString();
                                        dpapi.key_guid = dpapiEntry.KeyUid.ToString();
                                        dpapi.masterkey_sha = BCrypt.GetHashSHA1(dec_masterkey);

                                        if (Globals.debug)
                                        {
                                            Console.WriteLine("[*] Decryption using DES Key:");
                                            Console.WriteLine(Helpers.ByteArrayToString(lsaKeys.des_key));
                                            Console.WriteLine("[*] Decryption using IV:");
                                            Console.WriteLine(Helpers.ByteArrayToString(lsaKeys.iv));
                                        }


                                        Console.WriteLine($" ");
                                        Console.WriteLine($"=========================================================================");
                                        Console.WriteLine("Decrypted Credentials");
                                        Console.WriteLine("\tDPAPI :");
                                        Console.WriteLine($"\t * SID\t\t: " + "S-1-5-18");
                                        Console.WriteLine($"\t * Username\t: " + "(Local Machine)");
                                        Console.WriteLine($"\t * Logon ID\t: " + dpapi.luid);
                                        Console.WriteLine($"\t * Logon Time\t: " + dpapi.insertTime);
                                        Console.WriteLine($"\t * Key Size\t: " + dpapi.key_size);
                                        Console.WriteLine($"\t * Key GUID\t: " + dpapi.key_guid);
                                        Console.WriteLine($"\t * SHA1(key)\t: " + dpapi.masterkey_sha);
                                        if (Globals.boolValidIV == true)
                                        {
                                            Console.WriteLine($"\t * Master Key\t: " + dpapi.masterkey);
                                        }
                                        else
                                        {
                                            Console.WriteLine($"\t * Master Key\t: " + "<INVALID 8BYTES>" + dpapi.masterkey.Substring(16));
                                        }
                                        Console.WriteLine($"=========================================================================");

                                    }
                                }
                            }
                        }
                    }
                }
            }


            patternAddrListUser = Helpers.SearchSignatureTillEnd(deadmatter, utf16leBytesDpapiUserPattern);
            foreach (long puaddr in patternAddrListUser)
            {
                if (puaddr == 0)
                    continue;

                string SID = "";
                string username = "";

                if (Globals.debug) { Console.WriteLine("--------------------------------------------------------------------------"); }
                if (Globals.debug) { Console.WriteLine("[*] User level pattern found at address: " + (string.Format("{0:X}", (puaddr)))); }
                
                //lets check if the C Drive pattern is found within the 80 bytes before the User pattern
                if (puaddr > 80)
                {
                    deadmatter.fileBinaryReader.BaseStream.Seek(puaddr - 80, 0);
                    byte[] tempCDriveChunk = deadmatter.fileBinaryReader.ReadBytes(80);
                    if (Globals.debug) { Console.WriteLine("[*] TempCDriveChunk data holding the C Drive pattern: " + Helpers.ByteArrayToString(tempCDriveChunk)); }

                    List<long> cDrivePatternAddrList = new List<long>();
                    byte[] bytesCDrivePattern = { 0x00, 0x43, 0x00, 0x3A, 0x00, 0x5C }; // C: plus backslash
                    cDrivePatternAddrList = AllPatternAt(tempCDriveChunk, bytesCDrivePattern);
                    if (Globals.debug) { Console.WriteLine("[*] Searching for C:\\ pattern"); }

                    //At least one C Drive pattern was found in the chunk
                    if (cDrivePatternAddrList.Count > 0)
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Found C:\\ pattern"); }
                        long addrCDrive = cDrivePatternAddrList[cDrivePatternAddrList.Count - 1];
                        int lengthCDriveUsernamePath = tempCDriveChunk.Length - (int)addrCDrive - 1;
                        if (Globals.debug) { Console.WriteLine("[*] The length of C:\\Users\\<USERNAME> in UTF16 is: " + lengthCDriveUsernamePath); }

                        byte[] tempUserKeySizeChunk;
                        List<long> keySizeUserPatternAddrList = new List<long>();
                        byte[] tempSIDChunk;
                        List<long> sidAddrList = new List<long>();

                        //lets check if the key size is found 80 bytes before the C Drive pattern
                        if (puaddr - lengthCDriveUsernamePath > 80)
                        {
                            if (Globals.debug) { Console.WriteLine("[*] Space before pattern is greater then 80 bytes so it is safe to proceed"); }
                            deadmatter.fileBinaryReader.BaseStream.Seek(puaddr - lengthCDriveUsernamePath - 80, 0);
                            tempUserKeySizeChunk = deadmatter.fileBinaryReader.ReadBytes(4);
                            keySizeUserPatternAddrList = AllPatternAt(tempUserKeySizeChunk, bytesDpapiKeySizePattern);
                            if (Globals.debug) { Console.WriteLine("[*] The user structure key size chunk bytes are: " + Helpers.ByteArrayToString(tempUserKeySizeChunk)); }

                            //check if the key size search returned any findings
                            if (keySizeUserPatternAddrList.Count > 0)
                            {
                                if (Globals.debug) { Console.WriteLine("[*] DPAPI User level account structure passed key size validation check."); }

                                if (Globals.debug) { Console.WriteLine("--------------------------------------------------------------------------"); }
                                //Lets extract the Username
                                //Get the bytes between the C: backslash and the User pattern to extract the Username
                                deadmatter.fileBinaryReader.BaseStream.Seek(puaddr - lengthCDriveUsernamePath + 18, 0);
                                byte[] usernameBytes = deadmatter.fileBinaryReader.ReadBytes(lengthCDriveUsernamePath - 18);
                                username = Encoding.Unicode.GetString(usernameBytes);
                                if (Globals.debug) { Console.WriteLine("[*] Username: " + username); }

                                //Lets extract the user's SID
                                byte[] bytesBackslashPattern = { 0x00, 0x5C }; // UTF16 backslash
                                deadmatter.fileBinaryReader.BaseStream.Seek(puaddr + (dpapiUserPattern.Length * 2), 0); //move the pointer after the User pattern.  x2 because the pattern is a UTF16 string
                                tempSIDChunk = deadmatter.fileBinaryReader.ReadBytes(55 * 2); // get enough bytes to contain the SID. x2 because it is a UTF16 string
                                sidAddrList = AllPatternAt(tempSIDChunk, bytesBackslashPattern);

                                //check if the search for the SID ending backslash has returned any findings
                                if (sidAddrList.Count > 0)
                                {
                                    if (Globals.debug) { Console.WriteLine("[*] SID chunk " + Helpers.ByteArrayToString(tempSIDChunk)); }

                                    //Get the bytes after the User pattern and before the next backslash to extract the User SID
                                    byte[] sidBytes = GetBytes(tempSIDChunk, 0, (int)sidAddrList[0] + 1);
                                    SID = "S-" + Encoding.Unicode.GetString(sidBytes);
                                    if (Globals.debug) { Console.WriteLine("[*] SID: " + SID); }

                                }

                                //Lets extract the DPAPI structure bytes
                                if (Globals.debug) { Console.WriteLine("[*] User DPAPI structure bytes:"); }
                                deadmatter.fileBinaryReader.BaseStream.Seek(puaddr - lengthCDriveUsernamePath - 128, 0);
                                byte[] dpapiStructBytes = deadmatter.fileBinaryReader.ReadBytes(120);
                                if (Globals.debug) { Console.WriteLine(Helpers.ByteArrayToString(dpapiStructBytes)); }

                                dpapi.KIWI_MASTERKEY_CACHE_ENTRY dpapiEntry = ReadStruct<dpapi.KIWI_MASTERKEY_CACHE_ENTRY>(dpapiStructBytes);
                                //PrintProperties(dpapiEntry);

                                if (dpapiEntry.keySize > 1)
                                {
                                    
                                    foreach (LsaDecryptor.LsaKeys lsaKeys in deadmatter.lsakeysList)
                                    {
                                        if (lsaKeys.des_key.Length > 0)
                                        {
                                            deadmatter.lsakeys.des_key = lsaKeys.des_key;
                                            deadmatter.lsakeys.iv = lsaKeys.iv;

                                            byte[] dec_masterkey = BCrypt.DecryptCredentials(dpapiEntry.key, deadmatter.lsakeys);
                                            Dpapi dpapi = new Dpapi();
                                            dpapi.luid = $"{dpapiEntry.LogonId.HighPart}:{dpapiEntry.LogonId.LowPart}";
                                            dpapi.masterkey = BitConverter.ToString(dec_masterkey).Replace("-", "");
                                            dpapi.insertTime = $"{ToDateTime(dpapiEntry.insertTime):yyyy-MM-dd HH:mm:ss}";
                                            dpapi.key_size = dpapiEntry.keySize.ToString();
                                            dpapi.key_guid = dpapiEntry.KeyUid.ToString();
                                            dpapi.masterkey_sha = BCrypt.GetHashSHA1(dec_masterkey);

                                            if (Globals.debug)
                                            {
                                                Console.WriteLine("[*] Decryption using DES Key:");
                                                Console.WriteLine(Helpers.ByteArrayToString(lsaKeys.des_key));
                                                Console.WriteLine("[*] Decryption using IV:");
                                                Console.WriteLine(Helpers.ByteArrayToString(lsaKeys.iv));
                                            }

                                            Console.WriteLine($" ");
                                            Console.WriteLine($"=========================================================================");
                                            Console.WriteLine("Decrypted Credentials");
                                            Console.WriteLine("\tDPAPI :");
                                            Console.WriteLine($"\t * SID\t\t: " + SID);
                                            Console.WriteLine($"\t * Username\t: " + username);
                                            Console.WriteLine($"\t * Logon ID\t: " + dpapi.luid);
                                            Console.WriteLine($"\t * Logon Time\t: " + dpapi.insertTime);
                                            Console.WriteLine($"\t * Key Size\t: " + dpapi.key_size);
                                            Console.WriteLine($"\t * Key GUID\t: " + dpapi.key_guid);
                                            Console.WriteLine($"\t * SHA1(key)\t: " + dpapi.masterkey_sha);
                                            if (Globals.boolValidIV == true)
                                            {
                                                Console.WriteLine($"\t * Master Key\t: " + dpapi.masterkey);
                                            }
                                            else
                                            {
                                                Console.WriteLine($"\t * Master Key\t: " + "<INVALID 8BYTES>" + dpapi.masterkey.Substring(16));
                                            }
                                            Console.WriteLine($"=========================================================================");

                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return 0;
        }
    }
}