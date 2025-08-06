using Deadmatter.Crypto;
using Deadmatter.Templates;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
using static Deadmatter.Helpers;

namespace Deadmatter.Decryptor
{
    public class Msv1_
    {
        public const int LM_NTLM_HASH_LENGTH = 16;
        public const int SHA_DIGEST_LENGTH = 20;

        public static int FindCredentials(Program.DeadMatter deadmatter, msv.MsvTemplate template, List<long> addrList)
        {
            //PrintProperties(template);
            string osVersion = "";
            bool bruteSearched = false;
            bool ivMsgDisplayed = false;

            var msventry = new Msv();
            KIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;

            byte[] iv = deadmatter.lsakeysList[0].iv;      //we get the first LsaKeys IV entry because they all have the same IV

            //Setup our list of AES keys before proceeding with the processing of MSV Credential structures
            List<byte[]> AESkeysList = new List<byte[]>();
            foreach (LsaDecryptor.LsaKeys lsa_keys in deadmatter.lsakeysList)
            {
                if (lsa_keys.aes_key != null && lsa_keys.aes_key.Length > 0)
                {
                    AESkeysList.Add(lsa_keys.aes_key);
                }
            }

            //Setup our list of 3DES keys before proceeding with the processing of MSV Credential structures
            List<byte[]> DESkeysList = new List<byte[]>();
            foreach (LsaDecryptor.LsaKeys lsa_keys in deadmatter.lsakeysList)
            {
                if (lsa_keys.des_key != null && lsa_keys.des_key.Length > 0)
                {
                    DESkeysList.Add(lsa_keys.des_key);
                }
            }

            int msvCount = 0;
            //Process each MSV Credential structure found
            foreach (long lsasscred in addrList)
            {
                msvCount += 1;
                //if (Globals.debug) { Console.WriteLine($"[*] PrimaryCredentials struct Physical Address in Hex: " + (string.Format("{0:X}", lsasscred))); }

                deadmatter.fileBinaryReader.BaseStream.Seek(lsasscred, 0);
                //if (Globals.debug) { Console.WriteLine($"[*] PrimaryCredentials - About to read this number of bytes: " + Marshal.SizeOf(typeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS))); }
                byte[] primaryCredentialsBytes = deadmatter.fileBinaryReader.ReadBytes(Marshal.SizeOf(typeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS)));

                primaryCredentials = ReadStruct<KIWI_MSV1_0_PRIMARY_CREDENTIALS>(primaryCredentialsBytes);
                primaryCredentials.Credentials = ExtractUnicodeString(deadmatter.fileBinaryReader, lsasscred + template.MSV1CredentialsOffset);

                //32 bytes forward from where the virtual address is stored, we can find the actual physical position of the MSV Credentials structure
                primaryCredentials.Credentials.Buffer = lsasscred + template.MSV1CredentialsOffset + 24;
                //if (Globals.debug) { Console.WriteLine($"[*] PrimaryCredentials physical address in Hex (physical position of MSV Credentials struct): " + (string.Format("{0:X}", (primaryCredentials.Credentials.Buffer)))); }


                primaryCredentials.Primary = ExtractUnicodeString(deadmatter.fileBinaryReader, lsasscred + template.MSV1PrimaryOffset);
                if (Globals.debug)
                {
                    //Console.WriteLine($"[*] Primary word string WRONG address in Hex (position of len, maxlen, virtual address): " + (string.Format("{0:X}", (lsasscred + template.MSV1PrimaryOffset))));
                    Console.WriteLine($"[*] Primary word string length is: " + primaryCredentials.Primary.Length);
                    Console.WriteLine($"[*] Primary word string maxlength is: " + primaryCredentials.Primary.MaximumLength);
                }

                //32 bytes forward from where the virtual address is stored, we can find the actual physical position of the Primary text string
                primaryCredentials.Primary.Buffer = lsasscred + template.MSV1PrimaryOffset + 32;
                if (Globals.debug) { Console.WriteLine($"[*] Primary word string physical address in Hex (physical position of word): " + (string.Format("{0:X}", (primaryCredentials.Primary.Buffer)))); }

                if (ExtractANSIStringString(deadmatter, primaryCredentials.Primary).Equals("Primary"))
                {
                    if (Globals.debug) { Console.WriteLine($"[*] MSV Credentials structure PASSED CHECK "); }

                    if (Globals.debug)
                    {
                        Console.WriteLine($"[*] msvCredentialsBytes buffer physical address in Hex: " + (string.Format("{0:X}", (primaryCredentials.Credentials.Buffer))));
                        Console.WriteLine($"[*] msvCredentialsBytes buffer maxlength in Dec: " + (primaryCredentials.Credentials.MaximumLength));
                        Console.WriteLine($"[*] msvCredentialsBytes buffer maxlength in Hex: " + (string.Format("{0:X}", (primaryCredentials.Credentials.MaximumLength))));
                        Console.WriteLine($"[*] msvCredentialsBytes buffer length in Dec: " + (primaryCredentials.Credentials.Length));
                        Console.WriteLine($"[*] msvCredentialsBytes buffer length in Hex: " + (string.Format("{0:X}", (primaryCredentials.Credentials.Length))));
                    }

                    //Get the MSV credentials blob
                    deadmatter.fileBinaryReader.BaseStream.Seek(primaryCredentials.Credentials.Buffer, 0);
                    byte[] msvCredentialsBytes = deadmatter.fileBinaryReader.ReadBytes(primaryCredentials.Credentials.MaximumLength);

                    /*
                    //Uncomment the below 2 lines to display the encrypted MSV Credential struct hex bytes
                    if (Globals.debug) 
                    {
                        Console.WriteLine("msvCredentialsBytes (PRIMARY_CREDENTIAL struct):");
                        Console.WriteLine("--" + Helpers.ByteArrayToString(msvCredentialsBytes));
                    }
                    */

                    List<byte[]> keysList = new List<byte[]>();
                    if (msvCredentialsBytes.Length % 8 != 0)
                    {
                        keysList = AESkeysList;
                    }
                    else
                    {
                        keysList = DESkeysList;
                    }

                    
                    foreach (byte[] key in keysList)
                    {
                        //LsaDecryptor.LsaKeys tempLsaKeys = new LsaDecryptor.LsaKeys();
                        if (msvCredentialsBytes.Length % 8 != 0)
                        {
                            if (Globals.debug) { Console.WriteLine("[*] Decryption will happen with AES"); }
                            //tempLsaKeys.aes_key = key;
                            deadmatter.lsakeys.aes_key = key;
                            deadmatter.lsakeys.iv = iv;
                        }
                        else
                        {
                            if (Globals.debug) { Console.WriteLine("[*] Decryption will happen with 3DES"); }
                            //tempLsaKeys.des_key = key;
                            deadmatter.lsakeys.des_key = key;
                            deadmatter.lsakeys.iv = iv;
                        }

                        //DECRYPT THE MSV STRUCTURE
                        var msvDecryptedCredentialsBytes = BCrypt.DecryptCredentials(msvCredentialsBytes, deadmatter.lsakeys);

                        var usLogonDomainName = ReadStruct<UNICODE_STRING>(GetBytes(msvDecryptedCredentialsBytes, template.LogonDomainNameOffset, Marshal.SizeOf(typeof(UNICODE_STRING))));
                        var usUserName = ReadStruct<UNICODE_STRING>(GetBytes(msvDecryptedCredentialsBytes, template.UserNameOffset, Marshal.SizeOf(typeof(UNICODE_STRING))));

                        //CHECK IF THE CURRENTLY DECRYPTED MSV STRUCTURE IS VALID. IF IT IS NOT, MOVE ON TO THE NEXT AVAILABLE KEY
                        //If the position of the username string is beyond the MSV Credential structure
                        //or if the size of the username is too big,
                        //then the current MSV Credential structure is either invalid or failed decryption
                        //hence move on to the next MSV address in the list
                        if (usUserName.Buffer > primaryCredentials.Credentials.MaximumLength || usUserName.Length > 256 || msvDecryptedCredentialsBytes[17] != 0x00 || msvDecryptedCredentialsBytes[19] != 0x00)
                        {
                            if (Globals.debug) { Console.WriteLine("[*] The current MSV Credential structure at " + (string.Format("{0:X}", (primaryCredentials.Credentials.Buffer))) + " is either invalid or failed decryption using key " + Helpers.ByteArrayToString(deadmatter.lsakeys.des_key)); }
                            continue;
                        }

                        //------------------------------- START OF SECTION FOR BRUTEFORCE SEARCHING THE CORRECT IV ---------------------------------------

                        if (Globals.bSearch)
                        {
                            //Check if we already brute-force searched for the IV and skip the process if we already did
                            if (bruteSearched == false)
                            {
                                //Identify segments that may contain the IV so that we can perform IV carving on them
                                Console.WriteLine("\n[*] Brute-force searching for the IV");
                                if (Globals.debug) { Console.WriteLine("[*] Searching for IV LCD patterns"); }
                                List<LsaDecryptor_NT6.IV_LCD_ECD_Addresses> ivSegmentsAddrList = new List<LsaDecryptor_NT6.IV_LCD_ECD_Addresses>();
                                ivSegmentsAddrList = LsaDecryptor_NT6.LocateCandidateIVSegments(deadmatter);

                                byte[] ivSegmentArray = new byte[] { };
                                long segmentSize = Globals.bSearchSize * 1024;      //1KB increments
                                Console.WriteLine("[*] Searching for the IV in the " + Globals.bSearchSize + "KB blob before the LCD upto the ECD");
                                LsaDecryptor.LsaKeys lsaKeys = new LsaDecryptor.LsaKeys();
                                lsaKeys = deadmatter.lsakeys;

                                foreach (LsaDecryptor_NT6.IV_LCD_ECD_Addresses LCD_ECD_addr in ivSegmentsAddrList)
                                {
                                    //Get the IV Segment blob
                                    deadmatter.fileBinaryReader.BaseStream.Seek(LCD_ECD_addr.addrLCD - segmentSize, 0);
                                    ivSegmentArray = deadmatter.fileBinaryReader.ReadBytes((int)(segmentSize + LCD_ECD_addr.distanceECD)); //segmentSize + the destance from LCD to ECD

                                    //Uncomment the line below to display the selected IV Segment blob
                                    //if (Globals.debug) { Console.WriteLine(Helpers.ByteArrayToString(ivSegmentArray));}

                                    byte[] validIV = BruteforceSearchValidIV(ivSegmentArray, msvCredentialsBytes, lsaKeys);
                                    byte[] nullBytes16 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                                    if (!validIV.SequenceEqual(nullBytes16))
                                    {
                                        Console.WriteLine("[+] IV: " + Helpers.ByteArrayToString(validIV));
                                        deadmatter.lsakeys.iv = validIV;
                                        iv = validIV;   //Need to set this because in every iteration it gets assigned to deadmatter.lsakeys.iv
                                        Globals.boolValidIV = true;
                                    }
                                    else
                                    {

                                        //Seaching again while allowing the IV to contain as many null bytes as its entire length
                                        //This is a slower search as evey byte in the ivSegmentArray will create a new key and a new decryption process
                                        if (Globals.debug) { Console.WriteLine("[*] IV was not found during the 1st pass. Attempting a 2nd pass with less strict rules."); }
                                        validIV = BruteforceSearchValidIVwithNulls(ivSegmentArray, msvCredentialsBytes, lsaKeys);
                                        if (!validIV.SequenceEqual(nullBytes16))
                                        {
                                            Console.WriteLine("[*] Found valid IV using brute-force search during 2nd pass");
                                            Console.WriteLine("[+] IV: " + Helpers.ByteArrayToString(validIV));
                                            deadmatter.lsakeys.iv = validIV;
                                            iv = validIV;   //Need to set this because in every iteration it gets assigned to deadmatter.lsakeys.iv
                                            Globals.boolValidIV = true;
                                        }
                                        else
                                        {
                                            if (Globals.debug) { Console.WriteLine("[*] IV was not found during the 2nd pass either."); }

                                            if (deadmatter.BUILDNUMBER >= 26100)
                                            {
                                                List<long> deepIVSegmentsList = LsaDecryptor_NT6.DeepSearchIVSegments(deadmatter);
                                                if (deepIVSegmentsList.Count > 0)
                                                {
                                                    byte[] ivDeepSegmentArray = new byte[] { };
                                                    foreach (long deepSegmentAddr in deepIVSegmentsList)
                                                    {
                                                        //Get the candiate IV segment blob (512 bytes in total. 144 bytes before the 470201 pattern and 368 after it)
                                                        deadmatter.fileBinaryReader.BaseStream.Seek(deepSegmentAddr - 144, 0);
                                                        ivDeepSegmentArray = deadmatter.fileBinaryReader.ReadBytes((int)(512));

                                                        validIV = BruteforceSearchValidIVwithNulls(ivDeepSegmentArray, msvCredentialsBytes, lsaKeys);
                                                        if (!validIV.SequenceEqual(nullBytes16))
                                                        {
                                                            Console.WriteLine("[*] Found valid IV using brute-force deep search");
                                                            Console.WriteLine("[+] IV: " + Helpers.ByteArrayToString(validIV));
                                                            deadmatter.lsakeys.iv = validIV;
                                                            iv = validIV;   //Need to set this because in every iteration it gets assigned to deadmatter.lsakeys.iv
                                                            Globals.boolValidIV = true;
                                                            break;
                                                        }

                                                    }
                                                }
                                                else
                                                {
                                                    Console.WriteLine("[*] Deep seach produced no results.");
                                                    Console.WriteLine("[*] IV could not be located. Without a valid IV the DPAPI master keys cannot be fully decrypted.\n");
                                                }
                                            }
                                            else
                                            {
                                                Console.WriteLine("[*] IV could not be located. Without a valid IV the DPAPI master keys cannot be fully decrypted.\n");
                                            }
                                        }
                                        
                                    }
                                }

                                bruteSearched = true;
                            }
                        }

                        //------------------------------- END OF SECTION FOR BRUTEFORCE SEARCHING THE CORRECT IV ---------------------------------------

                        // ----------- CHECK IV VALIDITY -----------
                        //If the decryption of the first MSV bytes is successful or we brute-force found the IV that means the IV is valid so set the Global variable to true
                        //I put this check here because the previous one happens only in debug mode and I need to set the Global IV var during normal operation flow
                        if ((msvDecryptedCredentialsBytes[1] == 0x00 &&
                            msvDecryptedCredentialsBytes[3] == 0x00 &&
                            msvDecryptedCredentialsBytes[4] == 0x00 &&
                            msvDecryptedCredentialsBytes[5] == 0x00 &&
                            msvDecryptedCredentialsBytes[6] == 0x00 &&
                            msvDecryptedCredentialsBytes[7] == 0x00) || Globals.boolValidIV == true)
                        {
                            Globals.boolValidIV = true;
                            if (!ivMsgDisplayed)
                            {
                                Console.WriteLine($"[*] The IV found is valid!!!");
                                if (Globals.debug) { Console.WriteLine(""); }
                                ivMsgDisplayed = true;      //set this so the msg is displayed only once and not in every loop
                            }
                        }
                        else
                        {
                            if (!ivMsgDisplayed)
                            {
                                Console.WriteLine($"[*] The IV found is not valid!!!");
                                if (Globals.debug) { Console.WriteLine(""); }
                                ivMsgDisplayed = true;      //set this so the msg is displayed only once and not in every loop
                            }
                        }

                        //-------------------------- START OF SECTION FOR MSV VERSION IDENTIFICATION AND CREDENTIALS CARVING ---------------------------

                        if (Globals.idOS)
                        {
                            if (String.IsNullOrEmpty(osVersion))
                            {
                                osVersion = IdentifyOS(GetBytes(msvDecryptedCredentialsBytes, 0, msvDecryptedCredentialsBytes.Length));

                                Console.WriteLine($"\n*************************************************************************\n");
                                if (osVersion == "Win_8.1_2012R2")
                                {
                                    Console.WriteLine("[+] OS Version Detected: ");
                                    Console.WriteLine("\tWindows 8.1 / 2012 R2");
                                }
                                else if (osVersion == "Win_10_1507")
                                {
                                    Console.WriteLine("[+] OS Version Detected: ");
                                    Console.WriteLine("\tWindows 10 1507");
                                }
                                else if (osVersion == "Win_10_1607_2016")
                                {
                                    Console.WriteLine("[+] OS Version Detected: ");
                                    Console.WriteLine("\tWindows 10 1607 / 2016");
                                }
                                else if (osVersion == "Win_10_1607-11_23H2")
                                {
                                    Console.WriteLine("[+] OS Version Detected: ");
                                    Console.WriteLine("\tWindows 10 1607 - Windows 11 23H2");
                                }
                                else if (osVersion == "Win_11_24H2")
                                {
                                    Console.WriteLine("[+] OS Version Detected: ");
                                    Console.WriteLine("\tWindows 11 24H2 or later");
                                }
                                else
                                {
                                    Console.WriteLine("[-] Error in OS detection ");
                                }
                                Console.WriteLine($"\n*************************************************************************");

                            }
                        }

                        if (Globals.mode == "carve" || Globals.mode == "both")
                        {
                            CarveHashes(msvDecryptedCredentialsBytes, msvCount);
                        }

                        //---------------------------- END OF SECTION FOR MSV VERSION IDENTIFICATION AND CREDENTIALS CARVING ---------------------------

                        if (Globals.debug)
                        {
                            //The below 2 lines display the decrypted MSV Credential struct hex bytes
                            Console.WriteLine("[*] msvDecryptedCredentialsBytes (PRIMARY_CREDENTIAL struct):");
                            Console.WriteLine("-- " + Helpers.ByteArrayToString(msvDecryptedCredentialsBytes));

                            //Check the validity of the IV based on the successful decryption of the first 8 bytes of the MSV struct for 3DES
                            //and 16 bytes for AES. There should be a lot of null bytes except at position 0 which specifies the Domain Length
                            //and position 2 which specifies the Domain Max Length. If the IV is not the correct one, we need to find out the 
                            //Domain Length manually.
                            if (msvDecryptedCredentialsBytes[1] == 0x00 &&
                                msvDecryptedCredentialsBytes[3] == 0x00 &&
                                msvDecryptedCredentialsBytes[4] == 0x00 &&
                                msvDecryptedCredentialsBytes[5] == 0x00 &&
                                msvDecryptedCredentialsBytes[6] == 0x00 &&
                                msvDecryptedCredentialsBytes[7] == 0x00)
                            {
                                Console.WriteLine($"[*] The first bytes (8 or 16) of the MSV Credential struct have been decrypted successfully.");
                                Console.WriteLine($"[*] The IV found is the correct one!!!");
                            }
                            else
                            {
                                Console.WriteLine($"[*] The first bytes (8 or 16) of the MSV Credential struct failed decryption.");
                                Console.WriteLine($"[*] The IV found is the wrong one, but we can extract the Domain string without it.");
                            }

                            Console.WriteLine($"[*] Username addresses blob offest: " + template.UserNameOffset);
                            Console.WriteLine($"[*] Username addresses blob size: " + Marshal.SizeOf(typeof(UNICODE_STRING)));
                            Console.WriteLine($"[*] Username blob start position in Dec: " + usUserName.Buffer);
                            Console.WriteLine($"[*] Username blob start position in Hex: " + (string.Format("{0:X}", (usUserName.Buffer))));
                            Console.WriteLine($"[*] Username (UTF-16LE) length : " + usUserName.Length);
                            Console.WriteLine($"[*] Username (UTF-16LE) maxlength: " + usUserName.MaximumLength);
                            Console.WriteLine($"[*] Username bytes: " + Helpers.ByteArrayToString(GetBytes(msvDecryptedCredentialsBytes, usUserName.Buffer, usUserName.Length)));
                            Console.WriteLine($"[+] Username cleartext: " + Encoding.Unicode.GetString(GetBytes(msvDecryptedCredentialsBytes, usUserName.Buffer, usUserName.Length)));
                            Console.WriteLine($"[*] Domain addresses blob offest: " + template.LogonDomainNameOffset);
                            Console.WriteLine($"[*] Domain addresses blob size: " + Marshal.SizeOf(typeof(UNICODE_STRING)));
                            Console.WriteLine($"[*] Domain blob start position in Dec: " + usLogonDomainName.Buffer);
                            Console.WriteLine($"[*] Domain blob start position in Hex: " + (string.Format("{0:X}", (usLogonDomainName.Buffer))));
                            Console.WriteLine($"[*] Domain (UTF-16LE) length: " + usLogonDomainName.Length);
                            Console.WriteLine($"[*] Domain (UTF-16LE) maxlength: " + usLogonDomainName.MaximumLength);
                        }

                                               

                        //Check if the decryption will happen with AES, the IV is not valid and hence decryption of the first 16 bytes will fail 
                        //If it fails the Domain buffer offset/position may be past the end of the MSV struct and/or bytes 11-16 of the MSV struct won't be 0x00
                        if ((usLogonDomainName.Buffer > primaryCredentials.Credentials.Length || Globals.boolValidIV == false) &&
                        (msvCredentialsBytes.Length % 8 != 0) &&
                        msvDecryptedCredentialsBytes[10] == 0x00 &&
                        msvDecryptedCredentialsBytes[11] == 0x00 &&
                        msvDecryptedCredentialsBytes[12] == 0x00 &&
                        msvDecryptedCredentialsBytes[13] == 0x00 &&
                        msvDecryptedCredentialsBytes[14] == 0x00 &&
                        msvDecryptedCredentialsBytes[15] == 0x00)
                        {
                            //Set the size of the Domain buffer to 32 bytes. It starts 32 bytes before the Username buffer
                            usLogonDomainName.Buffer = usUserName.Buffer - 32;
                            if (Globals.debug)
                            {
                                Console.WriteLine($"[*] AES decryption with invalid IV detected. Domain buffer offset was wrong.");
                                Console.WriteLine($"[*] Corrected/adjusted domain buffer start position in Dec: " + usLogonDomainName.Buffer);
                            }

                        }

                        //Check the validity of the Domain based on its length or whether the IV was valid and we managed to decrypt
                        //the first 8 bytes of the MSV struct (if 3DES was used), which hold the Domain Length and Domain Max Length.
                        if (usLogonDomainName.Length > 32 || Globals.boolValidIV == false)
                        {
                            //The Domain Max Length is the difference between the start of the Domain buffer and the start of the Username buffer
                            usLogonDomainName.MaximumLength = Convert.ToUInt16(usUserName.Buffer - usLogonDomainName.Buffer);

                            //Initally setting the Domain Length to the entire size of the Domain buffer (i.e. around 32 bytes)
                            usLogonDomainName.Length = usLogonDomainName.MaximumLength;
                            byte[] domainBlockByteArray = GetBytes(msvDecryptedCredentialsBytes, usLogonDomainName.Buffer, usLogonDomainName.Length);

                            // Loop through the array two bytes at a time
                            for (int i = 0; i < domainBlockByteArray.Length - 1; i += 2)
                            {
                                // Check if both bytes are equal to 0x00
                                if (domainBlockByteArray[i] == 0x00 && domainBlockByteArray[i + 1] == 0x00 && i >= 2)
                                {
                                    usLogonDomainName.Length = Convert.ToUInt16(i);
                                    break;
                                }
                            }
                            if (Globals.debug)
                            {
                                Console.WriteLine($"[*] Domain (UTF-16LE) corrected length: " + usLogonDomainName.Length);
                                Console.WriteLine($"[*] Domain (UTF-16LE) corrected maxlength: " + usLogonDomainName.MaximumLength);
                            }
                        }

                        if (Globals.debug)
                        {
                            Console.WriteLine($"[*] Domain bytes: " + Helpers.ByteArrayToString(GetBytes(msvDecryptedCredentialsBytes, usLogonDomainName.Buffer, usLogonDomainName.Length)));
                            Console.WriteLine($"[+] Domain cleartext: " + Encoding.Unicode.GetString(GetBytes(msvDecryptedCredentialsBytes, usLogonDomainName.Buffer, usLogonDomainName.Length)));
                            Console.WriteLine($"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                        }

                        msventry = new Msv();
                        msventry.DomainName = Encoding.Unicode.GetString(GetBytes(msvDecryptedCredentialsBytes, usLogonDomainName.Buffer, usLogonDomainName.Length));
                        msventry.UserName = "  " + Encoding.Unicode.GetString(GetBytes(msvDecryptedCredentialsBytes, usUserName.Buffer, usUserName.Length));

                        string lmhash = PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.LmOwfPasswordOffset, LM_NTLM_HASH_LENGTH));
                        if (lmhash != "00000000000000000000000000000000")
                            msventry.Lm = "     " + lmhash;

                        if (Globals.debug)
                        {
                            Console.WriteLine($"[*] LM hash offest: " + template.LmOwfPasswordOffset);
                            Console.WriteLine($"[*] LM hash length is 16 bytes");
                            Console.WriteLine($"[*] LM hash bytes: " + Helpers.ByteArrayToString(GetBytes(msvDecryptedCredentialsBytes, template.LmOwfPasswordOffset, LM_NTLM_HASH_LENGTH)));
                            Console.WriteLine($"[+] LM hash cleartext: " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.LmOwfPasswordOffset, LM_NTLM_HASH_LENGTH)));
                            Console.WriteLine($"`````````````````````````````````````````````````````````````````````````");
                        }

                        msventry.NT = "     " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.NtOwfPasswordOffset, LM_NTLM_HASH_LENGTH));

                        if (Globals.debug)
                        {
                            Console.WriteLine($"[*] NTLM hash offest: " + template.NtOwfPasswordOffset);
                            Console.WriteLine($"[*] NTLM hash length is 16 bytes");
                            Console.WriteLine($"[*] NTLM hash bytes: " + Helpers.ByteArrayToString(GetBytes(msvDecryptedCredentialsBytes, template.NtOwfPasswordOffset, LM_NTLM_HASH_LENGTH)));
                            Console.WriteLine($"[+] NTLM hash cleartext: " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.NtOwfPasswordOffset, LM_NTLM_HASH_LENGTH)));

                            Console.WriteLine($"`````````````````````````````````````````````````````````````````````````");
                        }

                        msventry.Sha1 = "   " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.ShaOwPasswordOffset, SHA_DIGEST_LENGTH));
                        string dpapi = PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.DPAPIProtectedOffset, LM_NTLM_HASH_LENGTH));
                        if (dpapi != "00000000000000000000000000000000" && dpapi != "0c000e00000000005800000000000000")
                            msventry.Dpapi = "  " + dpapi;

                        if (Globals.debug)
                        {
                            Console.WriteLine($"[*] SHA1 offest: " + template.ShaOwPasswordOffset);
                            Console.WriteLine($"[*] SHA1 length is " + SHA_DIGEST_LENGTH + " bytes");
                            Console.WriteLine($"[*] SHA1 bytes: " + Helpers.ByteArrayToString(GetBytes(msvDecryptedCredentialsBytes, template.ShaOwPasswordOffset, SHA_DIGEST_LENGTH)));
                            Console.WriteLine($"[+] SHA1 cleartext: " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.ShaOwPasswordOffset, SHA_DIGEST_LENGTH)));

                            /*
                            if (Globals.debug) 
                            { 
                                Console.WriteLine($"[*] DPAPI hash offest: " + template.DPAPIProtectedOffset);
                                Console.WriteLine($"[*] DPAPI hash length is " + LM_NTLM_HASH_LENGTH + " bytes");
                                Console.WriteLine($"[*] DPAPI hash bytes: " + Helpers.ByteArrayToString(GetBytes(msvDecryptedCredentialsBytes, template.DPAPIProtectedOffset, LM_NTLM_HASH_LENGTH)));
                                Console.WriteLine($"[+] DPAPI hash cleartext: " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.DPAPIProtectedOffset, LM_NTLM_HASH_LENGTH)));
                             }
                             */
                            Console.WriteLine($"`````````````````````````````````````````````````````````````````````````");
                        }


                        if (Globals.mode == "mimikatz" || Globals.mode == "both")
                        {
                            Console.WriteLine($" ");
                            Console.WriteLine($"=========================================================================");
                            Console.WriteLine("Decrypted Credentials");
                            Console.WriteLine("\tmsv :");
                            Console.WriteLine("\t [struct. " + msvCount + "] Primary");
                            Console.WriteLine($"\t * Username\t: " + Encoding.Unicode.GetString(GetBytes(msvDecryptedCredentialsBytes, usUserName.Buffer, usUserName.Length)));
                            Console.WriteLine($"\t * Domain\t: " + Encoding.Unicode.GetString(GetBytes(msvDecryptedCredentialsBytes, usLogonDomainName.Buffer, usLogonDomainName.Length)));
                            //if (Globals.debug) { Console.WriteLine($"\t * DPAPI Hash\t: " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.DPAPIProtectedOffset, LM_NTLM_HASH_LENGTH)));}
                            Console.WriteLine($"\t * NTLM\t\t: " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.NtOwfPasswordOffset, LM_NTLM_HASH_LENGTH)));
                            Console.WriteLine($"\t * LM\t\t: " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.LmOwfPasswordOffset, LM_NTLM_HASH_LENGTH)));
                            Console.WriteLine($"\t * SHA1\t\t: " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.ShaOwPasswordOffset, SHA_DIGEST_LENGTH)));
                            Console.WriteLine($"=========================================================================");
                        }
                    }
                }

            }

            if (Globals.boolValidIV == false)
            {
                Console.WriteLine("\n[-] The IV found is not valid. Perhaps you should adjust the Windows version parameter with -w to get the valid IV.");
                Console.WriteLine("\t - A wrong Windows version may affect both the validity of the IV and the MSV credentials (e.g. MTLM Hash).");
                Console.WriteLine("\t - An invalid IV will not necessarily affect the validity of the NTLM Hash, but will invalidate the DPAPI master key.");
            }


            if (Globals.debug)
            {

                Console.WriteLine($"\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
                if (Globals.boolValidIV == true)
                {
                    Console.WriteLine("[*] The IV (VALID) is: ");
                }
                else
                {
                    Console.WriteLine("[*] The IV (INVALID) is: ");
                }
                Console.WriteLine(Helpers.ByteArrayToString(deadmatter.lsakeys.iv));
                Console.WriteLine($"  ");
                Console.WriteLine($"[*] The list of 3DES Keys is: ");
                foreach (byte[] deskey in DESkeysList)
                {
                    Console.WriteLine(Helpers.ByteArrayToString(deskey));
                }
                Console.WriteLine($"  ");
                Console.WriteLine($"[*] The list of AES Keys is: ");
                foreach (byte[] aeskey in AESkeysList)
                {
                    Console.WriteLine(Helpers.ByteArrayToString(aeskey));
                }
                Console.WriteLine($"  ");
                Console.WriteLine($"[*] The list of MSV Credential structure addresses is: ");
                foreach (long lsasscred in addrList)
                {
                    Console.WriteLine(string.Format("{0:X}", lsasscred));
                }
                Console.WriteLine($"^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            }


            //Populate the Global list of lsakeys with the keys found (not only the valid one because we dont know if the rest will be needed later on)
            LsaDecryptor.LsaKeys lsakeys = new LsaDecryptor.LsaKeys();
            if (AESkeysList.Count >= DESkeysList.Count)
            {
                int i = 0;
                foreach (byte[] aeskey in AESkeysList)
                {
                    lsakeys.iv = deadmatter.lsakeys.iv;
                    lsakeys.aes_key = aeskey;
                    if (DESkeysList.Count > 0 && i <= DESkeysList.Count - 1)
                    {
                        lsakeys.des_key = DESkeysList[i];
                    }
                    else
                    {
                        lsakeys.des_key = new byte[] { };
                    }
                    Globals.gLSAkeyslist.Add(lsakeys);
                    i++;
                }
            }
            else if (DESkeysList.Count > AESkeysList.Count)
            {
                int i = 0;
                foreach (byte[] deskey in DESkeysList)
                {
                    lsakeys.iv = deadmatter.lsakeys.iv;
                    lsakeys.des_key = deskey;
                    if (AESkeysList.Count - 1 >= 0 && i <= AESkeysList.Count - 1)
                    {
                        lsakeys.aes_key = AESkeysList[i];
                    }
                    else
                    {
                        lsakeys.aes_key = new byte[] { };
                    }
                    Globals.gLSAkeyslist.Add(lsakeys);
                    i++;
                }
            }
            return 0;
        }

        public static List<long> FindValidMSVBlobs(Program.DeadMatter deadmatter)
        {
            List<long> addrList = new List<long>();
            List<long> primcredsAddrList = new List<long>();

            //This is the word Primary prepended to the MSV structure
            byte[] primaryPattern = new byte[] { 0x50, 0x72, 0x69, 0x6D, 0x61, 0x72, 0x79 };    // Primary

            Console.WriteLine("[*] Searching for MSV Credentials data structures.");
            //Searching for the string "Primary" which is prepended to the MSV Credentials data struct
            if (Globals.debug) { Console.WriteLine("[*] Searching for the string 'Primary' which is prepended to the MSV Credentials data struct."); }
            addrList = Helpers.SearchSignatureTillEnd(deadmatter, primaryPattern);
            if (addrList.Count == 0)
            {
                Console.WriteLine("[-] Error: Could not find any MSV Credentials data structures... Quitting");
                System.Environment.Exit(0);
            }
            else
            {
                if (Globals.debug) { Console.WriteLine("[*] Found candidate addresses. Proceeding to validate them."); }
            }

            //Validate the Primary Credentials structures that we found and put the good candidates in a list
            primcredsAddrList = Helpers.ValidatePrimCredsList(deadmatter, addrList);
            if (primcredsAddrList.Count == 0)
            {
                Console.WriteLine("[-] Error: No valid PrimaryCredential data structures found... Quitting");
                System.Environment.Exit(0);
            }
            else
            {
                Console.WriteLine("[*] Found valid PrimaryCredential data structures.");
                foreach (long a in primcredsAddrList)
                {
                    if (Globals.debug) { Console.WriteLine("[*] Found PrimaryCredential structure at: " + a.ToString("X")); }
                }
            }

            return primcredsAddrList;
        }

        public static byte[] BruteforceSearchValidIV(byte[] ivSegmentArray, byte[] msvCredentialsBytes, LsaDecryptor.LsaKeys lsaKeys)
        {
            //if (Globals.debug) { Console.WriteLine("IV Segment: " + Helpers.ByteArrayToString(ivSegmentArray));}
            byte[] iv = new byte[16];
            int count;

            for (int i = 0; i <= ivSegmentArray.Length - 16; i++)
            {
                Array.Copy(ivSegmentArray, i, iv, 0, 16);

                count = 0;
                foreach (byte b in iv)
                {
                    if (b == 0x00)
                    {
                        count++;
                    }
                }

                if (count <= 2)
                {
                    lsaKeys.iv = iv;
                    var msvDecrypted = BCrypt.DecryptCredentials(msvCredentialsBytes, lsaKeys);
                    byte[] msvDecryptedBytes = GetBytes(msvDecrypted, 0, msvDecrypted.Length);
                    
                    if (isValidIV(msvDecryptedBytes))
                    {
                        Console.WriteLine("[*] Found valid IV using brute-force search");
                        //if (Globals.debug) { Console.WriteLine("[+] Valid IV: " + Helpers.ByteArrayToString(iv));}
                        return iv;
                    }
                }
            }
            return iv;
        }

        public static byte[] BruteforceSearchValidIVwithNulls(byte[] ivSegmentArray, byte[] msvCredentialsBytes, LsaDecryptor.LsaKeys lsaKeys)
        {
            //if (Globals.debug) { Console.WriteLine("IV Segment: " + Helpers.ByteArrayToString(ivSegmentArray));}
            byte[] iv = new byte[16];
            for (int i = 0; i <= ivSegmentArray.Length - 16; i++)
            {
                Array.Copy(ivSegmentArray, i, iv, 0, 16);

                lsaKeys.iv = iv;
                var msvDecrypted = BCrypt.DecryptCredentials(msvCredentialsBytes, lsaKeys);
                byte[] msvDecryptedBytes = GetBytes(msvDecrypted, 0, msvDecrypted.Length);

                if (isValidIV(msvDecryptedBytes))
                {
                    //if (Globals.debug) { Console.WriteLine("[+] Valid IV: " + Helpers.ByteArrayToString(iv));}
                    return iv;
                }
                
            }
            return iv;
        }

        public static bool isValidIV(byte[] decryptedMSVArray)
        {
            bool result = false;

            if (decryptedMSVArray[0] <= 0x20 &&
                decryptedMSVArray[1] == 0x00 &&
                decryptedMSVArray[2] <= 0x20 &&
                decryptedMSVArray[3] == 0x00 &&
                decryptedMSVArray[4] == 0x00 &&
                decryptedMSVArray[5] == 0x00 &&
                decryptedMSVArray[6] == 0x00 &&
                decryptedMSVArray[7] == 0x00)
            {
                result = true;
            }

            return result;
        }


        public static void CarveHashes(byte[] msvDecryptedCredentialsBytes, int msvCount)
        {
            //Assuming that LM Hash is all 0x00

            byte[] hashesBlob = GetHashSequences(msvDecryptedCredentialsBytes);
            string domain = GetDomain(msvDecryptedCredentialsBytes);
            string username = GetUsername(msvDecryptedCredentialsBytes);

            if (hashesBlob.Length != 0)
            {
                byte[] hashNTLM = GetBytes(hashesBlob, 0, 16);
                byte[] hashLM = GetBytes(hashesBlob, 16, 16);
                byte[] hashSHA1 = GetBytes(hashesBlob, 32, 20);

                Console.WriteLine($" ");
                Console.WriteLine($"=========================================================================");
                Console.WriteLine("Decrypted Credentials --=[ CARVED ]=--");
                Console.WriteLine("\tmsv :");
                Console.WriteLine("\t [struct. " + msvCount + "] Primary");
                if (!String.IsNullOrEmpty(username))
                {
                    Console.WriteLine($"\t * Username\t: " + username);
                }
                else
                {
                    Console.WriteLine($"\t * Username\t: " + "<UNKNOWN>");
                }
                if (!String.IsNullOrEmpty(domain))
                {
                    Console.WriteLine($"\t * Domain\t: " + domain);
                }
                else
                {
                    Console.WriteLine($"\t * Domain\t: " + "<UNKNOWN>");
                }
                //if (Globals.debug) { Console.WriteLine($"\t * DPAPI Hash\t: " + PrintHashBytes(GetBytes(msvDecryptedCredentialsBytes, template.DPAPIProtectedOffset, LM_NTLM_HASH_LENGTH)));}
                Console.WriteLine($"\t * NTLM\t\t: " + PrintHashBytes(hashNTLM));
                Console.WriteLine($"\t * LM\t\t: " + PrintHashBytes(hashLM));
                Console.WriteLine($"\t * SHA1\t\t: " + PrintHashBytes(hashSHA1));
                Console.WriteLine($"=========================================================================");

            }
        }


        public static string GetDomain(byte[] msvArray)
        {
            string domain = "";

            //Locate the hashes blob in the MSV array so as to start the Domain search in the blob after it
            byte[] hashesBlob = new byte[] { };
            hashesBlob = GetHashSequences(msvArray);
            if (hashesBlob.Length == 0)
            {
                return domain;
            }


            long postHashIndex = Helpers.FindByteSequence(msvArray, hashesBlob);
                    
            
            if (postHashIndex != -1)
            {
                if (Globals.debug) { Console.WriteLine("[*] Searching for the Domain just after the end of the Hash blob at MSV index: " + postHashIndex); }
                
                //Locate the start of the Domain name
                long startDomainIndex = IdentifyDomainStartIndex(msvArray, postHashIndex);
                if (Globals.debug) { Console.WriteLine("[*] Domain found at MSV position: " + startDomainIndex); }
                if (startDomainIndex == -1)
                {
                    return domain;
                }

                //Extract the Domain name
                byte[] domainBytes = ExtractUTF16ByteSequenceFromMSV(msvArray, startDomainIndex);
                if (Globals.debug) { Console.WriteLine("[*] Domain bytes are: " + Helpers.ByteArrayToString(domainBytes)); }
                if (domainBytes.Length > 0)
                {
                    domain = Encoding.Unicode.GetString(domainBytes);
                }
                
            }
            else
            {
                Console.WriteLine("[-] Error: Hash blob sequence not found in MSV structure. Domain retrieval failed");
            }

            return domain;
        }

        public static string GetUsername(byte[] msvArray)
        {
            string username = "";
            byte usernameLength;
            byte usernameMaxLength;
            byte[] usernameOffset = new byte[2];

            //We need these values for verification after carving
            usernameLength = msvArray[16];  // 17th byte
            usernameMaxLength = msvArray[18];  // 19th byte
            Array.Copy(msvArray, 24, usernameOffset, 0, 2);  // 25-26th bytes (25th only needed)

            //Two bytes are too short for a long (8 bytes). We need 6 more bytes
            //Pad with 0x00 to form a long
            byte[] usernameOffsetLongBytes = new byte[8];
            Array.Copy(usernameOffset, 0, usernameOffsetLongBytes, 0, usernameOffset.Length);

            //Ensure the system is Little Endian
            if (BitConverter.IsLittleEndian)
            {
                long usernameIndex = BitConverter.ToInt64(usernameOffsetLongBytes, 0);
                if (Globals.debug) { Console.WriteLine("[*] Username MSV index position is: " + usernameIndex); }

                //Extract the Username name
                byte[] usernameBytes = ExtractUTF16ByteSequenceFromMSV(msvArray, usernameIndex);
                if (Globals.debug) { Console.WriteLine("[*] Username bytes are: " + Helpers.ByteArrayToString(usernameBytes)); }
                if (usernameBytes.Length > 0)
                {
                    username = Encoding.Unicode.GetString(usernameBytes);
                    if (username.Length == usernameLength / 2 && (usernameMaxLength / 2 == username.Length + 1 || usernameMaxLength <= 40))
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Verification passed. Username matches MSV reported values."); }
                    }
                    return username;
                }
                else 
                {
                    if (Globals.debug) { Console.WriteLine("[*] Username does not start at the position indicated by the offset in the MSV structure."); }
                }
            }
            else
            {
               Console.WriteLine("[-] Error: System is not Little Endian. Username position retrieval failed");
            }

            return username;
        }


        //Indentify the start of the Domain byte sequence
        public static long IdentifyDomainStartIndex(byte[] msvArray, long startIndex)
        {
            for (long i = startIndex; i <= msvArray.Length - 20; i++)
            {
                bool match = true;
                // Check for 18 0x00 bytes to avoid hitting the LM hash
                for (int j = 0; j < 18; j++)
                {
                    if (msvArray[i + j] != 0x00)
                    {
                        match = false;
                        break;
                    }
                }
                // Check for a non-0x00 byte
                if (msvArray[i + 18] == 0x00)
                {
                    match = false;
                }
                // Check for 0x00 after non-0x00
                if (msvArray[i + 19] != 0x00)
                {
                    match = false;
                }
                if (match)
                {
                    return i + 18; // Return index of non-0x00 byte
                }
            }
            return -1; // Next sequence not found
        }


        //Identifies and extracts the UTF16LE byte sequence from the position provided up until the terminating null (i.e. two nulls)
        public static byte[] ExtractUTF16ByteSequenceFromMSV(byte[] msvArray, long startIndex)
        {
            int endIndex = 0;

            for (int i = (int)startIndex; i <= msvArray.Length - 2; i++)
            {
                //Stop extraction once we hit a triple 0x00 (i.e. the end of the Domain). One 0x00 that goes with the last non-0x00 byte and two more for the UTF16LE string terminator
                if (msvArray[i] == 0x00 && msvArray[i + 1] == 0x00 && msvArray[i + 2] == 0x00)
                {
                    endIndex = i + 1;  //We need to account for the null byte accompanying the non-null byte before it
                    break;
                }
            }

            //32 bytes (0x20) is usually the max domain length in decrypted MSV blobs but AI reported that it can be up to 40 bytes in NetBIOS
            //Username max length can be up to 40 bytes
            if (endIndex > 0 && endIndex - (int)startIndex <= 40 )
            {
                byte[] extractedBytes = new byte[endIndex - (int)startIndex];
                Array.Copy(msvArray, startIndex, extractedBytes, 0, extractedBytes.Length);
                return extractedBytes;
            }
            else
            {
                return new byte[] { };
            }
            
        }


        public static byte[] GetHashSequences(byte[] msvArray)
        {
            byte[] hashesBlob = new byte[] { };

            for (int i = 0; i <= msvArray.Length - 52; i++) // 52 bytes total in the sequence
            {
                bool isCorrectSequence = true;

                // Check first 16 bytes for non-0x00 with up to two 0x00 occurences
                int zerosCount = 0;
                for (int j = 0; j < 16; j++)
                {
                    if (msvArray[i + j] == 0x00)
                    {
                        zerosCount++;
                        if (zerosCount > 2)
                        {
                            isCorrectSequence = false;
                            break;
                        }
                    }
                }

                if (!isCorrectSequence)
                {
                    continue;
                }

                // Check next 16 bytes for 0x00
                for (int j = 16; j < 32; j++)
                {
                    if (msvArray[i + j] != 0x00)
                    {
                        isCorrectSequence = false;
                        break;
                    }
                }

                if (!isCorrectSequence)
                {
                    continue;
                }

                // Check last 20 bytes for non-0x00 with up to two 0x00 occurences
                zerosCount = 0;
                for (int j = 32; j < 52; j++)
                {
                    if (msvArray[i + j] == 0x00)
                    {
                        zerosCount++;
                        if (zerosCount > 2)
                        {
                            isCorrectSequence = false;
                            break;
                        }
                    }
                }

                if (isCorrectSequence)
                {
                    
                    hashesBlob = GetBytes(msvArray, i, 52);
                    if (Globals.debug)
                    {
                        Console.WriteLine("[*] Found Hash blob sequence starting at MSV index: " + i);
                        Console.WriteLine(ByteArrayToString(hashesBlob));
                    }
                    return hashesBlob;
                }
            }

            return hashesBlob;
        }


        public static string IdentifyOS(byte[] msvDecryptedCredentialsBytes)
        {
            //The identification assumes that there is no LM hash hence its value is all 0x00

            byte domainLength;
            byte domainMaxLength;
            byte[] domainOffset = new byte[2];
            byte usernameLength;
            byte usernameMaxLength;
            byte[] usernameOffset = new byte[2];
            byte isIso;
            byte isNTLM;
            byte isLM;
            byte isSHA1;
            byte isDPAPIProtect;

            if (msvDecryptedCredentialsBytes.Length < 200)
            {
                //Windows 8.1 / 2012 R2

                domainLength = msvDecryptedCredentialsBytes[0];  // 1st byte
                domainMaxLength = msvDecryptedCredentialsBytes[2];  // 3rd byte
                Array.Copy(msvDecryptedCredentialsBytes, 8, domainOffset, 0, 2);  // 9-10th bytes (9th only)
                usernameLength = msvDecryptedCredentialsBytes[16];  // 17th byte
                usernameMaxLength = msvDecryptedCredentialsBytes[18];  // 19th byte
                Array.Copy(msvDecryptedCredentialsBytes, 24, usernameOffset, 0, 2);  // 25-26th bytes (25th only)

                //Check if a valid IV was used for decryption. If yes then we have the domain bytes to check otherwise don't check them
                if (msvDecryptedCredentialsBytes[1] == 0x00 &&
                    msvDecryptedCredentialsBytes[3] == 0x00 &&
                    msvDecryptedCredentialsBytes[4] == 0x00 &&
                    msvDecryptedCredentialsBytes[5] == 0x00 &&
                    msvDecryptedCredentialsBytes[6] == 0x00 &&
                    msvDecryptedCredentialsBytes[7] == 0x00)
                {
                    if (domainLength != 0x00 &&
                        domainMaxLength > domainLength &&
                        (domainOffset[0] != 0x00 || domainOffset[1] != 0x00) &&
                        usernameLength != 0x00 &&
                        usernameMaxLength > usernameLength &&
                        (usernameOffset[0] != 0x00 || usernameOffset[1] != 0x00))

                    {
                        if (Globals.debug) { Console.WriteLine("[*] Windows 8.1 / 2012 R2 detected !!! "); }
                        return "Win_8.1_2012R2";
                    }
                    else
                    {
                        if (Globals.debug) { Console.WriteLine("[-] Error in OS detection "); }
                        return "";
                    }
                }
                else
                {
                    if (usernameLength != 0x00 &&
                        usernameMaxLength > usernameLength &&
                        (usernameOffset[0] != 0x00 || usernameOffset[1] != 0x00))
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Windows 8.1 / 2012 R2 detected !!! "); }
                        return "Win_8.1_2012R2";
                    }
                    else
                    {
                        if (Globals.debug) { Console.WriteLine("[-] Error in OS detection "); }
                        return "";
                    }
                }                    
            }
            else if (msvDecryptedCredentialsBytes.Length < 300)
            {
                //Windows 10 1507

                domainLength = msvDecryptedCredentialsBytes[0];  // 1st byte
                domainMaxLength = msvDecryptedCredentialsBytes[2];  // 3rd byte
                Array.Copy(msvDecryptedCredentialsBytes, 8, domainOffset, 0, 2);  // 9-10th bytes
                usernameLength = msvDecryptedCredentialsBytes[16];  // 17th byte
                usernameMaxLength = msvDecryptedCredentialsBytes[18];  // 19th byte
                Array.Copy(msvDecryptedCredentialsBytes, 24, usernameOffset, 0, 2);  // 25-26th bytes
                isIso = msvDecryptedCredentialsBytes[32];  // 33rd byte
                isNTLM = msvDecryptedCredentialsBytes[33];  // 34th byte
                isLM = msvDecryptedCredentialsBytes[34];  // 35th byte
                isSHA1 = msvDecryptedCredentialsBytes[35];  // 36th byte


                //Check if a valid IV was used for decryption then we have the domain bytes to check otherwise don't check them 
                if (msvDecryptedCredentialsBytes[1] == 0x00 &&
                    msvDecryptedCredentialsBytes[3] == 0x00 &&
                    msvDecryptedCredentialsBytes[4] == 0x00 &&
                    msvDecryptedCredentialsBytes[5] == 0x00 &&
                    msvDecryptedCredentialsBytes[6] == 0x00 &&
                    msvDecryptedCredentialsBytes[7] == 0x00)
                {
                    if (domainLength != 0x00 &&
                        domainMaxLength > domainLength &&
                        (domainOffset[0] != 0x00 || domainOffset[1] != 0x00) &&
                        usernameLength != 0x00 &&
                        usernameMaxLength > usernameLength &&
                        (usernameOffset[0] != 0x00 || usernameOffset[1] != 0x00) &&
                        (isIso == 0x00 || isIso == 0x01) &&
                        isNTLM == 0x01 &&
                        isLM == 0x00 &&
                        isSHA1 == 0x01)
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Windows 10 1507 detected !!! "); }
                        return "Win_10_1507";
                    }
                    else
                    {
                        if (Globals.debug) { Console.WriteLine("[-] Error in OS detection "); }
                        return "";
                    }
                }
                else
                {
                    if (usernameLength != 0x00 &&
                        usernameMaxLength > usernameLength &&
                        (usernameOffset[0] != 0x00 || usernameOffset[1] != 0x00) &&
                        (isIso == 0x00 || isIso == 0x01) &&
                        isNTLM == 0x01 &&
                        isLM == 0x00 &&
                        isSHA1 == 0x01)
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Windows 10 1507 detected !!! "); }
                        return "Win_10_1507";
                    }
                    else
                    {
                        if (Globals.debug) { Console.WriteLine("[-] Error in OS detection "); }
                        return "";
                    }
                }
                    
            }
            else if (msvDecryptedCredentialsBytes.Length < 400)
            {
                //Windows 10 1607 / 2016

                domainLength = msvDecryptedCredentialsBytes[0];  // 1st byte
                domainMaxLength = msvDecryptedCredentialsBytes[2];  // 3rd byte
                Array.Copy(msvDecryptedCredentialsBytes, 8, domainOffset, 0, 2);  // 9-10th bytes
                usernameLength = msvDecryptedCredentialsBytes[16];  // 17th byte
                usernameMaxLength = msvDecryptedCredentialsBytes[18];  // 19th byte
                Array.Copy(msvDecryptedCredentialsBytes, 24, usernameOffset, 0, 2);  // 25-26th bytes
                isIso = msvDecryptedCredentialsBytes[40];  // 41st byte
                isNTLM = msvDecryptedCredentialsBytes[41];  // 42nd byte
                isLM = msvDecryptedCredentialsBytes[42];  // 43rd byte
                isSHA1 = msvDecryptedCredentialsBytes[43];  // 44th byte
                isDPAPIProtect = msvDecryptedCredentialsBytes[44];  // 45th byte

                //Check if a valid IV was used for decryption then we have the domain bytes to check otherwise don't check them 
                if (msvDecryptedCredentialsBytes[1] == 0x00 &&
                    msvDecryptedCredentialsBytes[3] == 0x00 &&
                    msvDecryptedCredentialsBytes[4] == 0x00 &&
                    msvDecryptedCredentialsBytes[5] == 0x00 &&
                    msvDecryptedCredentialsBytes[6] == 0x00 &&
                    msvDecryptedCredentialsBytes[7] == 0x00)
                {
                    if (domainLength != 0x00 &&
                        domainMaxLength > domainLength &&
                        domainOffset[0] != 0x00 && domainOffset[1] != 0x00 &&
                        usernameLength != 0x00 &&
                        usernameMaxLength > usernameLength &&
                        usernameOffset[0] != 0x00 && usernameOffset[1] != 0x00 &&
                        (isIso == 0x00 || isIso == 0x01) &&
                        isNTLM == 0x01 &&
                        isLM == 0x00 &&
                        isSHA1 == 0x01 &&
                        (isDPAPIProtect == 0x00 || isDPAPIProtect == 0x01 || isDPAPIProtect == 0x02 || isDPAPIProtect == 0x03))
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Windows 10 1607 / 2016 detected !!! "); }
                        return "Win_10_1607_2016";
                    }
                    else
                    {
                        if (Globals.debug) { Console.WriteLine("[-] Error in OS detection "); }
                        return "";
                    }
                }
                else
                {
                    if (usernameLength != 0x00 &&
                        usernameMaxLength > usernameLength &&
                        usernameOffset[0] != 0x00 && usernameOffset[1] != 0x00 &&
                        (isIso == 0x00 || isIso == 0x01) &&
                        isNTLM == 0x01 &&
                        isLM == 0x00 &&
                        isSHA1 == 0x01 &&
                        (isDPAPIProtect == 0x00 || isDPAPIProtect == 0x01 || isDPAPIProtect == 0x02 || isDPAPIProtect == 0x03))
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Windows 10 1607 / 2016 detected !!! "); }
                        return "Win_10_1607_2016";
                    }
                    else
                    {
                        if (Globals.debug) { Console.WriteLine("[-] Error in OS detection "); }
                        return "";
                    }
                }

            }
            else
            {
                //Windows 10 > 1703 or 1709 or 1803 / 11 / 2019 / 2022

                domainLength = msvDecryptedCredentialsBytes[0];  // 1st byte
                domainMaxLength = msvDecryptedCredentialsBytes[2];  // 3rd byte
                Array.Copy(msvDecryptedCredentialsBytes, 8, domainOffset, 0, 2);  // 9-10th bytes
                usernameLength = msvDecryptedCredentialsBytes[16];  // 17th byte
                usernameMaxLength = msvDecryptedCredentialsBytes[18];  // 19th byte
                Array.Copy(msvDecryptedCredentialsBytes, 24, usernameOffset, 0, 2);  // 25-26th bytes
                isIso = msvDecryptedCredentialsBytes[40];  // 41st byte
                isNTLM = msvDecryptedCredentialsBytes[41];  // 42nd byte
                isLM = msvDecryptedCredentialsBytes[42];  // 43rd byte
                isSHA1 = msvDecryptedCredentialsBytes[43];  // 44th byte
                isDPAPIProtect = msvDecryptedCredentialsBytes[44];  // 45th byte

                //Check if a valid IV was used for decryption then we have the domain bytes to check otherwise don't check them 
                if (msvDecryptedCredentialsBytes[1] == 0x00 && 
                    msvDecryptedCredentialsBytes[3] == 0x00 && 
                    msvDecryptedCredentialsBytes[4] == 0x00 && 
                    msvDecryptedCredentialsBytes[5] == 0x00 && 
                    msvDecryptedCredentialsBytes[6] == 0x00 && 
                    msvDecryptedCredentialsBytes[7] == 0x00)
                {
                    if (domainLength != 0x00 &&
                        domainMaxLength > domainLength &&
                        domainOffset[0] != 0x00 && domainOffset[1] != 0x00 &&
                        usernameLength != 0x00 &&
                        usernameMaxLength > usernameLength &&
                        usernameOffset[0] != 0x00 && usernameOffset[1] != 0x00 &&
                        (isIso == 0x00 || isIso == 0x01) &&
                        isNTLM == 0x01 &&
                        isLM == 0x00 &&
                        isSHA1 == 0x01 &&
                        (isDPAPIProtect == 0x00 || isDPAPIProtect == 0x01 || isDPAPIProtect == 0x02 || isDPAPIProtect == 0x03))
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Windows 10 1607 - Windows 11 23H2 detected !!! "); }
                        return "Win_10_1607-11_23H2";
                    }
                    else if (domainLength != 0x00 &&
                        domainMaxLength > domainLength &&
                        domainOffset[0] != 0x00 && domainOffset[1] != 0x00 &&
                        usernameLength != 0x00 &&
                        usernameMaxLength > usernameLength &&
                        usernameOffset[0] != 0x00 && usernameOffset[1] != 0x00 &&
                        (isIso == 0x00 || isIso == 0x01) &&
                        isNTLM == 0x01 &&
                        (isLM == 0x00 || isLM == 0x01) &&
                        isSHA1 == 0x01 &&
                        (isDPAPIProtect == 0x00 || isDPAPIProtect == 0x01 || isDPAPIProtect == 0x02 || isDPAPIProtect == 0x03))
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Windows 11 24H2 or later detected !!!"); }
                        return "Win_11_24H2";
                    }
                    else
                    {
                        if (Globals.debug) { Console.WriteLine("[-] Error in OS detection "); }
                        return "";
                    }
                }
                else
                {
                    if (usernameLength != 0x00 &&
                        usernameMaxLength > usernameLength &&
                        usernameOffset[0] != 0x00 && usernameOffset[1] != 0x00 &&
                        (isIso == 0x00 || isIso == 0x01) &&
                        isNTLM == 0x01 &&
                        isLM == 0x00 &&
                        isSHA1 == 0x01 &&
                        (isDPAPIProtect == 0x00 || isDPAPIProtect == 0x01 || isDPAPIProtect == 0x02 || isDPAPIProtect == 0x03))
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Windows 10 1607 - Windows 11 23H2 detected !!! "); }
                        return "Win_10_1607-11_23H2";
                    }
                    else if (usernameLength != 0x00 &&
                        usernameMaxLength > usernameLength &&
                        usernameOffset[0] != 0x00 && usernameOffset[1] != 0x00 &&
                        (isIso == 0x00 || isIso == 0x01) &&
                        isNTLM == 0x01 &&
                        (isLM == 0x00 || isLM == 0x01) &&
                        isSHA1 == 0x01 &&
                        (isDPAPIProtect == 0x00 || isDPAPIProtect == 0x01 || isDPAPIProtect == 0x02 || isDPAPIProtect == 0x03))
                    {
                        if (Globals.debug) { Console.WriteLine("[*] Windows 11 24H2 detected !!!"); }
                        return "Win_11_24H2";
                    }
                    else
                    {
                        if (Globals.debug) { Console.WriteLine("[-] Error in OS detection "); }
                        return "";
                    }
                }
            }
        }
    }
}