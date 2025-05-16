using Deadmatter.Decryptor;
using Deadmatter.Templates;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Deadmatter
{
    public static class Globals
    {
        public static List<long> gValidAddrList = new List<long>();
        public static List<long> gDesAddrList = new List<long>();
        public static List<long> gAesAddrList = new List<long>();
        public static List<byte[]> gDESKeysList = new List<byte[]>();
        public static List<byte[]> gAESKeysList = new List<byte[]>();
        public static bool boolValidIV = false;
        public static bool debug = false;
        public static bool idOS = false;
        public static string mode = "both";
        public static bool bSearch = false;
        public static int bSearchSize = 16;
        public static bool dpapi = false;
        public static List<IV_Signatures> IVsignaturesList = new List<IV_Signatures>();
        public static List<IV_Addresses> IVaddressesList = new List<IV_Addresses>();
    }
    public class Program
    {
        public struct DeadMatter
        {
            public string ARCHITECTURE;
            public int BUILDNUMBER;
            public BinaryReader fileBinaryReader;
            public LsaDecryptor.LsaKeys lsakeys;
            public List<LsaDecryptor.LsaKeys> lsakeysList;
        }

        private static void Main(string[] args)
        {
            Console.WriteLine(
                "  ____                 _ __  __       _   _            \n" +
                " |  _ \\  ___  __ _  __| |  \\/  | __ _| |_| |_ ___ _ __ \n" +
                " | | | |/ _ \\/ _` |/ _` | |\\/| |/ _` | __| __/ _ \\ '__|\n" +
                " | |_| |  __/ (_| | (_| | |  | | (_| | |_| ||  __/ |   \n" +
                " |____/ \\___|\\__,_|\\__,_|_|  |_|\\__,_|\\__|\\__\\___|_|   \n" +
                "\n v0.9.2 alpha");



            //set variables
            string dumpfile = "";
            string winVersion = "";
            string verbosity = "";
            string idOS = "";
            string mode = "";
            string bSearch = "";
            string bSearchSize = "";
            string dpapi = "";
            int buildNumber = 18362;    //default Windows version is Win 10 1903

            //Create the list with the IV patterns to search for
            List<byte[]> IVpatternsList = new List<byte[]>();
            IVpatternsList.Add(new byte[] { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d });
            IVpatternsList.Add(new byte[] { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d });
            IVpatternsList.Add(new byte[] { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 });

            List<string> IVpatternsVersionList = new List<string>();
            IVpatternsVersionList.Add("LSA_x64_1_n_2");
            IVpatternsVersionList.Add("LSA_x64_3_n_4");
            IVpatternsVersionList.Add("LSA_x64_5_n_6");

            IV_Signatures IVsignature = new IV_Signatures();
            
            int i = 0;
            foreach (byte[] pattern in IVpatternsList)
            {
                IVsignature.signature = IVpatternsList[i];
                IVsignature.lsaVersion = IVpatternsVersionList[i];
                Globals.IVsignaturesList.Add(IVsignature);
                i++;
            }


            /*
            foreach (IV_Signatures IVsig in Globals.IVsignaturesList)
            {
                Console.WriteLine("Signature: " + Helpers.ByteArrayToString(IVsig.signature));
                Console.WriteLine("LSA version: " + IVsig.lsaVersion);
            }
            */

            try 
            {
                //Display help menu
                if (args.Length <= 0 || args[0] == "help" || args[0] == "?" || args[0] == "-h")
                {
                    Usage helpmenu = new Usage();
                    helpmenu.Help();
                }
                else
                {
                    //Process args
                    for (int ctr = 0; ctr < args.Length; ctr++)
                    {
                        switch (args[ctr])
                        {

                            case "-f":
                                dumpfile = args[++ctr];
                                break;

                            case "-w":
                                winVersion = args[++ctr];
                                switch (winVersion.ToUpper())
                                {
                                    case "WIN_11_24H2":
                                        buildNumber = 26100;
                                        break;
                                    case "WIN_11":
                                        buildNumber = 22000;
                                        break;
                                    case "WIN_10_1903":
                                        buildNumber = 18362;
                                        break;
                                    case "WIN_10_1809":
                                        buildNumber = 17763;
                                        break;
                                    case "WIN_10_1803":
                                        buildNumber = 17134;
                                        break;
                                    case "WIN_10_1703":
                                        buildNumber = 15063;
                                        break;
                                    case "WIN_10_1607":
                                        buildNumber = 14393;
                                        break;
                                    case "WIN_10_1511":
                                        buildNumber = 10586;
                                        break;
                                    case "WIN_10_1507":
                                        buildNumber = 10240;
                                        break;
                                    case "WIN_81":
                                        buildNumber = 9400;
                                        break;
                                    default:
                                        Console.WriteLine("[-] Error: Incorrect Windows version provided in argument -w");
                                        Console.WriteLine();
                                        System.Environment.Exit(1);
                                        break;
                                }
                                break;

                            case "-v":
                                Globals.debug = true;
                                break;

                            case "-i":
                                Globals.idOS = true;
                                break;

                            case "-m":
                                mode = args[++ctr];
                                switch (mode.ToLower())
                                {
                                    case "mimikatz":
                                        Globals.mode = "mimikatz";
                                        break;
                                    case "carve":
                                        Globals.mode = "carve";
                                        break;
                                    case "both":
                                        Globals.mode = "both";
                                        break;
                                    case "none":
                                        Globals.mode = "none";
                                        break;
                                    default:
                                        Console.WriteLine("[-] Error: Incorrect mode of operation provided in argument -m");
                                        Console.WriteLine();
                                        System.Environment.Exit(1);
                                        break;
                                }
                                break;

                            case "-b":
                                Globals.bSearch = true;
                                break;

                            case "-s":
                                bSearchSize = args[++ctr];
                                int size;
                                bool isParsedSuccessfully = Int32.TryParse(bSearchSize, out size);
                                if (isParsedSuccessfully)
                                {
                                    if (size > 0)
                                    {
                                        Globals.bSearchSize = size;
                                    }
                                    else
                                    {
                                        Console.WriteLine("[-] Error: Invalid byte range provided in argument -s. Please specify a positive numeric value e.g. -s=10");
                                        Console.WriteLine();
                                        System.Environment.Exit(1);
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("[-] Error: Invalid byte range provided in argument -s. Please specify a positive numeric value e.g. -s=10");
                                    Console.WriteLine();
                                    System.Environment.Exit(1);
                                }
                                break;

                            case "-d":
                                Globals.dpapi = true;
                                break;

                            default:
                                Usage helpmenu = new Usage();
                                helpmenu.Help();

                                Console.WriteLine("[-] Error: Invalid arguments or missing required argument -f");
                                Console.WriteLine();
                                System.Environment.Exit(1);
                                break;
                        }

                    }

                }
            }
            catch (System.IndexOutOfRangeException)
            {
                Usage helpmenu = new Usage();
                helpmenu.Help();

                Console.WriteLine("[-] Error: Invalid arguments or missing required argument -f");
                Console.WriteLine();
                System.Environment.Exit(1);
            }



            string filename = dumpfile;
            if (!File.Exists(filename))
            {
                Console.WriteLine("[-] Error: Could not find file " + filename);
                return;
            }

            DeadMatter deadmatter = new DeadMatter();
            deadmatter.ARCHITECTURE = "x64";
            deadmatter.BUILDNUMBER = buildNumber;


            using (BinaryReader fileBinaryReader = new BinaryReader(File.Open(filename, FileMode.Open)))
            {
                deadmatter.fileBinaryReader = fileBinaryReader;


                //Get LSA Keys and IV
                Console.WriteLine($" ");
                Console.WriteLine($"-------------------------------------------------------------------------");
                Console.WriteLine($" ");
                try 
                {
                    //Locate the IV based on mimikatz search patterns and offsets
                    //Locate valid DES and AES keys
                    if (Globals.debug) { Console.WriteLine("[*] Getting LSA template for " + deadmatter.ARCHITECTURE + " ARCH and Win Build " + deadmatter.BUILDNUMBER); }
                    deadmatter.lsakeysList = LsaDecryptor.Choose(deadmatter, lsaTemplate.GetTemplate(deadmatter.ARCHITECTURE, deadmatter.BUILDNUMBER));

                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error: IV and Keys failed with error -  {e.Message}");
                }




                //Get MSV Credentials
                Console.WriteLine($" ");
                Console.WriteLine($"-------------------------------------------------------------------------");
                Console.WriteLine($" ");
                try
                {
                    //Locate and validate MSV blobs
                    List<long> msvBlobsAddrList = new List<long>();
                    msvBlobsAddrList = Msv1_.FindValidMSVBlobs(deadmatter);

                    //Extract MSV credentials
                    Msv1_.FindCredentials(deadmatter, msv.GetTemplate(deadmatter.ARCHITECTURE, deadmatter.BUILDNUMBER), msvBlobsAddrList);    
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error: MSV failed with error -  {e.Message}");
                }




                if (Globals.dpapi == true)
                {
                    //Get DPAPI
                    Console.WriteLine($" ");
                    Console.WriteLine($"-------------------------------------------------------------------------");
                    //Console.WriteLine($" ");
                    try
                    {
                        Dpapi_.FindCredentials(deadmatter);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Error: DPAPI failed with error -  {e.Message}");
                    }
                }
            }
        }
    }
}