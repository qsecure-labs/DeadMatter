using System;

namespace Deadmatter
{
    class Usage
    {
        //Help menu
        public void Help()
        {
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("DeadMatter Usage:");
            Console.WriteLine("=================");
            Console.WriteLine();
            Console.WriteLine("Flags                Required    Description");
            Console.WriteLine("-----                --------    -----------");
            Console.WriteLine("-h                   False       Print usage information");
            Console.WriteLine("-f                   True        Memory dump file name and path. e.g. C:\\path\\memdump.raw");
            Console.WriteLine("-m                   False       Set mode of MSV logon credentials extraction. Default value \'both\'");
            Console.WriteLine("                                   Accepted values:");
            Console.WriteLine("                                     mimikatz    -   use mimikatz MSV credential structures");
            Console.WriteLine("                                     carve       -   carve credentials out of the decrypted MSV blob. LM must be nulls.");
            Console.WriteLine("                                     both        -   use both carve and mimikatz modes. (Default)");
            Console.WriteLine("                                     none        -   do not display extracted MSV credentials");
            Console.WriteLine("-w                   False       Set target Windows version for the mimikatz mode. Default value \'WIN_10_1903\'");
            Console.WriteLine("                                   Accepted values:");
            Console.WriteLine("                                     WIN_11_24H2    -   Windows 11/2025 >= 24H2");
            Console.WriteLine("                                     WIN_11         -   Windows 11/2022 <= 23H2");
            Console.WriteLine("                                     WIN_10_1903    -   Windows 10/2019 >= 1903");
            Console.WriteLine("                                     WIN_10_1809    -   Windows 10/2019 1809");
            Console.WriteLine("                                     WIN_10_1803    -   Windows 10/2016 1803");
            Console.WriteLine("                                     WIN_10_1703    -   Windows 10/2016 1703");
            Console.WriteLine("                                     WIN_10_1607    -   Windows 10/2016 1607");
            Console.WriteLine("                                     WIN_10_1511    -   Windows 10 1511");
            Console.WriteLine("                                     WIN_10_1507    -   Windows 10 1507");
            Console.WriteLine("                                     WIN_81         -   Windows 8.1/2012R2");
            Console.WriteLine("-i                   False       Identify OS version using MSV structure");
            Console.WriteLine("-b                   False       Brute-force search for the IV");
            Console.WriteLine("-s                   False       Byte range in KB to brute-force search for the IV. Default value \'16\'");
            Console.WriteLine("-d                   False       Extract DPAPI master keys");
            Console.WriteLine("-v                   False       Turn on verbose mode");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Command usage examples:");
            Console.WriteLine("=======================");
            Console.WriteLine();
            Console.WriteLine("Extract credentials from a full memory dump file in raw format using both mimkatz structure and carving techinques");
            Console.WriteLine("------------------------------------------------------------------------------------------------------------------");
            Console.WriteLine(@"C:\> Deadmatter.exe -f memory_dump.raw ");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Extract credentials from a full memory dump file in raw format using carving techinques only");
            Console.WriteLine("--------------------------------------------------------------------------------------------");
            Console.WriteLine(@"C:\> Deadmatter.exe -f memory_dump.raw -m carve");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Identify the OS version based on the MSV structure details");
            Console.WriteLine("----------------------------------------------------------");
            Console.WriteLine(@"C:\> Deadmatter.exe -f memory_dump.raw -m none -i");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Extract credentials from a minidump file using Windows 10 version 1507 mimkatz structure techinque with verbose output");
            Console.WriteLine("----------------------------------------------------------------------------------------------------------------------");
            Console.WriteLine(@"C:\> Deadmatter.exe -f lsass.dmp -m mimikatz -w WIN_10_1507 -v");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Extract credentials and DPAPI keys from a full memory dump file in raw format and brute-force search for the IV");
            Console.WriteLine("----------------------------------------------------------------------------------------------------------------------");
            Console.WriteLine(@"C:\> Deadmatter.exe -f memory_dump.raw -b -d");
            Console.WriteLine();
            Console.WriteLine();
        }
    }
}
