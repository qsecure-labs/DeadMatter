using System;

namespace Deadmatter.Templates
{
    public class lsaTemplate
    {
        public static object GetTemplate(string arch, int buildNum)
        {
            int WIN_VISTA = 5000;

            if (arch != "x64" )
            {
                Console.WriteLine("[-] Error: X86 not yet supported");
                System.Environment.Exit(1);
            }
            else
            {
                if (buildNum < WIN_VISTA)
                {
                    Console.WriteLine("[-] Error: NT5 not yet supported");
                    System.Environment.Exit(1);
                }
                else
                {
                    return lsaTemplate_NT6.GetTemplate(arch, buildNum);
                }
            }
            return null;
        }
    }
}