using Deadmatter.Templates;
using System.Collections.Generic;
using System;

namespace Deadmatter.Decryptor
{
    public class LsaDecryptor
    {
        public struct LsaKeys
        {
            public byte[] iv;
            public byte[] aes_key;
            public byte[] des_key;
        }

        public static List<LsaKeys> Choose(Program.DeadMatter deadmatter, object template)
        {
            if (template.GetType() == typeof(lsaTemplate_NT6.LsaTemplate_NT6))
            {
                return LsaDecryptor_NT6.LsaDecryptor(deadmatter, (lsaTemplate_NT6.LsaTemplate_NT6)template);
            }
            else
            {
                throw new Exception($"[-] NT5 not yet supported");
            }
        }
    }
}