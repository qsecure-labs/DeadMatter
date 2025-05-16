

namespace Deadmatter.Decryptor
{
   
    public class Dpapi
    {
        public string luid { get; set; }
        public string key_guid { get; set; }
        public string masterkey { get; set; }
        public string masterkey_sha { get; set; }
        public string insertTime { get; set; }
        public string key_size { get; set; }
    }

    public class Msv
    {
        public string DomainName { get; set; }
        public string UserName { get; set; }
        public string Lm { get; set; }
        public string NT { get; set; }
        public string Sha1 { get; set; }
        public string Dpapi { get; set; }
    }

   

    
}