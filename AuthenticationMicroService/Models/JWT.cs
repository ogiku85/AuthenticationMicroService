using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationMicroService.Models
{
    public class JWT
    {
        public JWT()
        {
            Audiences = new List<string>();
        }
        public string Key { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public List<string> Audiences { get; set; }
        public int Expires { get; set; }
    }
}
