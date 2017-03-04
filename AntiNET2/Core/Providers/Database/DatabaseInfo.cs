using AntiNET2.Core.Models.Database;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Providers.Database
{
    internal class DatabaseInfo
    {
        public List<ReflectionEntry> Calls { get; set; }
        public List<StringEntry> Strings { get; set; }
        public List<PInvokeEntry> Natives { get; set; }
        public List<SignatureEntry> Signatures { get; set; }
    }
}