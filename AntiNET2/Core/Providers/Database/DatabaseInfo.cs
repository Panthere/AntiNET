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
        public List<ReflectionEntry> Calls { get; private set; }
        public List<StringEntry> Strings { get; private set; }
        public List<PInvokeEntry> Natives { get; private set; }
        public List<SignatureEntry> Signatures { get; private set; }
    }
}