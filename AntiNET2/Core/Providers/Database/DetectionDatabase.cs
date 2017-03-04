using AntiNET2.Core.Helpers;
using AntiNET2.Core.Models;
using AntiNET2.Core.Models.Database;
using AntiNET2.Core.Providers.Database;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Providers.Database
{
    public static class DetectionDatabase
    {

        public static List<ReflectionEntry> Calls => Database.Calls;
        public static List<StringEntry> Strings => Database.Strings;
        public static List<PInvokeEntry> Natives => Database.Natives;
        public static List<SignatureEntry> Signatures => Database.Signatures;

        private static DatabaseInfo Database;
        static DetectionDatabase()
        {
            Database = JsonConvert.DeserializeObject<DatabaseInfo>(File.ReadAllText("sigs.json"));
        }

        public static void Save() => File.WriteAllText("sigs.json", JsonConvert.SerializeObject(Database));

    }
}
