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
    /// <summary>
    /// Credits to BahNahNah for curing the eye melting mess!
    /// </summary>
    public static class DetectionDatabase
    {

        public static List<ReflectionEntry> Calls => Database.Calls;
        public static List<StringEntry> Strings => Database.Strings;
        public static List<PInvokeEntry> Natives => Database.Natives;
        public static List<SignatureEntry> Signatures => Database.Signatures;

        private static DatabaseInfo Database;

        static DetectionDatabase()
        {
            if (!File.Exists("db.json"))
            {
                Database = new DatabaseInfo();
                CreateData();
                Save();
            }
            else
            {
                Database = JsonConvert.DeserializeObject<DatabaseInfo>(File.ReadAllText("db.json"));
            }

            // This has to happen no matter whether it is just created, or just loaded
            // Multiple methods like this will more than likely be made for other things that require 'Tag' to be used.
            LoadSignatures();
        }

        public static void Save() => File.WriteAllText("db.json", JsonConvert.SerializeObject(Database));

        private static void CreateData()
        {
            Database.Calls = new List<ReflectionEntry>();
            Database.Signatures = new List<SignatureEntry>();
            Database.Natives = new List<PInvokeEntry>();
            Database.Strings = new List<StringEntry>();

            /*for (int i = 0; i < 5000; i++)
            {
                Signatures.Add(new SignatureEntry() { Trigger = "0E 1F BA 0E ?? B4 09 CD ?? B8 01 ?? CD 21", Category = "Test", Description = "Test1" });
                Signatures.Add(new SignatureEntry() { Trigger = "?? 29 D6 F4 3F 14 DE AB F1 84 9B 6A E3 1B ?? 02 ?? 7A AF B6 13 4E E3 83 B9", Category = "Test", Description = "Test2" });
                Signatures.Add(new SignatureEntry() { Trigger = "4D 5A 90 0? 03", Category = "Test", Description = "Test3" });
            }*/
        }

        public static void AddDetection(IDetectionEntry entry)
        {
            if (entry is ReflectionEntry)
            {
                Database.Calls.Add(entry as ReflectionEntry);
            }
            else if (entry is SignatureEntry)
            {
                Database.Signatures.Add(entry as SignatureEntry);
            }
            else if (entry is PInvokeEntry)
            {
                Database.Natives.Add(entry as PInvokeEntry);
            }
            else if (entry is StringEntry)
            {
                Database.Strings.Add(entry as StringEntry);
            }
        }

        private static void LoadSignatures()
        {
            for (int i = 0; i < Signatures.Count; i++)
            {
                if (Signatures[i].Tag == null)
                {
                    Signatures[i].Tag = ByteScan.CompileSig(Signatures[i].Trigger);
                }
                else if (Signatures[i].Tag.GetType().Name != "Sig")
                {
                    string contents = ((JToken)Signatures[i].Tag).ToString();
                    ByteScan.Sig sg = JsonConvert.DeserializeObject<ByteScan.Sig>(contents);
                    Signatures[i].Tag = sg;
                }
            }
        }
    }
}
