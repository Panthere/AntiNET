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
        public static List<ReflectionEntry> Calls { get; private set; }
        public static List<StringEntry> Strings { get; private set; }
        public static List<PInvokeEntry> Natives { get; private set; }
        public static List<SignatureEntry> Signatures { get; private set; }

        private static Dictionary<string, string> Tables = new Dictionary<string, string>();

        private static string BASE_PATH = @"D:\A\DB\";//Environment.CurrentDirectory + "\\";

        static DetectionDatabase()
        {

            Tables.Add("sigs.json", "Signatures");
            LoadJSON();

            // Welcome to hell, this is stupid
            if (Calls == null)
                Calls = new List<ReflectionEntry>();
            if (Strings == null)
                Strings = new List<StringEntry>();
            if (Natives == null)
                Natives = new List<PInvokeEntry>();
            if (Signatures == null)
                Signatures = new List<SignatureEntry>();
        }

        public static void Save()
        {
            SaveJSON();
        }

        private static void LoadJSON()
        {
            foreach (var tbl in Tables)
            {
                if (!LoadJSONList(BASE_PATH + tbl.Key, tbl.Value))
                {
                    Console.WriteLine("Failed to load the table {0}, using defaults", tbl.Key);
                }

            }
        }
        private static void SaveJSON()
        {
            foreach (var tbl in Tables)
            {
                if (!SaveJSONList(BASE_PATH + tbl.Key, tbl.Value))
                {
                    Console.WriteLine("Failed to save the table {0}!", tbl.Key);
                }

            }
        }

        private static bool LoadJSONList(string fileName, string type)
        {
            try
            {
                string tableContents = File.ReadAllText(fileName);
                int count = 0;
                // Calling all smart people who don't love type restricted bs in .net
                if (type == "Calls")
                {
                    Calls = JsonConvert.DeserializeObject<List<ReflectionEntry>>(tableContents);
                    count = Calls.Count;
                }
                else if (type == "Strings")
                {
                    Strings = JsonConvert.DeserializeObject<List<StringEntry>>(tableContents);
                    count = Strings.Count;
                }
                else if (type == "Natives")
                {
                    Natives = JsonConvert.DeserializeObject<List<PInvokeEntry>>(tableContents);
                    count = Natives.Count;
                }
                else if (type == "Signatures")
                {
                    Signatures = JsonConvert.DeserializeObject<List<SignatureEntry>>(tableContents);
                    LoadSignatures();

                    count = Signatures.Count;
                }
                else if (type == "Test")
                {
                    Calls = JsonConvert.DeserializeObject<List<ReflectionEntry>>(tableContents);
                    count = Calls.Count;
                }

                Console.WriteLine("Loaded {0} entries for {1}", count, type);
            }
            catch (Exception ex)
            {
                // More than likely a problem with the file contents, or reading the file.
                Console.WriteLine("Error while processing table {0}, {1}", Path.GetFileNameWithoutExtension(fileName), ex.Message);
                return false;
            }
            return true;
        }

        private static bool SaveJSONList(string fileName, string type)
        {
            try
            {
                // Once again, fucking cancershits
                object typeObj = default(object);
                if (type == "Calls")
                {
                    typeObj = Calls;
                }
                else if (type == "Natives")
                {
                    typeObj = Natives;
                }
                else if (type == "Strings")
                {
                    typeObj = Strings;
                }
                else if (type == "Signatures")
                {
                    typeObj = Signatures;
                }
                string tableContents = JsonConvert.SerializeObject(typeObj);

                File.WriteAllText(fileName, tableContents);
            }
            catch (Exception ex)
            {
                // More than likely a problem with the file contents, or reading the file.
                Console.WriteLine("Error while writing table {0}, {1}", Path.GetFileNameWithoutExtension(fileName), ex.Message);
                return false;
            }
            return true;
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
