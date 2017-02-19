using AntiNET2.Core.Models;
using AntiNET2.Core.Models.Database;
using AntiNET2.Core.Providers.Database;
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
        public static ReflectionTable Calls { get; private set; }
        public static StringTable Strings { get; private set; }
        public static PInvokeTable Natives { get; private set; }
        public static SignatureTable Signatures { get; private set; }

        private static Dictionary<string, string> Tables = new Dictionary<string, string>();

        static DetectionDatabase()
        {
            // Load database into table
            string basePath = Environment.CurrentDirectory + "\\";

            foreach (var tbl in Tables)
            {
                IDetectionTable tableInstance = null;
                switch (tbl.Value)
                {
                    case "calls":
                        tableInstance = Calls;
                        break;
                    case "strings":
                        tableInstance = Strings;
                        break;
                    case "natives":
                        tableInstance = Natives;
                        break;
                    case "signatures":
                        tableInstance = Signatures;
                        break;
                    default:
                        continue;
                }

                if (!LoadTable(basePath + tbl.Key, tableInstance))
                {
                    Console.WriteLine("Failed to load the table {0}", tbl.Key);
                }
                Console.WriteLine("Loaded {0} detection entries for {1}", tableInstance.Rows.Count, tbl.Key);

            }
        }

        private static bool LoadTable(string fileName, IDetectionTable targetTable)
        {
            try
            {
                string tableContents = File.ReadAllText(fileName);
                List<IDetectionEntry> entries = new List<IDetectionEntry>();
                // Not sure of another way to do this...
                if (targetTable is ReflectionTable)
                {
                    entries = GetEntries<ReflectionEntry>(tableContents).Cast<IDetectionEntry>().ToList();
                }
                else if (targetTable is StringTable)
                {
                    entries = GetEntries<StringEntry>(tableContents).Cast<IDetectionEntry>().ToList();
                }
                else if (targetTable is PInvokeTable)
                {
                    entries = GetEntries<PInvokeEntry>(tableContents).Cast<IDetectionEntry>().ToList();
                }
                else if (targetTable is SignatureTable)
                {
                    entries = GetEntries<SignatureEntry>(tableContents).Cast<IDetectionEntry>().ToList();
                }
                if (entries.Count == 0)
                {
                    return false;
                }

                targetTable.Rows = entries;
            }
            catch (Exception ex)
            {
                // More than likely a problem with the file contents, or reading the file.
                Console.WriteLine("Error while processing table {0}, {1}", Path.GetFileNameWithoutExtension(fileName), ex.Message);
                
                return false;

            }
            return true;
        }

        private static List<T> GetEntries<T>(string tableContents) where T : IDetectionEntry, new()
        {
            // Need to work out a system for this, right now this is quite shocking.
            List<T> tList = new List<T>();

            string[] detections = tableContents.Split(new string[] { "||||||||" }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string det in detections)
            {
                string real = det.Trim('\r', '\n');
                string[] parts = real.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);


                T detection = new T();
                detection.Trigger = parts[0].Split('=')[1];
                detection.Description = parts[1].Split('=')[1];
                detection.Category = parts[2].Split('=')[1];

                tList.Add(detection);
            }

            return tList;
        }
    }
}
