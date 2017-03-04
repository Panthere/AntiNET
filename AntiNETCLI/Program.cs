using AntiNET2;
using AntiNET2.Core.Models;
using AntiNET2.Core.Providers;
using AntiNET2.Core.Providers.DetectionEngines.Managed;
using AntiNET2.Core.Providers.DetectionEngines.Native;
using dnlib.DotNet;
using dnlib.PE;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNETCLI
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch sw = new Stopwatch();

            Console.Title = "AntiNET - \"False positive? Never!!1\"";

            int totalDetections = 0;
            sw.Start();
            List<Detection> TotalDetections = Scanner.Scan(args[0], out totalDetections);
            sw.Stop();

            Console.WriteLine("Total Detection: {0}", totalDetections);

            var grouped = TotalDetections.GroupBy(x => x.DetectionType).ToDictionary(x => x.Key);
            foreach (var pair in grouped)
            {
                foreach (var x in pair.Value)
                {
                    x.DetectionReasons.ForEach(y => Console.WriteLine(y));
                }
            }

            Console.WriteLine("Total time taken for scanning: {0}", sw.Elapsed.TotalSeconds);
            Console.ReadKey();
        }
    }
}
