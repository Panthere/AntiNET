using AntiNET2.Core.Models;
using AntiNET2.Core.Providers;
using AntiNET2.Core.Providers.DetectionEngines.Managed;
using AntiNET2.Core.Providers.DetectionEngines.Native;
using dnlib.DotNet;
using dnlib.PE;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2
{
    class Program
    {
        static void Main(string[] args)
        {
            AssemblySettings asmSettings = new AssemblySettings();
            bool isNet = true;
            try
            {
                asmSettings.Module = ModuleDefMD.Load(args[0]);
            }
            catch (Exception ex)
            {
                isNet = false;
            }

            if (!isNet)
            {
                try
                {
                    asmSettings.NativeImage = new PEImage(args[0]);

                }
                catch (Exception ex)
                {
                    // Cannot continue execution
                    Console.WriteLine(ex);
                    Console.ReadLine();
                    return;
                }
            }
            else
            {
                asmSettings.NativeImage = asmSettings.Module.MetaData.PEImage as PEImage;
            }

            List<IDetectionProcess> dp = new List<IDetectionProcess>();

            if (isNet)
            {
                dp.Add(new ResourceDetection());
            }

            dp.Add(new EOFDetection());
            dp.Add(new SectionDetection());
            dp.Add(new SignatureDetection());

            int totalDetections = 0;

            dp.ForEach(x => totalDetections += x.Detect(asmSettings));

            Console.WriteLine(totalDetections);

            var grouped = asmSettings.TotalDetections.GroupBy(x => x.DetectionType).ToDictionary(x => x.Key);
            foreach (var pair in grouped)
            {
                foreach (var x in pair.Value)
                {
                    x.DetectionReasons.ForEach(y => Console.WriteLine(y));
                }
            }
        }
    }
}
