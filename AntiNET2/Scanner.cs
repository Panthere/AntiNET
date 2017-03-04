using AntiNET2.Core.Models;
using AntiNET2.Core.Providers.Database;
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

namespace AntiNET2
{
    public static class Scanner
    {
        public static List<Detection> Scan(string file, out int detectionCount)
        {

            AssemblySettings asmSettings = new AssemblySettings();
            bool isNet = true;
            try
            {
                asmSettings.Module = ModuleDefMD.Load(file);
            }
            catch (Exception)
            {
                isNet = false;
            }

            if (!isNet)
            {
                try
                {
                    asmSettings.NativeImage = new PEImage(file);

                }
                catch (Exception ex)
                {
                    // Cannot continue execution
                    Console.WriteLine(ex);
                    Console.ReadLine();
                    detectionCount = 0;
                    return new List<Detection>();
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

            DetectionDatabase.Save();

            detectionCount = totalDetections;

            return asmSettings.TotalDetections;

        }
    }
}
