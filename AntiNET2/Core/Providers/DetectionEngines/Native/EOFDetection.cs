using AntiNET2.Core.Models;
using dnlib.DotNet;
using dnlib.PE;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AntiNET2.Core.Extensions;

namespace AntiNET2.Core.Providers.DetectionEngines.Native
{
    public class EOFDetection : IDetectionProcess
    {
        private PEImage mod;
        public int Detect(AssemblySettings asm)
        {
            int d = 0;

            mod = asm.NativeImage;

            var lastSec = mod.ImageSectionHeaders.Last();

            var eofOffset = lastSec.PointerToRawData + lastSec.SizeOfRawData;

            using (var pe = mod.CreateFullStream())
            {
                // Check whether it's got EOF anyway
                if (pe.Length <= eofOffset)
                {
                    return d;

                }
                if (pe.Length > eofOffset + 8)
                {
                    pe.Position = eofOffset;
                    byte[] eof = pe.ReadBytes(8);

                    d += eof.SigDetection(asm, "End of File");
                }
                asm.AddDetection("End of File", new Reason("End of File", "End of File data detected, could be storage for malicious content or settings"));
                d++;
            }

            return d;
        }
    }
}
