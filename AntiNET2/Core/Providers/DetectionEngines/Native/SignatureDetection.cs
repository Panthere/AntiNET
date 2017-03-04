using AntiNET2.Core.Models;
using AntiNET2.Core.Models.Database;
using AntiNET2.Core.Providers.Database;
using AntiNET2.Core.Extensions;

using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using static AntiNET2.Core.Helpers.ByteScan;

namespace AntiNET2.Core.Providers.DetectionEngines.Native
{
    public class SignatureDetection : IDetectionProcess
    {
        private AssemblySettings _asm;
        public int Detect(AssemblySettings asm)
        {
            _asm = asm;
            int d = 0;
            
            
            //asm.NativeImage.UnsafeDisableMemoryMappedIO();
            try
            {
                byte[] file = File.ReadAllBytes(asm.NativeImage.FileName);

                foreach (SignatureEntry sig in DetectionDatabase.Signatures.Rows)
                {
                    long sigIndex = ((Sig)sig.Tag).Scan(file);
                    if (sigIndex == -1)
                    {
                        continue;
                    }
                    // Should I insert the sig Category here instead of "Signature"?
                    asm.AddDetection("Signature", new Reason("Signature", string.Format("Matched {0} ({2}) at offset 0x{1}", sig.Trigger, sigIndex.ToString("X2"), sig.Description)));
                    d++;
                }
                
            }
            catch (Exception)
            {
                // File access issue?
                asm.AddDetection("Signature", new Reason("Signature", "Error when processing signatures"));
                d++;
            }

            return d;
        }

    }
}
