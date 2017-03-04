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

namespace AntiNET2.Core.Providers.DetectionEngines.Native
{
    public class SignatureDetection : IDetectionProcess
    {
        private AssemblySettings _asm;
        public int Detect(AssemblySettings asm)
        {
            _asm = asm;
            int d = 0;
            
            // Signatures
            
            // Read file into byte array
            // foreach on signatures, try match sigs, regex enabled/allowed

            //asm.NativeImage.UnsafeDisableMemoryMappedIO();

            //try
            {
                byte[] file = File.ReadAllBytes(asm.NativeImage.FileName);

                foreach (string sig in GetFileSigs())
                {
                    long sigIndex = file.IndexOfTest(sig);
                    if (sigIndex != -1)
                    {
                        asm.AddDetection("Signature", new Reason("Signature", string.Format("Matched {0} at offset {1}", sig, sigIndex)));
                    }
                }
                
            }
            //catch (Exception ex)
            //{
                // File access issue
            //    asm.AddDetection("Signature", new Reason("Signature", "Error opening file to read bytes from"));
            //    d++;
            //}

            return d;
        }
        private List<string> GetFileSigs()
        {
            List<string> fileSigs = new List<string>();
            //fileSigs.Add("4D 5A 9? 00 03");
            //fileSigs.Add("6E 00 31 00 2E ?4");
            fileSigs.Add("0E 1F BA 0E ?? B4 09 CD 2? B8 01 ?C CD 21");
            fileSigs.Add("?1 29 D6 F4 3F 14 DE AB F1 84 9B 6A E3 1B D? 02 ?? 7A AF B6 13 4E E3 83 B9");
            /*
            foreach (SignatureEntry sig in DetectionDatabase.Signatures.Rows)
            {
                fileSigs.Add(sig.Trigger);
                
            }*/

            return fileSigs;

        }


    }
}
