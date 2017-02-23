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

            try
            {
                byte[] file = File.ReadAllBytes(asm.NativeImage.FileName);


                for (int i = 0; i < file.Length; i++)
                {
                }
            }
            catch (Exception ex)
            {
                // File access issue
                asm.AddDetection("Signature", new Reason("Signature", "Error opening file to read bytes from"));
                d++;
            }

            return d;
        }
        private List<byte[]> GetFileSigs()
        {
            List<byte[]> fileSigs = new List<byte[]>();

            foreach (SignatureEntry sig in DetectionDatabase.Signatures.Rows)
            {
                //fileSigs.Add(BitConvert
            }

            return fileSigs;

        }


    }
}
