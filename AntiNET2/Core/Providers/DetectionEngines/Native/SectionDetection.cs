using AntiNET2.Core.Models;
using dnlib.PE;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Providers.DetectionEngines.Native
{
    public class SectionDetection : IDetectionProcess
    {

        private PEImage mod;
        public int Detect(AssemblySettings asm)
        {
            int d = 0;
            mod = asm.NativeImage;


            // Check for starting with .
            // Check for only top section headers
            // .rsrc, .text, .data, .rdata, .reloc, .idata, .tls, .bss

            

            foreach (var sect in mod.ImageSectionHeaders)
            {
                string dispName = sect.DisplayName;
                uint attrs = sect.Characteristics;

                if (!dispName.StartsWith("."))
                {
                    asm.AddDetection("Sections", new Reason("Sections", string.Format("Section {0} does not start with a dot. Could be invalid section.", dispName)));
                    d++;
                }
                bool hasInvalidAttrs = false;
                switch (dispName)
                {
                    case ".text":
                        if (attrs != 0x60000020)
                        {
                            hasInvalidAttrs = true;
                        }
                        break;
                    case ".rsrc":
                    case ".rdata":
                        if (attrs != 0x40000040)
                        {
                            hasInvalidAttrs = true;
                        }
                        break;
                    case ".idata":
                    case ".data":
                        if (attrs != 0xC0000040)
                        {
                            hasInvalidAttrs = true;
                        }
                        break;
                    case ".reloc":
                        if (attrs != 0x42000040)
                        {
                            hasInvalidAttrs = true;
                        }
                        break;
                    case ".bss":
                        if (attrs != 0xC0000080)
                        {
                            hasInvalidAttrs = true;
                        }
                        break;
                    default:
                        asm.AddDetection("Sections", new Reason("Sections", string.Format("Section {0} is not a common section name. Could contain malicious content.", dispName)));
                        d++;
                        break;
                    
                }
                if (hasInvalidAttrs)
                {
                    asm.AddDetection("Sections", new Reason("Sections", string.Format("Section {0} does not have the correct attributes. Could be spoofed.", dispName)));
                }

            }

            return d;
        }
    }
}
