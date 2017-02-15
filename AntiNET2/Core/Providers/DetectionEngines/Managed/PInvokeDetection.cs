using AntiNET2.Core.Models;
using AntiNET2.Core.Models.Database;
using AntiNET2.Core.Providers.Database;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Providers.DetectionEngines.Managed
{
    public class PInvokeDetection : IDetectionProcess
    {
        public AssemblySettings _asm;
        private List<string> commonUsed = new List<string>() { "kernel32.dll", "gdi32.dll", "user32.dll", "mscoree.dll" };

        public int Detect(AssemblySettings asm)
        {
            _asm = asm;

            int d = 0;

            foreach (TypeDef td in asm.Module.GetTypes())
            {
                foreach (MethodDef md in td.Methods)
                {
                    if (!md.IsPinvokeImpl)
                        continue;

                    d += ProcessMethod(md);
                }
            }


            return d;
        }
        private int ProcessMethod(MethodDef md)
        {
            int d = 0;

            if (!commonUsed.Contains(md.ImplMap.Module.Name.ToString()))
            {
                _asm.AddDetection("PInvoke", new Reason("PInvoke", string.Format("Uncommon PInvoke dll referenced: {0}", md.ImplMap.Module.Name.ToString())));
                d++;
                return d;
            }

            foreach (PInvokeEntry pEntry in DetectionDatabase.Natives.Rows)
            {
                if (md.ImplMap.Name.ToLower().StartsWith(pEntry.Trigger.ToLower()))
                {
                    _asm.AddDetection(pEntry.Category, new Reason(pEntry.Category, pEntry.Description));
                    d++;
                }
            }

            return d;
        }
    }
}
