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
    public class StringDetection : IDetectionProcess
    {
        private AssemblySettings _asm;
        public int Detect(AssemblySettings asm)
        {
            _asm = asm;
            int d = 0;

            foreach (TypeDef td in asm.Module.GetTypes())
            {
                foreach (MethodDef md in td.Methods)
                {
                    if (!md.HasBody)
                        continue;
                    d += ProcessMethod(md);
                }
            }

            return d;
        }
        private int ProcessMethod(MethodDef md)
        {
            int d = 0;
            foreach (Instruction inst in md.Body.Instructions)
            {
                if (inst.OpCode == OpCodes.Ldstr)
                {
                    string data = inst.Operand as string;
                    foreach (StringEntry pEntry in DetectionDatabase.Strings)
                    {
                        if (data.ToLower().Contains(pEntry.Trigger.ToLower()))
                        {
                            _asm.AddDetection("ManagedStrings", new Reason("ManagedStrings", pEntry.Description));
                            d++;
                        }
                    }
                }
            }
            return d;
        }
    }
}
