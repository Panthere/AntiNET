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
    public class ReflectionDetection : IDetectionProcess
    {
        public AssemblySettings _asm;
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
                if (inst.OpCode == OpCodes.Calli)
                {
                    // You shouldn't ever come across calli when an obfuscator isn't present... no?
                    _asm.AddDetection("Call", new Reason("Call", "Calli Present, could be a sign of hiding behind an obfuscator"));
                    d++;
                }

                if (inst.OpCode != OpCodes.Call && inst.OpCode != OpCodes.Callvirt)
                {
                    continue;
                }

                foreach (ReflectionEntry callEntry in DetectionDatabase.Calls)
                {
                    if (inst.ToString().ToLower().Contains(callEntry.Trigger.ToLower()))
                    {
                        _asm.AddDetection(callEntry.Category, new Reason(callEntry.Category, callEntry.Description));
                        d++;
                    }
                }
            }
            return d;
        }
    }
}
