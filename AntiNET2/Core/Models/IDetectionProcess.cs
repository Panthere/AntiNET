using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Models
{
    interface IDetectionProcess
    {
        int Detect(AssemblySettings asm);
    }
}
