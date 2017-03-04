using dnlib.DotNet;
using dnlib.PE;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Models
{
    public class AssemblySettings
    {
        public ModuleDefMD Module { get; set; }
        public PEImage NativeImage { get; set; }

        public List<Detection> TotalDetections { get; set; } = new List<Detection>();

        public void AddDetection(string type, Reason r)
        {
            var typeDetection = TotalDetections.Where(x => x.DetectionType == type).FirstOrDefault();
            if (typeDetection == null)
            {
                TotalDetections.Add(new Detection() { DetectionType = type, DetectionReasons = new List<Reason>() { r }, TotalDetections = 1 });
            }
            else
            {
                typeDetection.DetectionReasons.Add(r);
                typeDetection.TotalDetections++;
            }

        }
    }
}
