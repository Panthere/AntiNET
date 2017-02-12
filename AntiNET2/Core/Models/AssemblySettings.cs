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
        public ModuleDefMD Module;
        public PEImage NativeImage;

        public List<Detection> TotalDetections = new List<Detection>();//public List<Reason> HumanReasons = new List<Reason>();

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
