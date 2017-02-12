using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Models
{
    public class Detection
    {
        public string DetectionType = string.Empty;
        public int TotalDetections = 0;

        public List<Reason> DetectionReasons = new List<Reason>();
    }
}
