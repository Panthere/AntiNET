using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Models.Database
{
    public class StringEntry : IDetectionEntry
    {
        public string Category { get; set; }
        public string Description { get; set; }
        public string Trigger { get; set; }
    }
}
