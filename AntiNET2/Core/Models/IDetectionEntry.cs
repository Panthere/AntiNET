using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Models
{
    public interface IDetectionEntry
    {
        string Category { get; set; }
        string Description { get; set; }
        string Trigger { get; set; }
        object Tag { get; set; }
    }
}
