﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Models.Database
{
    public class PInvokeEntry : IDetectionEntry
    {
        public string Category { get; set; }
        public string Description { get; set; }
        public object Tag { get; set; }
        public string Trigger { get; set; }
    }
}
