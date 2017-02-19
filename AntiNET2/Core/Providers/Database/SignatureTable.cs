using AntiNET2.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Providers.Database
{
    public class SignatureTable : IDetectionTable
    {
        public List<IDetectionEntry> Rows
        {
            get;
            set;
        }
    }
}
