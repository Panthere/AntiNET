using AntiNET2.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Providers.Database
{
    public class ReflectionTable : IDetectionTable
    {

        public List<IDetectionEntry> Rows
        {
            get
            {
                return Rows;
            }
            set
            {
                Rows = value;
            }
        }
    }
}
