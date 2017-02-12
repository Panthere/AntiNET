using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Models
{
    public class Reason
    {
        public string ReasonType;
        public string Message;
        public Reason(string type, string msg)
        {
            ReasonType = type;
            Message = msg;
        }
        public override string ToString()
        {
            return string.Format("{0} - {1}", ReasonType, Message);
        }
    }
}
