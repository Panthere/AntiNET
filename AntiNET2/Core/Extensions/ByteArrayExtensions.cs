using AntiNET2.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNET2.Core.Extensions
{
    public static class ByteArrayExtensions
    {
        public static int SigDetection(this byte[] array, AssemblySettings _asm, string type)
        {
            string singular = type;
            if (type.EndsWith("s"))
            {
                 singular = type.Remove(type.Length - 2);
            }
            int d = 0;
            // GZip
            if (array[0] == 0x1f && array[1] == 0x8b)
            {
                _asm.AddDetection(type, new Reason(type, singular + " has GZip magic number. Could be malicious packed content."));
                d++;
            }
            // Pkzip .zip
            if (array[0] == 0x50 && array[1] == 0x4b && array[2] == 0x03 && array[3] == 0x04)
            {
                _asm.AddDetection(type, new Reason(type, singular + " has PKZip magic number. Could be malicious packed content."));
                d++;
            }
            // Rar
            if (array[0] == 0x52 && array[1] == 0x61 && array[2] == 0x72 && array[3] == 0x21 && array[4] == 0x1A && array[5] == 0x07 && array[6] == 0x00)
            {
                _asm.AddDetection(type, new Reason(type, singular + " has RAR magic number. Could be malicious packed content."));
                d++;
            }
            // Exe
            if (array[0] == 0x4D && array[1] == 0x5A)
            {
                _asm.AddDetection(type, new Reason(type, singular + " has EXE magic number. Could be malicious content."));
                d++;
            }
            return d;
        }
    }
}
