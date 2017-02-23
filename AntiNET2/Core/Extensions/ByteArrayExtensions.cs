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
        public static unsafe long IndexOf(this byte[] haystack, byte[] needle, long startOffset = 0)
        {
            fixed (byte* h = haystack) fixed (byte* n = needle)
            {
                for (byte* hNext = h + startOffset, hEnd = h + haystack.LongLength + 1 - needle.LongLength, nEnd = n + needle.LongLength; hNext < hEnd; hNext++)
                    for (byte* hInc = hNext, nInc = n; *nInc == *hInc; hInc++)
                        if (++nInc == nEnd)
                            return hNext - h;
                return -1;
            }
        }
        // Credits to github.com/BahNahNah
        // Slower, sadly
        public static unsafe long IndexOf(this byte[] search, string sig)
        {
            var pattern = sig.ToArray();
            fixed (byte* scrArrayPtr = &search[0])
            {
                var scrEnum = scrArrayPtr;
                for (var end = (scrArrayPtr + (search.Length - sig.Length + 1)); scrEnum != end; scrEnum++)
                {
                    bool found = true;
                    fixed (char* mPtr = &pattern[0])
                    {
                        var mEnum = mPtr;
                        for (var mEnd = mPtr + pattern.Length; mEnum != mEnd; mEnum++)
                        {
                            if (*mEnum == '?')
                            {
                                continue;
                            }
                            if (*(byte*)mEnum != *scrEnum)
                            {
                                found = false;
                                break;
                            }
                        }
                    }
                    if (found)
                        return (int)(scrEnum - scrArrayPtr);
                    scrEnum++;
                }

            }
            return -1;
        }
        // Credits to github.com/BahNahNah
        static unsafe int GetIndexOfScan(byte[] search, byte[] pattern, string match)
        {

            if (search.Length == 0 || pattern.Length != match.Length || pattern.Length == 0)
                return 0;

            fixed (byte* scrArrayPtr = &search[0])
            {
                var scrEnum = scrArrayPtr;
                var end = (scrArrayPtr + (search.Length - pattern.Length + 1));

                while (scrEnum != end)
                {
                    bool found = true;
                    for (int pIndex = 0; pIndex < pattern.Length; pIndex++)
                    {

                        if (match[pIndex] != '?')
                        {
                            if (*(scrEnum + pIndex) != pattern[pIndex])
                            {
                                found = false;
                                break;
                            }
                        }
                    }
                    if (found)
                        return (int)(scrEnum - scrArrayPtr);
                    scrEnum++;
                }
            }
            return -1;
        }
    }
}
