﻿using AntiNET2.Core.Helpers;
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

        public static long IndexOf(this byte[] file, string sig)
        {
            return ByteScan.GetIndexOfSig(file, sig);
        }

        #region Testing Index Of

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

        // string like
        // 4D 5A 9? 00 03 is sig
        // Hex is 2 chars, so need to work on that
        public static long IndexOfTest(this byte[] search, string sig)
        {
            string[] sigParts = sig.Split(' ');
            int count = search.Length - sig.Replace(" ", "").Length + 1;

            for (int i = 0; i < count; i++)
            {
                // Problem with this is that it will not work if the first part contains ?
                /*if (search[i].ToString("X2") != sigParts[0])
                {
                    continue;
                }*/
                int j = 0;
                for (int a = 0; a < sigParts.Length; a++)
                {
                    string part = sigParts[a];

                    string testMatch = search[i + a].ToString("X2");


                    if (testMatch == part || part == "??")
                    {
                        j++;
                        continue;
                    }
                    if (part[0] == '?')
                    {
                        if (testMatch[1] == part[1])
                            j++;
                    }
                    else if (part[1] == '?')
                    {
                        if (testMatch[0] == part[0])
                            j++;
                    }
                    else
                    {
                        // No match, break
                        break;
                    }
                }
                if (j == sigParts.Length)
                    return i;
            }
            return -1;
        }

        // Credits to github.com/BahNahNah
        // Slower, sadly
        public static unsafe long IndexOfTest2(this byte[] search, string sig)
        {
            var pattern = sig.Split(' ').Select(x =>
            {
                if (x == "??")
                    return '?';
                return (char)Convert.ToByte(x, 16);
            }).ToArray();

            fixed (byte* scrArrayPtr = &search[0])
            {
                var scrEnum = scrArrayPtr;
                for (var end = (scrArrayPtr + (search.Length - sig.Length + 1)); scrEnum <= end; scrEnum++)
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
                            string left = (*mEnum).ToString();
                            string right = (*scrEnum).ToString("X");
                            if (left != right)
                            //if (*(byte*)mEnum != *scrEnum)
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
        #endregion
    }
}
