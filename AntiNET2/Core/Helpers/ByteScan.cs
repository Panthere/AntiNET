using System;
using System.Linq;

namespace AntiNET2.Core.Helpers
{
    /// <summary>
    /// BahNahNah
    /// </summary>
    public static class ByteScan
    {
        /// <summary>
        /// Example sig:
        /// 01 02 ?3 04
        /// will match with
        /// 01 02 A3 04
        /// 01 02 03 04
        /// but not with
        /// 01 02 3A 04
        /// A0 02 3A 04
        /// etc.
        /// </summary>
        /// <param name="scan">Bytes to scan</param>
        /// <param name="sig">Byte sig</param>
        /// <returns>Index of scan array where pattern match. -1 on failure.</returns>
        public static unsafe int GetIndexOfSig(byte[] scan, string sig)
        {
            return CompileSig(sig).Scan(scan);
        }

        public static Sig CompileSig(string sig)
        {
            var cArray = sig.Split(' ').Select(c =>
            {
                SigChar sChar = new SigChar();
                if (c == "??")
                {
                    return sChar;
                }
                if (c[0] != '?')
                { //LEFT
                    sChar.Flag |= 0xF0;
                }
                if (c[1] != '?')
                { //RIGHT
                    sChar.Flag |= 0x0F;
                }
                c = c.Replace('?', '0');
                sChar.CmpX = (byte)(Convert.ToByte(c, 16) & sChar.Flag);
                return sChar;
            }).ToArray();
            return new Sig(cArray);
        }

        public unsafe struct Sig
        {
            private SigChar[] SigChars;

            public Sig(SigChar[] _sc)
            {
                SigChars = _sc;
            }


            public int Scan(byte[] scan)
            {
                if (scan.Length < SigChars.Length)
                    return -1;

                fixed (byte* scrArrayPtr = &scan[0])
                {
                    var scrEnum = scrArrayPtr;
                    var end = (scrArrayPtr + (scan.Length - SigChars.Length + 1));

                    while (scrEnum != end)
                    {
                        bool found = true;
                        for (int pIndex = 0; pIndex < SigChars.Length; pIndex++)
                        {
                            SigChar sigChar = SigChars[pIndex];
                            var current = *(scrEnum + pIndex);
                            if (((current & sigChar.Flag) ^ sigChar.CmpX) != 0)
                            {
                                found = false;
                                break;
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

        public struct SigChar
        {
            public byte Flag;
            public byte CmpX;

        }

    }
}