using System;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace AntiNET2.Core.Helpers
{
    /// <summary>
    /// BahNahNah
    /// </summary>
    public static unsafe class ByteScan
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
        public static int GetIndexOfSig(byte[] scan, string sig) => CompileSig(sig).Scan(scan);
        public static Sig CompileSig(string sig)
        {
            var cArray = sig.Split(' ').Select(c => {
                ushort flag = 0;
                if (c == "??")
                {
                    return flag;
                }
                if (c[0] != '?')
                { //LEFT
                    flag |= 0xF0;
                }
                if (c[1] != '?')
                { //RIGHT
                    flag |= 0x0F;
                }
                c = c.Replace('?', '0');
                flag |= (ushort)((Convert.ToByte(c, 16) & flag) << 8);
                return flag;
            }).ToArray();
            return new Sig(cArray);
        }
        
        public class Sig
        {
            [JsonProperty("SigFlags")]
            private ushort[] SigFlags;

            public Sig(ushort[] _sc)
            {
                SigFlags = _sc;
            }

            public int Scan(byte[] scan)
            {
                if (scan.Length < SigFlags.Length)
                    return -1;

                fixed (byte* scrArrayPtr = &scan[0])
                {
                    var scrEnum = scrArrayPtr;
                    var end = (scrArrayPtr + (scan.Length - SigFlags.Length + 1));

                    while (scrEnum != end)
                    {
                        bool found = true;
                        for (int pIndex = 0; pIndex < SigFlags.Length; pIndex++)
                        {
                            ushort flag = SigFlags[pIndex];
                            var current = *(scrEnum + pIndex);
                            if (((current & flag) ^ (flag >> 8)) != 0)
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
    }
}