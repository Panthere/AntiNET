using AntiNET2.Core.Models;
using dnlib.DotNet;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Resources;
using System.Text;
using System.Threading.Tasks;
using AntiNET2.Core.Extensions;

namespace AntiNET2.Core.Providers
{
    public class ResourceDetection : IDetectionProcess
    {
        private Random r = new Random();
        private AssemblySettings _asm;

        private Dictionary<int, Resource> sizeHandler = new Dictionary<int, Resource>();

        private List<string> manifestNames = new List<string>();
        private List<string> readerNames = new List<string>();

        public int Detect(AssemblySettings asm)
        {
            _asm = asm;
            ModuleDefMD mod = asm.Module;

            int d = 0;

            foreach (Resource res in mod.Resources)
            {
                manifestNames.Add(res.Name);
            }

            foreach (Resource res in mod.Resources)
            {
                if (res.ResourceType != ResourceType.Embedded)
                    continue;

                EmbeddedResource ebr = res as EmbeddedResource;

                TypeDef assoc = GetAssociatedType(mod, ebr.Name);

                if (assoc == null)
                {
                    asm.AddDetection("Resources", new Reason("Resources", "Associated type with the resource was not found"));
                    d++;
                }

                ResourceReader reader = null;

                try
                {
                    reader = new ResourceReader(ebr.GetResourceStream());
                }
                catch (Exception)
                {
                   // Probably null or such
                }

                if (reader == null)
                {
                    asm.AddDetection("Resources", new Reason("Resources", "Resource is a manifest resource, could contain malicious details."));
                    d++;

                    if (ebr.GetResourceData().Length > 32)
                    {
                        d += ByteTests(ebr.GetResourceData(), ebr); 
                    }

                    d += NameTests(ebr.Name, ebr, manifestNames);
                   
                }
                else
                {
                    foreach (DictionaryEntry a in reader)
                    {
                        readerNames.Add((string)a.Key);
                    }

                    foreach (DictionaryEntry a in reader)
                    {
                        if (a.Value is byte[])
                        {
                            byte[] b = a.Value as byte[];

                            d += ByteTests(b, ebr);
                        }
                        if (a.Value is Bitmap)
                        {
                            // Icon check, icons generally have the same width & height

                            Bitmap bit = a.Value as Bitmap;
                            
                            if (bit.Size.Height != bit.Size.Width)
                            {

                                asm.AddDetection("Resources", new Reason("Resources", "Bitmap Resource was not equal dimensions, could be steganography."));
                                d++;
                            }

                        }
                        d += NameTests(a.Key as string, ebr, readerNames);
                        
                    }
                }
                readerNames.Clear();
            }

            return d;
        }

        private int ByteTests(byte[] array, EmbeddedResource ebr)
        {
            int d = 0;
            if (array.Length > 300000)
            {
                _asm.AddDetection("Resources", new Reason("Resources", "Large resource was found, larger than 300KB"));
                d++;
            }
            if (sizeHandler.ContainsKey(array.Length))
            {
                _asm.AddDetection("Resources", new Reason("Resources", "Another resource has the same data/length."));
                d++;
            }
            else
            {
                sizeHandler.Add(array.Length, ebr);
            }

            if (array.Length > 8)
            {
                d += array.SigDetection(_asm, "Resources");
            }
            return d;
        }

        private int NameTests(string resEntryName, EmbeddedResource ebr, List<string> testAgainst)
        {
            int d = 0;
            string cToReader = testAgainst[r.Next(testAgainst.Count - 1)];
            if (cToReader != resEntryName)
            {
                int readerComp = LevenshteinDistance.Compute(ebr.Name, cToReader);

                if (readerComp < 5)
                {
                    _asm.AddDetection("Resources", new Reason("Resources", "Resource naming was consistent across others. Could mean split resources."));
                    d++;
                }
            }
            return d;
        }

        private TypeDef GetAssociatedType(ModuleDefMD mod, string name)
        {
            foreach (TypeDef td in mod.Types)
            {
                if (td.FullName.Contains(name.Replace(".resources", "")))
                {
                    return td;
                }
            }
            return null;
        }
    }
}
