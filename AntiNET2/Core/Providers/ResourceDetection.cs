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

namespace AntiNET2.Core.Providers
{
    class ResourceDetection : IDetectionProcess
    {
        Random r = new Random();
        public int Detect(AssemblySettings asm)
        {
            ModuleDefMD mod = asm.Module;

            int d = 0;

            Dictionary<int, Resource> sizeHandler = new Dictionary<int, Resource>();

            List<string> names = new List<string>();
            List<string> readerNames = new List<string>();
            foreach (Resource res in mod.Resources)
            {
                names.Add(res.Name);
            }
            foreach (Resource res in mod.Resources)
            {
                switch (res.ResourceType)
                {
                    case ResourceType.Embedded:

                        EmbeddedResource ebr = res as EmbeddedResource;

                        TypeDef assoc = GetAssociatedType(mod, ebr.Name);
                        if (assoc == null)
                        {
                            asm.HumanReasons.Add(new Reason("Resources", "Associated type with the resource was not found"));
                            d++;
                        }

                        ResourceReader reader = null;

                        try
                        {
                            reader = new ResourceReader(ebr.GetResourceStream());
                        }
                        catch (Exception)
                        {
                        }

                        if (reader == null)
                        {
                            asm.HumanReasons.Add(new Reason("Resources", "Resource is a manifest resource, could contain malicious details."));
                            d++;

                            // Reader was null
                            if (ebr.GetResourceData().Length > 50)
                            {
                                if (ebr.GetResourceData().Length > 300000)
                                {
                                    asm.HumanReasons.Add(new Reason("Resources", "Large resource was found, larger than 300KB"));
                                    d++;
                                }
                                // probably not empty data
                                if (sizeHandler.ContainsKey(ebr.GetResourceData().Length))
                                {
                                    asm.HumanReasons.Add(new Reason("Resources", "Another resource has the same data/length."));
                                    d++;
                                }
                                else
                                {
                                    sizeHandler.Add(ebr.GetResourceData().Length, ebr);
                                }

                            }

                            
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

                                    if (b.Length > 300000)
                                    {
                                        asm.HumanReasons.Add(new Reason("Resources", "Large resource was found, larger than 300KB"));
                                        d++;
                                    }
                                }
                                if (a.Value is Bitmap)
                                {
                                    Bitmap bit = a.Value as Bitmap;
                                    // Icon check, icons generally have the same width & height
                                    if (bit.Size.Height != bit.Size.Width)
                                    {

                                        asm.HumanReasons.Add(new Reason("Resources", "Bitmap Resource was not equal dimensions, could be steganography."));
                                        d++;
                                    }

                                }

                                string cToReader = readerNames[r.Next(readerNames.Count - 1)];
                                if (cToReader != a.Key as string)
                                {
                                    int readerComp = LevenshteinDistance.Compute(ebr.Name, cToReader);

                                    if (readerComp < 5)
                                    {
                                        asm.HumanReasons.Add(new Reason("Resources", "Resource naming was consistent across others. Could mean split resources."));
                                        d++;
                                    }
                                }
                            }
                        }

                        // compare name to random
                        string cTo = names[r.Next(names.Count - 1)];
                        if (cTo != ebr.Name)
                        {
                            int comp = LevenshteinDistance.Compute(ebr.Name, cTo);

                            if (comp < 5)
                            {
                                asm.HumanReasons.Add(new Reason("Resources", "Resource naming was consistent across others. Could mean split resources."));
                                d++;
                            }
                        }
                        break;
                }
                readerNames.Clear();
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
