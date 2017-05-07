using AntiNET2;
using AntiNET2.Core.Models;
using AntiNET2.Core.Models.Database;
using AntiNET2.Core.Providers;
using AntiNET2.Core.Providers.Database;
using AntiNET2.Core.Providers.DetectionEngines.Managed;
using AntiNET2.Core.Providers.DetectionEngines.Native;
using dnlib.DotNet;
using dnlib.PE;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiNETCLI
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch sw = new Stopwatch();

            Console.Title = "AntiNET - \"False positive? Never!!1\"";

            // Trigger the db loading because it'll be counted in the time otherwise :s
            if (AntiNET2.Core.Providers.Database.DetectionDatabase.Calls == null)
            {
            }

            //AddDets();

            int totalDetections = 0;
            sw.Start();
            List<Detection> TotalDetections = Scanner.Scan(args[0], out totalDetections);
            sw.Stop();

            Console.WriteLine("Total Detection: {0}", totalDetections);

            /*var grouped = TotalDetections.GroupBy(x => x.DetectionType).ToDictionary(x => x.Key);
            foreach (var pair in grouped)
            {
                foreach (var x in pair.Value)
                {
                    x.DetectionReasons.ForEach(y => Console.WriteLine(y));
                }
            }*/


            // When you try to code, but can't, and then try half linq it...
            // :'(

            var grouped = TotalDetections.GroupBy(x => x.DetectionType).ToDictionary(x => x.Key);
            foreach (var pair in grouped)
            {
                foreach (var x in pair.Value)
                {
                    var z = x.DetectionReasons.GroupBy(a => a.ReasonType).ToDictionary(a => a.Key);
                    foreach (var p2 in z)
                    {
                        Console.WriteLine(p2.Key);
                        Dictionary<string, int> counts = new Dictionary<string, int>();

                        foreach (var x2 in p2.Value)
                        {
                            if (counts.ContainsKey(x2.Message))
                            {
                                counts[x2.Message]++;
                            }
                            else
                            {
                                counts.Add(x2.Message, 1);
                            }

                        }
                        foreach (var b in counts)
                        {
                            Console.WriteLine("\t{0}x {1}", b.Value, b.Key);
                        }
                    }
                }
            }

            Console.WriteLine("Total time taken for scanning: {0}", sw.Elapsed.TotalSeconds);
            
            Console.ReadKey();
        }

        static void AddDets()
        {
            PInvokeEntry p = new PInvokeEntry()
            {
                Category = "Dynamic Calls",
                Description = "Get Process Address",
                Trigger = "GetProcAddress",
                Tag = "DynCalls"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Memory",
                Description = "Read Process Memory",
                Trigger = "ReadProcessMemory",
                Tag = "Mem"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Memory",
                Description = "Write Process Memory",
                Trigger = "WriteProcessMemory",
                Tag = "Mem"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Thread",
                Description = "Resume Thread",
                Trigger = "ResumeThread",
                Tag = "Threads"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Process",
                Description = "Create new process",
                Trigger = "CreateProcess",
                Tag = "Procs"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Process",
                Description = "Open process",
                Trigger = "OpenProcess",
                Tag = "Procs"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Memory",
                Description = "Protect Memory",
                Trigger = "VirtualProtect",
                Tag = "Mem"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Memory",
                Description = "Allocate Memory",
                Trigger = "VirtualAlloc",
                Tag = "Mem"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Process",
                Description = "Terminate process",
                Trigger = "TerminateProcess",
                Tag = "Procs"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Anti-Debug",
                Description = "Output to debugger",
                Trigger = "OutputDebugString",
                Tag = "Debug"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Anti-Debug",
                Description = "Check if debugger present",
                Trigger = "IsDebuggerPresent",
                Tag = "Debug"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Process",
                Description = "Set Critical Process",
                Trigger = "RtlSetProcessIsCritical",
                Tag = "Procs"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Dynamic Calls",
                Description = "Load External Library",
                Trigger = "LoadLibrary",
                Tag = "DynCalls"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Thread",
                Description = "Set thread context",
                Trigger = "SetThreadContext",
                Tag = "Threads"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Thread",
                Description = "Set thread context x64",
                Trigger = "Wow64SetThreadContext",
                Tag = "Threads"
            };
            DetectionDatabase.AddDetection(p);
            p = new PInvokeEntry()
            {
                Category = "Hook",
                Description = "Low level Windows Hook",
                Trigger = "SetWindowsHook",
                Tag = "Hooks"
            };
            DetectionDatabase.AddDetection(p);



            ReflectionEntry r = new ReflectionEntry()
            {
                Trigger = "System.AppDomain::Load",
                Description = "Loading Assembly (Appdomain)",
                Category = "Load",
                Tag = "Load"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Reflection.Assembly::Load",
                Description = "Loading Assembly",
                Category = "Load",
                Tag = "Load"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Runtime.CompilerServices.RuntimeHelpers",
                Description = "Loading Assembly by Invoke (RuntimeHelpers)",
                Category = "Load",
                Tag = "Load"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Reflection.Assembly::get_EntryPoint",
                Description = "Getting Assembly EntryPoint",
                Category = "Invoke",
                Tag = "Invoke"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Reflection.MethodBase::Invoke",
                Description = "Invoking method with MethodBase",
                Category = "Invoke",
                Tag = "Invoke"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Type::InvokeMember",
                Description = "Invoking method with Type.InvokeMember",
                Category = "Invoke",
                Tag = "Invoke"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "Microsoft.VisualBasic.CompilerServices.NewLateBinding::",
                Description = "Late binding to invoke data",
                Category = "Invoke",
                Tag = "Invoke"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "Microsoft.VisualBasic.CompilerServices.Operators::OrObject",
                Description = "Or Object is used with NewLateBinding",
                Category = "Invoke",
                Tag = "Invoke"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Reflection.Module::ResolveSignature",
                Description = "Resolve signature to byte array (store data)",
                Category = "Resources",
                Tag = "Resources"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Reflection.Module::ResolveMethod",
                Description = "Resolve a method from MD Token",
                Category = "Invoke",
                Tag = "Invoke"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Type::GetMethod",
                Description = "Gets Method(s) from a type",
                Category = "Invoke",
                Tag = "Invoke"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Module::GetTypes",
                Description = "Gets Type(s) from a Module",
                Category = "Invoke",
                Tag = "Invoke"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Reflection.Emit.OpCodes",
                Description = "Initializing CIL related data",
                Category = "Dynamic",
                Tag = "Dynamic"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Reflection.Emit.ILGenerator",
                Description = "Using IL Generator",
                Category = "Dynamic",
                Tag = "Dynamic"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Runtime.InteropServices.Marshal::Alloc",
                Description = "Marshal Memory Allocation",
                Category = "Dynamic",
                Tag = "Dynamic"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Runtime.InteropServices.GCHandle::Alloc",
                Description = "GC Handle Allocation",
                Category = "Dynamic",
                Tag = "Dynamic"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Resources.ResourceManager::.ctor",
                Description = "Initializing ResourceManager",
                Category = "Resources",
                Tag = "Resources"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Resources.ResourceManager::GetObject",
                Description = "Getting Object from Resource Manager",
                Category = "Resources",
                Tag = "Resources"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Reflection.Assembly::GetManifestResource",
                Description = "Getting Resource from Assembly",
                Category = "Resources",
                Tag = "Resources"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Reflection.Assembly::GetManifestResource",
                Description = "Getting Resource from Assembly",
                Category = "Resources",
                Tag = "Resources"
            };
            DetectionDatabase.AddDetection(r);
            r = new ReflectionEntry()
            {
                Trigger = "System.Reflection.Assembly::GetManifestResourceNames",
                Description = "Getting Resource Names from Assembly",
                Category = "Resources",
                Tag = "Resources"
            };
            DetectionDatabase.AddDetection(r);
        }
    }
}
