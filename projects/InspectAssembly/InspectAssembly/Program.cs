using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using Mono.Cecil;
using Newtonsoft.Json;

namespace InspectAssembly
{
    class Program
    {
        private const string BF_DESERIALIZE = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize";
        private const string DC_JSON_READ_OBJ = "System.Runtime.Serialization.Json.DataContractJsonSerializer::ReadObject";
        private const string DC_XML_READ_OBJ = "System.Runtime.Serialization.Xml.DataContractSerializer::ReadObject";
        private const string JS_SERIALIZER_DESERIALIZE = "System.Web.Script.Serialization.JavaScriptSerializer::Deserialize";
        private const string LOS_FORMATTER_DESERIALIZE = "System.Web.UI.LosFormatter::Deserialize";
        private const string NET_DATA_CONTRACT_READ_OBJ = "System.Runtime.Serialization.NetDataContractSerializer::ReadObject";
        private const string NET_DATA_CONTRACT_DESERIALIZE = "System.Runtime.Serialization.NetDataContractSerializer::Deserialize";
        private const string OBJ_STATE_FORMATTER_DESERIALIZE = "System.Web.UI.ObjectStateFormatter::Deserialize";
        private const string SOAP_FORMATTER_DESERIALIZE = "System.Runtime.Serialization.Formatters.Soap.SoapFormatter::Deserialize";
        private const string XML_SERIALIZER_DESERIALIZE = "System.Xml.Serialization.XmlSerializer::Deserialize";
        private const string REGISTER_CHANNEL = "System.Runtime.Remoting.Channels.ChannelServices::RegisterChannel";
        private const string WCF_SERVER_STRING = "System.ServiceModel.ServiceHost::AddServiceEndpoint";
        private const string WCF_CLIENT_STRING = "System.ServiceModel.ChannelFactory::CreateChannel";
        private const string JSCRIPT_EVALUATION = "Microsoft.JScript.Eval::JScriptEvaluate";
        private const string POWERSHELL_EVALUATION = "System.Management.Automation.Runspaces.Pipeline::Invoke";
        private const string PROCESS_START = "System.Diagnostics.Process::Start";

        private static string[] wcfServerGadgetNames = { WCF_SERVER_STRING };


        static void Main(string[] args)
        {
            //JsonConvert.SerializeObject()
            if (args.Length != 1)
            {
                Console.WriteLine("{\"error\": \"no file path provided\"}");
                return;
            }
            else if (!File.Exists(args[0]))
            {
                Console.WriteLine($"{{\"error\": \"file path {args[0]} does not exist\"}}");
                return;
            }

            var assemblyPath = args[0];

            try
            {
                // Make sure that the target is actually an assembly before we get started
                AssemblyName assemblyName = AssemblyName.GetAssemblyName(assemblyPath);
            }
            catch
            {
                Console.WriteLine($"{{\"error\": \"file path {args[0]} is not an assembly\"}}");
                return;
            }

            AssemblyAnalysis result = AnalyzeAssembly(assemblyPath);
            Console.WriteLine(JsonConvert.SerializeObject(result));
        }

        public static Dictionary<string, MethodInfo[]> FormatGadgets(Dictionary<string, MethodInfo[]> tmp)
        {
            Dictionary<string, MethodInfo[]> gadgets = new Dictionary<string, MethodInfo[]>();

            foreach (var key in tmp.Keys)
            {
                string[] gadgetParts = key.Replace("::", "|").Split('|');
                string gadget;
                if (gadgetParts.Length != 2)
                    gadget = key;
                else
                {
                    string[] typeParts = gadgetParts[0].Split('.');
                    gadget = String.Format("{0}::{1}()", typeParts[typeParts.Length - 1], gadgetParts[1]);
                }

                MethodInfo[] result = tmp[key].Distinct().Select((o) =>
                {
                    return o;
                }).ToArray();

                gadgets[gadget] = result;
            }
            return gadgets;
        }

        internal struct AssemblyAnalysis
        {
            string AssemblyName;
            public string[] RemotingChannels;
            public bool IsWCFServer;
            public bool IsWCFClient;
            public Dictionary<string, MethodInfo[]> SerializationGadgetCalls;
            public Dictionary<string, MethodInfo[]> WcfServerCalls;
            public Dictionary<string, MethodInfo[]> ClientCalls;
            public Dictionary<string, MethodInfo[]> RemotingCalls;
            public Dictionary<string, MethodInfo[]> ExecutionCalls;

            public AssemblyAnalysis(string assemblyName, GadgetItem[] items)
            {
                AssemblyName = assemblyName;
                IsWCFClient = false;
                IsWCFServer = false;
                Dictionary<string, List<MethodInfo>> temp = new Dictionary<string, List<MethodInfo>>();
                Dictionary<string, List<MethodInfo>> tempClient = new Dictionary<string, List<MethodInfo>>();
                Dictionary<string, List<MethodInfo>> tempServer = new Dictionary<string, List<MethodInfo>>();
                Dictionary<string, List<MethodInfo>> tempRemoting = new Dictionary<string, List<MethodInfo>>();
                Dictionary<string, List<MethodInfo>> tempExecution = new Dictionary<string, List<MethodInfo>>();
                List<string> dnRemotingChannels = new List<string>();

                foreach (var gadget in items)
                {
                    if (gadget.IsWCFClient && !tempClient.ContainsKey(gadget.GadgetName))
                        tempClient[gadget.GadgetName] = new List<MethodInfo>();
                    else if (gadget.IsWCFServer && !tempServer.ContainsKey(gadget.GadgetName))
                        tempServer[gadget.GadgetName] = new List<MethodInfo>();
                    if (gadget.IsDotNetRemoting && !tempClient.ContainsKey(gadget.GadgetName))
                        tempRemoting[gadget.GadgetName] = new List<MethodInfo>();
                    if (gadget.IsExecution && !tempClient.ContainsKey(gadget.GadgetName))
                        tempExecution[gadget.GadgetName] = new List<MethodInfo>();
                    else if (!temp.ContainsKey(gadget.GadgetName))
                        temp[gadget.GadgetName] = new List<MethodInfo>();
                    if (gadget.IsWCFClient)
                    {
                        tempClient[gadget.GadgetName].Add(new MethodInfo()
                        {
                            MethodName = gadget.MethodAppearance,
                            FilterLevel = gadget.FilterLevel
                        });
                    }
                    else if (gadget.IsWCFServer)
                    {
                        tempServer[gadget.GadgetName].Add(new MethodInfo()
                        {
                            MethodName = gadget.MethodAppearance,
                            FilterLevel = gadget.FilterLevel
                        });
                    }
                    else if (gadget.IsDotNetRemoting)
                    {
                        tempRemoting[gadget.GadgetName].Add(new MethodInfo()
                        {
                            MethodName = gadget.MethodAppearance,
                            FilterLevel = gadget.FilterLevel
                        });
                    }
                    else if (gadget.IsExecution)
                    {
                        tempExecution[gadget.GadgetName].Add(new MethodInfo()
                        {
                            MethodName = gadget.MethodAppearance,
                            FilterLevel = gadget.FilterLevel
                        });
                    }
                    else
                    {
                        temp[gadget.GadgetName].Add(new MethodInfo()
                        {
                            MethodName = gadget.MethodAppearance,
                            FilterLevel = gadget.FilterLevel
                        });
                    }
                    if (gadget.IsDotNetRemoting)
                        dnRemotingChannels.Add(gadget.RemotingChannel);
                }
                RemotingChannels = dnRemotingChannels.ToArray();
                SerializationGadgetCalls = new Dictionary<string, MethodInfo[]>();
                ClientCalls = new Dictionary<string, MethodInfo[]>();
                WcfServerCalls = new Dictionary<string, MethodInfo[]>();
                RemotingCalls = new Dictionary<string, MethodInfo[]>();
                ExecutionCalls = new Dictionary<string, MethodInfo[]>();
                foreach (var key in temp.Keys)
                {
                    if (!string.IsNullOrEmpty(key))
                        SerializationGadgetCalls[key] = temp[key].ToArray();
                }
                foreach (var key in tempClient.Keys)
                {
                    if (!string.IsNullOrEmpty(key))
                        ClientCalls[key] = tempClient[key].ToArray();
                }
                foreach (var key in tempServer.Keys)
                {
                    if (!string.IsNullOrEmpty(key))
                        WcfServerCalls[key] = tempServer[key].ToArray();
                }
                foreach (var key in tempRemoting.Keys)
                {
                    if (!string.IsNullOrEmpty(key))
                        RemotingCalls[key] = tempRemoting[key].ToArray();
                }
                foreach (var key in tempExecution.Keys)
                {
                    if (!string.IsNullOrEmpty(key))
                        ExecutionCalls[key] = tempExecution[key].ToArray();
                }
            }

            public override string ToString()
            {
                string fmtStr = "";
                var tmp = SerializationGadgetCalls;
                if (RemotingChannels.Length > 0)
                {
                    fmtStr += string.Format("  .NET Remoting Channels:\n");
                    foreach (var chan in RemotingChannels)
                        fmtStr += string.Format("    {0}\n", chan);
                }
                if (RemotingCalls.Keys.Count > 0)
                {
                    fmtStr += "  .NET Remoting:\n";
                    fmtStr += FormatGadgets(RemotingCalls);
                    //Console.WriteLine(FormatGadgets(RemotingCalls));

                    fmtStr += "    Remoting Channels:\n";
                    if (RemotingChannels.Length > 0)
                    {
                        foreach (var chan in RemotingChannels)
                            fmtStr += string.Format("      {0}\n", chan);
                    }
                }
                if (ClientCalls.Keys.Count > 0)
                {
                    fmtStr += "  WCFClient Gadgets:\n";
                    fmtStr += FormatGadgets(ClientCalls);
                }
                if (WcfServerCalls.Keys.Count > 0)
                {
                    fmtStr += "  WCFServer Gadgets:\n";
                    fmtStr += FormatGadgets(WcfServerCalls);
                }
                if (SerializationGadgetCalls.Keys.Count > 0)
                {
                    fmtStr += "  Serialization Gadgets:\n";
                    fmtStr += FormatGadgets(SerializationGadgetCalls);
                }
                if (fmtStr != "")
                    fmtStr = String.Format("Assembly Name: {0}\n", AssemblyName) + fmtStr;
                return fmtStr;
            }
        }

        public struct MethodInfo
        {
            public string MethodName;
            public string FilterLevel;

            public override string ToString()
            {
                return !string.IsNullOrEmpty(FilterLevel) ? string.Format("{0} (Filter Level: {1})", MethodName, FilterLevel) : MethodName;
            }
        }

        internal struct GadgetItem
        {
            internal bool IsDotNetRemoting;
            internal string RemotingChannel;
            internal bool IsWCFServer;
            internal bool IsWCFClient;
            internal bool IsExecution;
            internal string GadgetName;
            internal string FilterLevel;
            internal string MethodAppearance;

            public override string ToString()
            {
                //Console.WriteLine("[+] Assembly registers a .NET Remoting channel ({0}) in {1}.{2}", dnrChannel[5], method.t.Name, method.m.Name);
                string[] gadgetParts = GadgetName.Replace("::", "|").Split('|');
                string gadget;
                if (gadgetParts.Length != 2)
                    gadget = GadgetName;
                else
                {
                    string[] typeParts = gadgetParts[0].Split('.');
                    gadget = String.Format("{0}::{1}()", typeParts[typeParts.Length - 1], gadgetParts[1]);
                }
                string fmtMessage = String.Format(@"
IsDotNetRemoting     : {0}
    RemotingChannel  : {1}
IsWCFServer          : {2}
IsWCFClient          : {3}
IsExecution          : {4}
GadgetName           : {5}
MethodAppearance     : {6}", IsDotNetRemoting, RemotingChannel, IsWCFServer, IsWCFClient, IsExecution, gadget, MethodAppearance);
                if (!string.IsNullOrEmpty(FilterLevel))
                    fmtMessage += string.Format("\n\tFilterLevel      : {0}", FilterLevel);
                return fmtMessage;
            }
        }

        static AssemblyAnalysis AnalyzeAssembly(string assemblyName)
        {
            // Just in case we run into .NET Remoting
            string[] dnrChannel = { };
            string typeFilterLevel = "ldc.i4.2"; // Default opcode if not set manually
            string filterLevel = "Low";
            List<GadgetItem> listGadgets = new List<GadgetItem>();

            // Parse the target assembly and get its types
            AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(assemblyName);
            IEnumerable<TypeDefinition> allTypes = assembly.MainModule.GetTypes();

            // Pull out all the type with methods that we want to look at
            var validTypes = allTypes.SelectMany(t => t.Methods.Select(m => new { t, m }))
                .Where(x => x.m.HasBody);

            foreach (var method in validTypes)
            {
                // Disassemble the assembly and check for potentially vulnerable functions
                foreach (var instruction in method.m.Body.Instructions)
                {
                    string gadgetName = "";
                    bool isRemoting = false;
                    string remotingChannel = "";
                    bool isWCFServer = false;
                    bool isWCFClient = false;
                    bool isExecution = false;

                    // Deserialization checks
                    if (instruction.OpCode.ToString() == "callvirt")
                    {
                        switch (instruction.Operand.ToString())
                        {
                            case string x when x.Contains(BF_DESERIALIZE):
                                gadgetName = BF_DESERIALIZE;
                                break;
                            case string x when x.Contains(DC_JSON_READ_OBJ):
                                gadgetName = DC_JSON_READ_OBJ;
                                break;
                            case string x when x.Contains(DC_XML_READ_OBJ):
                                gadgetName = DC_XML_READ_OBJ;
                                break;
                            case string x when x.Contains(JS_SERIALIZER_DESERIALIZE):
                                gadgetName = JS_SERIALIZER_DESERIALIZE;
                                break;
                            case string x when x.Contains(LOS_FORMATTER_DESERIALIZE):
                                gadgetName = LOS_FORMATTER_DESERIALIZE;
                                break;
                            case string x when x.Contains(NET_DATA_CONTRACT_READ_OBJ):
                                gadgetName = NET_DATA_CONTRACT_READ_OBJ;
                                break;
                            case string x when x.Contains(NET_DATA_CONTRACT_DESERIALIZE):
                                gadgetName = NET_DATA_CONTRACT_DESERIALIZE;
                                break;
                            case string x when x.Contains(OBJ_STATE_FORMATTER_DESERIALIZE):
                                gadgetName = OBJ_STATE_FORMATTER_DESERIALIZE;
                                break;
                            case string x when x.Contains(SOAP_FORMATTER_DESERIALIZE):
                                gadgetName = SOAP_FORMATTER_DESERIALIZE;
                                break;
                            case string x when x.Contains(XML_SERIALIZER_DESERIALIZE):
                                gadgetName = XML_SERIALIZER_DESERIALIZE;
                                break;
                            case string x when x.Contains(POWERSHELL_EVALUATION):
                                gadgetName = POWERSHELL_EVALUATION;
                                isExecution = true;
                                break;
                            case string x when x.Contains(WCF_SERVER_STRING):
                                gadgetName = WCF_SERVER_STRING;
                                isWCFServer = true;
                                break;
                            case string x when x.Contains("System.ServiceModel.ChannelFactory") && x.Contains("CreateChannel"): // System.ServiceModel.ChannelFactory`1<ClassName.ClassName>::CreateChannel()
                                gadgetName = WCF_CLIENT_STRING;
                                isWCFClient = true;
                                break;
                            // Collect the TypeFilterLevel if it is explicitly set
                            case string x when x.Contains("set_FilterLevel(System.Runtime.Serialization.Formatters.TypeFilterLevel)"):
                                if (typeFilterLevel.EndsWith("3"))
                                {
                                    filterLevel = "Full";
                                }
                                break;
                        }

                    }
                    else if (instruction.OpCode.ToString().StartsWith("ldc.i4"))
                    {
                        typeFilterLevel = instruction.OpCode.ToString();
                    }
                    else if (instruction.OpCode.ToString() == "newobj" && instruction.Operand.ToString().Contains("System.Runtime.Remoting.Channels."))
                    {
                        // .NET Remoting Checks
                        dnrChannel = instruction.Operand.ToString().Split('.');
                    }
                    else if (instruction.OpCode.ToString() == "call")
                    {
                        switch (instruction.Operand.ToString())
                        {
                            case string x when x.Contains(JSCRIPT_EVALUATION):
                                gadgetName = JSCRIPT_EVALUATION;
                                isExecution = true;
                                break;
                            case string x when x.Contains(PROCESS_START):
                                gadgetName = PROCESS_START;
                                isExecution = true;
                                break;
                            case string x when x.Contains(REGISTER_CHANNEL):
                                isRemoting = true;
                                gadgetName = REGISTER_CHANNEL;
                                remotingChannel = dnrChannel[5];
                                break;
                        }
                    }

                    if (!string.IsNullOrEmpty(gadgetName) || isWCFClient || isWCFServer || isRemoting)
                    {
                        listGadgets.Add(new GadgetItem()
                        {
                            GadgetName = gadgetName,
                            IsDotNetRemoting = isRemoting,
                            RemotingChannel = remotingChannel,
                            IsWCFClient = isWCFClient,
                            IsWCFServer = isWCFServer,
                            IsExecution = isExecution,
                            MethodAppearance = String.Format("{0}.{1}", method.t.Name, method.m.Name),
                            FilterLevel = gadgetName.Contains(BF_DESERIALIZE) ? filterLevel : null
                        });
                    }
                }
            }

            return new AssemblyAnalysis(assemblyName, listGadgets.ToArray());
        }
    }
}