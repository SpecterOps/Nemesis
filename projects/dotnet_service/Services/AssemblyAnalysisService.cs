using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using ILSpyDecompilerService.Models;
using Microsoft.Extensions.Logging;
using Mono.Cecil;
using Newtonsoft.Json;

namespace ILSpyDecompilerService.Services
{
    public class AssemblyAnalysisService
    {
        private readonly ILogger<AssemblyAnalysisService> _logger;
        
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

        public AssemblyAnalysisService(ILogger<AssemblyAnalysisService> logger)
        {
            _logger = logger;
        }

        public string AnalyzeAssembly(string assemblyPath)
        {
            try
            {
                _logger.LogInformation($"Starting analysis of assembly: {assemblyPath}");
                
                // Validate that the file is actually an assembly
                try
                {
                    AssemblyName assemblyName = AssemblyName.GetAssemblyName(assemblyPath);
                }
                catch
                {
                    var errorResult = new { error = $"file path {assemblyPath} is not an assembly" };
                    return JsonConvert.SerializeObject(errorResult);
                }

                var result = AnalyzeAssemblyInternal(assemblyPath);
                var json = JsonConvert.SerializeObject(result);
                
                _logger.LogInformation($"Analysis completed for assembly: {assemblyPath}");
                return json;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to analyze assembly: {assemblyPath}");
                var errorResult = new { error = ex.Message };
                return JsonConvert.SerializeObject(errorResult);
            }
        }

        private AssemblyAnalysis AnalyzeAssemblyInternal(string assemblyPath)
        {
            string[] dnrChannel = { };
            string typeFilterLevel = "ldc.i4.2";
            string filterLevel = "Low";
            List<GadgetItem> listGadgets = new List<GadgetItem>();

            // Parse the target assembly and get its types
            AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(assemblyPath);
            IEnumerable<TypeDefinition> allTypes = assembly.MainModule.GetTypes();

            // Pull out all the types with methods that we want to look at
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
                            case string x when x.Contains("System.ServiceModel.ChannelFactory") && x.Contains("CreateChannel"):
                                gadgetName = WCF_CLIENT_STRING;
                                isWCFClient = true;
                                break;
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
                                remotingChannel = dnrChannel.Length > 5 ? dnrChannel[5] : "";
                                break;
                        }
                    }

                    if (!string.IsNullOrEmpty(gadgetName) || isWCFClient || isWCFServer || isRemoting)
                    {
                        listGadgets.Add(new GadgetItem
                        {
                            GadgetName = gadgetName,
                            IsDotNetRemoting = isRemoting,
                            RemotingChannel = remotingChannel,
                            IsWCFClient = isWCFClient,
                            IsWCFServer = isWCFServer,
                            IsExecution = isExecution,
                            MethodAppearance = $"{method.t.Name}.{method.m.Name}",
                            FilterLevel = gadgetName.Contains(BF_DESERIALIZE) ? filterLevel : null
                        });
                    }
                }
            }

            return CreateAssemblyAnalysis(Path.GetFileName(assemblyPath), listGadgets.ToArray());
        }

        private AssemblyAnalysis CreateAssemblyAnalysis(string assemblyName, GadgetItem[] items)
        {
            var analysis = new AssemblyAnalysis
            {
                AssemblyName = assemblyName,
                IsWCFClient = false,
                IsWCFServer = false,
                SerializationGadgetCalls = new Dictionary<string, Models.MethodInfo[]>(),
                ClientCalls = new Dictionary<string, Models.MethodInfo[]>(),
                WcfServerCalls = new Dictionary<string, Models.MethodInfo[]>(),
                RemotingCalls = new Dictionary<string, Models.MethodInfo[]>(),
                ExecutionCalls = new Dictionary<string, Models.MethodInfo[]>()
            };

            Dictionary<string, List<Models.MethodInfo>> temp = new Dictionary<string, List<Models.MethodInfo>>();
            Dictionary<string, List<Models.MethodInfo>> tempClient = new Dictionary<string, List<Models.MethodInfo>>();
            Dictionary<string, List<Models.MethodInfo>> tempServer = new Dictionary<string, List<Models.MethodInfo>>();
            Dictionary<string, List<Models.MethodInfo>> tempRemoting = new Dictionary<string, List<Models.MethodInfo>>();
            Dictionary<string, List<Models.MethodInfo>> tempExecution = new Dictionary<string, List<Models.MethodInfo>>();
            List<string> dnRemotingChannels = new List<string>();

            foreach (var gadget in items)
            {
                if (gadget.IsWCFClient && !tempClient.ContainsKey(gadget.GadgetName))
                    tempClient[gadget.GadgetName] = new List<Models.MethodInfo>();
                else if (gadget.IsWCFServer && !tempServer.ContainsKey(gadget.GadgetName))
                    tempServer[gadget.GadgetName] = new List<Models.MethodInfo>();
                if (gadget.IsDotNetRemoting && !tempRemoting.ContainsKey(gadget.GadgetName))
                    tempRemoting[gadget.GadgetName] = new List<Models.MethodInfo>();
                if (gadget.IsExecution && !tempExecution.ContainsKey(gadget.GadgetName))
                    tempExecution[gadget.GadgetName] = new List<Models.MethodInfo>();
                else if (!temp.ContainsKey(gadget.GadgetName))
                    temp[gadget.GadgetName] = new List<Models.MethodInfo>();

                if (gadget.IsWCFClient)
                {
                    tempClient[gadget.GadgetName].Add(new Models.MethodInfo
                    {
                        MethodName = gadget.MethodAppearance,
                        FilterLevel = gadget.FilterLevel
                    });
                }
                else if (gadget.IsWCFServer)
                {
                    tempServer[gadget.GadgetName].Add(new Models.MethodInfo
                    {
                        MethodName = gadget.MethodAppearance,
                        FilterLevel = gadget.FilterLevel
                    });
                }
                else if (gadget.IsDotNetRemoting)
                {
                    tempRemoting[gadget.GadgetName].Add(new Models.MethodInfo
                    {
                        MethodName = gadget.MethodAppearance,
                        FilterLevel = gadget.FilterLevel
                    });
                }
                else if (gadget.IsExecution)
                {
                    tempExecution[gadget.GadgetName].Add(new Models.MethodInfo
                    {
                        MethodName = gadget.MethodAppearance,
                        FilterLevel = gadget.FilterLevel
                    });
                }
                else
                {
                    temp[gadget.GadgetName].Add(new Models.MethodInfo
                    {
                        MethodName = gadget.MethodAppearance,
                        FilterLevel = gadget.FilterLevel
                    });
                }

                if (gadget.IsDotNetRemoting)
                    dnRemotingChannels.Add(gadget.RemotingChannel);
            }

            analysis.RemotingChannels = dnRemotingChannels.ToArray();

            foreach (var key in temp.Keys)
            {
                if (!string.IsNullOrEmpty(key))
                    analysis.SerializationGadgetCalls[key] = temp[key].ToArray();
            }
            foreach (var key in tempClient.Keys)
            {
                if (!string.IsNullOrEmpty(key))
                    analysis.ClientCalls[key] = tempClient[key].ToArray();
            }
            foreach (var key in tempServer.Keys)
            {
                if (!string.IsNullOrEmpty(key))
                    analysis.WcfServerCalls[key] = tempServer[key].ToArray();
            }
            foreach (var key in tempRemoting.Keys)
            {
                if (!string.IsNullOrEmpty(key))
                    analysis.RemotingCalls[key] = tempRemoting[key].ToArray();
            }
            foreach (var key in tempExecution.Keys)
            {
                if (!string.IsNullOrEmpty(key))
                    analysis.ExecutionCalls[key] = tempExecution[key].ToArray();
            }

            return analysis;
        }
    }
}