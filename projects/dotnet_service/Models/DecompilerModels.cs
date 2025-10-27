using Newtonsoft.Json;
using System.Collections.Generic;

namespace ILSpyDecompilerService.Models
{
    public class InputMessage
    {
        [JsonProperty("object_id")]
        public string ObjectId { get; set; }
    }

    public class OutputMessage
    {
        [JsonProperty("object_id")]
        public string ObjectId { get; set; }
        
        [JsonProperty("decompilation")]
        public string Decompilation { get; set; }
        
        [JsonProperty("analysis")]
        public string Analysis { get; set; }
    }

    public class AssemblyAnalysis
    {
        public string AssemblyName { get; set; }
        public string Error { get; set; }
        public string[] RemotingChannels { get; set; }
        public bool IsWCFServer { get; set; }
        public bool IsWCFClient { get; set; }
        public Dictionary<string, MethodInfo[]> SerializationGadgetCalls { get; set; }
        public Dictionary<string, MethodInfo[]> WcfServerCalls { get; set; }
        public Dictionary<string, MethodInfo[]> ClientCalls { get; set; }
        public Dictionary<string, MethodInfo[]> RemotingCalls { get; set; }
        public Dictionary<string, MethodInfo[]> ExecutionCalls { get; set; }
    }

    public class MethodInfo
    {
        public string MethodName { get; set; }
        public string FilterLevel { get; set; }
    }

    public class GadgetItem
    {
        public bool IsDotNetRemoting { get; set; }
        public string RemotingChannel { get; set; }
        public bool IsWCFServer { get; set; }
        public bool IsWCFClient { get; set; }
        public bool IsExecution { get; set; }
        public string GadgetName { get; set; }
        public string FilterLevel { get; set; }
        public string MethodAppearance { get; set; }
    }
}