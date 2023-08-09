#
# Author: @harmj0y
#
# Heavily adapted from https://github.com/chrismaddalena/ShellHerder/blob/master/ShellHerder.rb

require 'yaml'
require 'json'
require 'uri'
require 'time'
require 'net/http'

module Msf
  class Plugin::Nemesis < Msf::Plugin

    include Msf::SessionEvent

    # config globals
    $nemesis_url =  nil
    $nemesis_user = nil
    $nemesis_password = nil
    $nemesis_project = nil
    $expiration_days = nil
    $remote_paths = Hash.new
    $nemesis_yaml = "#{Msf::Config.get_config_root}/nemesis.yaml"


    def name
      'nemesis'
    end


    def desc
      "Ingests data into Nemesis"
    end


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


    def initialize(framework, opts)
      super
      if read_settings()
        self.framework.events.add_session_subscriber(self)
        print_good("Nemesis Connector Started")
      else
        print_error("Could not load Nemesis settings.")
      end
    end


    def cleanup
      self.framework.events.remove_session_subscriber(self)
    end


    # helper to build the metadata hash table for data submission
    def get_metadata(agent_uuid)
      timestamp = Time.now
      expiration = timestamp + $expiration_days * 86400 # 24 * 60 * 60
      metadata = {
        "agent_type"  => "meterpreter",
        "automated"   => true,
        "agent_id"    => agent_uuid,
        "data_type"   => "file_data",
        "project"     => $nemesis_project,
        # "source"     => session.sys.config.sysinfo["Computer"],
        "timestamp"   => timestamp.utc.iso8601,
        "expiration"  => expiration.utc.iso8601
      }
      return metadata
    end


    # posts raw file bytes to the /api/file endpoint and returns the Nemesis file UUID
    def post_file(file_path)
      # TODO later for possible opsec-on-upload blocking: https://yukimotopress.github.io/http

      uri = URI("#{$nemesis_url}file")
      req = Net::HTTP::Post.new(uri, 'Content-Type' => 'application/octet-stream')
      req.basic_auth $nemesis_user, $nemesis_password
      req['User-Agent'] = "METERPRETER"
      req.body = File.open(file_path, 'rb') { |io| io.read }
      begin
        res = Net::HTTP.start(uri.hostname, uri.port) { |http|
          http.request(req)
        }
        return JSON.parse(res.body)["object_id"]
      rescue ::Exception => e
        print_error("Exception connecting to Nemesis : #{e}")
        return nil
      end
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


    # main logic that checks for the download completion message
    #   and syncs submits the downloaded file to Nemesis
    def on_session_output(session, output)

      # check for completed download messages
      if output.starts_with?("download   :")
        data = output[13..-1]
        parts = data.split("->")
        if parts.length() == 2
          file_origin = parts[0].strip().tr('\\', '/')
          file_dest = parts[1].strip()

          username = ""
          hostname = ""
          info_parts = session.info.split("@")
          if info_parts.length() == 2
            username = info_parts[0].strip()
            hostname = info_parts[1].strip()
          end

          # if not absolute or UNC path, construct using the current working directory
          if not file_origin.match(/([A-Za-z]:|^\/\/)/)

            # get the current working directory
            working_directory = session.fs.dir.pwd.tr('\\', '/')

            if not working_directory.ends_with? "/"
              working_directory = "#{working_directory}/"
            end

            file_origin = "#{working_directory}#{file_origin}"
          end

          # print_status("file_dest : _#{file_dest}_")
          # print_status("Info: _#{username}_#{hostname}_")
          # print_status("Host: #{session.session_host}")
          # print_status("UUID: #{session.uuid}")

          # post the file bytes to get the Nemesis UUID back
          nemesis_uuid = post_file(file_dest)
          print_good("'#{file_origin}' uploaded to Nemesis for processing, file UUID: #{nemesis_uuid}")

          file_size = File.size(file_dest)

          data = {
            "metadata"  => get_metadata(session.uuid),
            "data"      => [
              {
              "path"      => file_origin,
              "size"      => file_size,
              "object_id" => nemesis_uuid
              }
            ]
          }
          # resp format: {"object_id":"0a75872b-338c-484f-8251-f018d2e20290"}
          resp = post_data(data)
        end
    end

  end
end
end