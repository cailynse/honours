#!/usr/bin/env ruby

require 'json'
require './mud-policy.rb'

HELP = <<-eos
This script will parse the given MUD policy into enforable network rules.
USAGE
  ./mud-parser.rb <FILEPATH>
FILEPATH - the path to the mud policy you would like parsed

EXAMPLE
  ./mud-parser.rb ./hue-bulb-mud.json
eos

if ARGV.size < 1
  puts 'error: required arguments are missing'
  puts '--'
  puts HELP
  exit(1)
end


FILEPATH=ARGV[0]

puts "Parsing mud policy located at #{FILEPATH}"

aces = []

mudpolicy_raw = File.read(FILEPATH)

mudpolicy = JSON.parse(mudpolicy_raw)

mud_policy_obj = MudPolicy.new(mudpolicy["ietf-mud:mud"]["systeminfo"].downcase, mudpolicy["ietf-mud:mud"]["mud-url"])

puts "Policy found for #{mud_policy_obj.device_name}"

ipv4_egress = mudpolicy["ietf-access-control-list:access-lists"]["acl"].find do |acl|
  acl["name"] == "from-ipv4-#{mud_policy_obj.device_name}"
end
match_options = ["ipv4", "tcp", "udp", "eth"]
# Make destination Profile (possible types ipv4, tcp, udp, eth)
ipv4_egress["aces"]["ace"].each do |ace|
  ace_obj = AccessControlEntry.new(ace["name"])

  match_types = ace["matches"].keys

  if match_types.include?("ipv4")
    ace_obj.protocol = ace["matches"]["ipv4"]["protocol"]
    ace_obj.dest_type = ace["matches"]["ipv4"].keys.find do |k|
        k != "protocol"
    end
    ace_obj.dest = ace["matches"]["ipv4"][ace_obj.dest_type]
  elsif match_types.includes("tcp")
    ace_obj.transport_protocol = "tcp"
    ace_obj.operator = ace["matches"]["tcp"]["destination-port"]["operator"]
    ace_obj.port = ace["matches"]["tcp"]["destination-port"]["port"]
  elsif match_types.includes("udp")
    ace_obj.transport_protocol = "udp"
    ace_obj.operator = ace["matches"]["udp"]["destination-port"]["operator"]
    ace_obj.port = ace["matches"]["udp"]["destination-port"]["port"]
  end
  #TODO HANDLE FOR ALTERNATIVE ACTIONS
  ace_obj.actions = ace["actions"]["forwarding"]
  aces << ace_obj
end

mud_policy_obj.aces = aces

puts mud_policy_obj.to_s