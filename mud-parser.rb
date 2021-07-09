#!/usr/bin/env ruby

require 'json'

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

mudpolicy_raw = File.read(FILEPATH)

mudpolicy = JSON.parse(mudpolicy_raw)

devicename = mudpolicy["ietf-mud:mud"]["systeminfo"].downcase

puts "Policy found for #{devicename}"

ipv4_egress = mudpolicy["ietf-access-control-list:access-lists"]["acl"].find do |acl|
    acl["name"] == "from-ipv4-#{devicename}"
end

ipv4_egress["aces"]["ace"].each do |ace|
    puts "Name: "
    puts ace["name"]
    puts "Matches (ipv4): "
    pp "Protocol: #{ace["matches"]["ipv4"]["protocol"]}"
    dest_type = ace["matches"]["ipv4"].keys.find do |k|
        k != "protocol"
    end
    pp "Destination: #{ace["matches"]["ipv4"][dest_type]}"
    puts "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
end