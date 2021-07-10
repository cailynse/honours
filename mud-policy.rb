class MudPolicy
  attr_accessor :device_name, :aces

  def initialize(name, mud_url)
      @device_name = name
      @mud_url = mud_url
  end

  def to_s
    "MUD Policy for #{@device_name} with url #{@mud_url} and #{@aces.length} access control entries."
  end
end

class AccessControlEntry
  attr_accessor :protocol, :dest_type, :dest, :transport_protocol, :operator, :port, :actions
  
  def initialize(name)
    @name = name
  end
end