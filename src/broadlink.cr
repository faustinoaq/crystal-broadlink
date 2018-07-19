require "socket"
require "openssl/cipher"
require "colorize"

module Broadlink
  extend self

  def gendevice(devtype : UInt16, host : String, mac : Bytes)
    devices = {
      # Sp1 => [0],
      Sp2 => [
        0x2728, # SPMini20_1+11
      ],
      # Sp2 => [0x2711,                         # SP2
      #         0x2719, 0x7919, 0x271a, 0x791a, # Honeywell SP2
      #         0x2720,                         # SPMini
      #         0x753e,                         # SP3
      #         0x7D00,                         # OEM branded SP3
      #         0x947a, 0x9479,                 # SP3S
      #         0x2728,                         # SPMini2
      #         0x2733, 0x273e,                 # OEM branded SPMini
      #         0x7530, 0x7918,                 # OEM branded SPMini2
      #         0x2736                          # SPMiniPlus
      # ],
      # Rm => [0x2712, # RM2
      #        0x2737, # RM Mini
      #        0x273d, # RM Pro Phicomm
      #        0x2783, # RM2 Home Plus
      #        0x277c, # RM2 Home Plus GDT
      #        0x272a, # RM2 Pro Plus
      #        0x2787, # RM2 Pro Plus2
      #        0x279d, # RM2 Pro Plus3
      #        0x27a9, # RM2 Pro Plus_300
      #        0x278b, # RM2 Pro Plus BL
      #        0x2797, # RM2 Pro Plus HYC
      #        0x27a1, # RM2 Pro Plus R1
      #        0x27a6, # RM2 Pro PP
      #        0x278f  # RM Mini Shate
      # ],
      # A1  => [0x2714], # A1
      # Mp1 => [0x4EB5,  # MP1
      #         0x4EF7   # Honyar oem mp1
      # ],
      # Hysen => [0x4EAD], # Hysen controller
      # S1C   => [0x2722], # S1 (SmartOne Alarm Kit)
      # Dooya => [0x4E4D], # Dooya DT360E (DOOYA_CURTAIN_V2)
    }

    # Look for the class associated to devtype in devices
    device = devices.find(&.last.includes?(devtype))
    if device.nil?
      Device.new(host: host, mac: mac, devtype: devtype)
    else
      device.first.new(host: host, mac: mac, devtype: devtype)
    end
  end

  def discover(timeout = 10, local_ip_address = "")
    # TODO: use ifaddrs to local_address
    if local_ip_address.empty?
      s = UDPSocket.new
      begin
        s.connect("8.8.8.8", 53) # connecting to a UDP address doesn't send packets
      rescue ex
        abort ex.message
      end
      local_ip_address = s.local_address.address
    end

    address = local_ip_address.split('.')
    cs = UDPSocket.new
    cs.broadcast = true
    cs.reuse_address = true
    begin
      cs.bind(local_ip_address, 0)
    rescue ex
      abort ex.message
    end
    port = cs.local_address.port

    devices = [] of Device

    timezone = Time.now.offset/-3600
    packet = Bytes.new(0x30, 0)

    year = Time.now.year

    if timezone < 0
      packet[0x08] = (0xff + timezone - 1).to_u8
      packet[0x09] = 0xff
      packet[0x0a] = 0xff
      packet[0x0b] = 0xff
    else
      packet[0x08] = timezone.to_u8
      packet[0x09] = 0
      packet[0x0a] = 0
      packet[0x0b] = 0
    end
    packet[0x0c] = year.to_u8
    packet[0x0d] = (year >> 8).to_u8
    packet[0x0e] = Time.now.minute.to_u8
    packet[0x0f] = Time.now.hour.to_u8
    packet[0x10] = (Time.now.year % 100).to_u8
    packet[0x11] = Time.now.day_of_week.to_u8
    packet[0x12] = Time.now.day.to_u8
    packet[0x13] = Time.now.month.to_u8
    packet[0x18] = address[0].to_u8
    packet[0x19] = address[1].to_u8
    packet[0x1a] = address[2].to_u8
    packet[0x1b] = address[3].to_u8
    packet[0x1c] = port.to_u8
    packet[0x1d] = (port >> 8).to_u8
    packet[0x26] = 6
    checksum = 0xbeaf

    packet.each do |value|
      checksum += value
    end
    checksum = checksum & 0xffff
    packet[0x20] = checksum.to_u8
    packet[0x21] = (checksum >> 8).to_u8

    cs.send(packet, to: Socket::IPAddress.new("255.255.255.255", 80))

    cs.read_timeout = timeout
    while true
      begin
        response, ip = cs.receive(1024)
        responsepacket = response.to_slice
        host = ip.address
        mac = responsepacket[0x3a, 0x40 - 0x3a]
        devtype = responsepacket[0x34].to_u16 | responsepacket[0x35].to_u16 << 8
        dev = gendevice(devtype, host, mac)
        devices.push(dev)
      rescue ex : IO::Timeout
        abort ex.message if devices.empty?
        break
      end
    end
    devices
  end

  class Device
    include Broadlink

    KEY_PACKET = Bytes[0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02]
    IV_PACKET  = Bytes[0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58]
    ID_PACKET  = Bytes[0, 0, 0, 0]

    getter type : String, host, mac, devtype

    @count : UInt16
    @key : Bytes
    @iv : Bytes
    @id : Bytes

    def initialize(@host : String, @mac : Bytes, @devtype : UInt16, @timeout = 1)
      @count = rand(0xffff).to_u16
      @key = KEY_PACKET
      @iv = IV_PACKET
      @id = ID_PACKET
      @cs = UDPSocket.new
      @cs.broadcast = true
      @cs.reuse_address = true
      @cs.bind("0.0.0.0", 0)
      @type = "Unknown"
    end

    def decrypt(payload : Bytes)
      aes = OpenSSL::Cipher.new("aes-128-cbc")
      aes.decrypt
      aes.padding = false
      aes.iv = String.new(@iv)
      aes.key = String.new(@key)
      io = IO::Memory.new
      io.write(aes.update(String.new(payload)))
      io.write(aes.final)
      io.to_slice
    end

    def encrypt(payload : Bytes)
      aes = OpenSSL::Cipher.new("aes-128-cbc")
      aes.encrypt
      aes.padding = false
      aes.iv = String.new(@iv)
      aes.key = String.new(@key)
      io = IO::Memory.new
      io.write(aes.update(String.new(payload)))
      io.write(aes.final)
      io.to_slice
    end

    def auth?
      payload = Bytes.new(0x50)
      payload[0x04] = 0x31
      payload[0x05] = 0x31
      payload[0x06] = 0x31
      payload[0x07] = 0x31
      payload[0x08] = 0x31
      payload[0x09] = 0x31
      payload[0x0a] = 0x31
      payload[0x0b] = 0x31
      payload[0x0c] = 0x31
      payload[0x0d] = 0x31
      payload[0x0e] = 0x31
      payload[0x0f] = 0x31
      payload[0x10] = 0x31
      payload[0x11] = 0x31
      payload[0x12] = 0x31
      payload[0x1e] = 0x01
      payload[0x2d] = 0x01
      payload[0x30] = 'c'.ord.to_u8
      payload[0x31] = 'r'.ord.to_u8
      payload[0x32] = 'y'.ord.to_u8
      payload[0x33] = 's'.ord.to_u8
      payload[0x34] = 't'.ord.to_u8
      payload[0x35] = 'a'.ord.to_u8
      payload[0x36] = 'l'.ord.to_u8

      response = send_packet(0x65, payload)

      return false if response.empty?

      encoded = response[0x38, response.size - 0x38]
      new_payload = decrypt(encoded)
      return false if new_payload.empty?

      key = new_payload[0x04, 0x14 - 0x04]
      return false if key.size % 16 != 0

      @id = new_payload[0x00, 0x04]
      @key = key

      true
    end

    def send_packet(command : UInt8, payload : Bytes)
      @count = (@count + 1) & 0xffff
      packet = Bytes.new(0x38)
      packet[0x00] = 0x5a
      packet[0x01] = 0xa5
      packet[0x02] = 0xaa
      packet[0x03] = 0x55
      packet[0x04] = 0x5a
      packet[0x05] = 0xa5
      packet[0x06] = 0xaa
      packet[0x07] = 0x55
      packet[0x24] = 0x2a
      packet[0x25] = 0x27
      packet[0x26] = command
      packet[0x28] = @count.to_u8
      packet[0x29] = (@count >> 8).to_u8
      packet[0x2a] = @mac[0]
      packet[0x2b] = @mac[1]
      packet[0x2c] = @mac[2]
      packet[0x2d] = @mac[3]
      packet[0x2e] = @mac[4]
      packet[0x2f] = @mac[5]
      packet[0x30] = @id[0]
      packet[0x31] = @id[1]
      packet[0x32] = @id[2]
      packet[0x33] = @id[3]

      checksum = 0xbeaf
      payload.each do |value|
        checksum += value
        checksum = checksum & 0xffff
      end

      new_payload = encrypt(payload)

      packet[0x34] = checksum.to_u8
      packet[0x35] = (checksum >> 8).to_u8

      new_packet = Bytes.new(packet.size + new_payload.size)

      new_packet.copy_from(new_payload.reverse!)
      new_packet.reverse!
      new_packet.copy_from(packet)

      checksum = 0xbeaf
      new_packet.each do |value|
        checksum += value
        checksum = checksum & 0xffff
      end

      new_packet[0x20] = checksum.to_u8
      new_packet[0x21] = (checksum >> 8).to_u8

      begin
        @cs.send(new_packet, to: Socket::IPAddress.new(@host, 80))
        @cs.read_timeout = @timeout
        response, ip = @cs.receive(2048)
        return response.to_slice
      rescue ex : IO::Timeout
        puts ex.message
        return Bytes.empty
      end
    end
  end

  class Sp2 < Device
    include Broadlink

    def initialize(host, mac, devtype)
      super(host, mac, devtype)
      @type = "SP2 (Smart Plug)"
    end

    # Sets the power state of the smart plug.
    def power=(state : Bool)
      packet = Bytes.new(16)
      packet[0] = 2
      if nightlight?
        if state
          packet[4] = 3
        else
          2
        end
      else
        if state
          packet[4] = 1
        else
          0
        end
      end
      send_packet(0x6a, packet)
    end

    # Sets the night light state of the smart plug.
    def nightlight=(state : Bool)
      packet = Bytes.new(16)
      packet[0] = 2
      if power?
        if state
          packet[4] = 3
        else
          1
        end
      else
        if state
          packet[4] = 2
        else
          0
        end
      end
      send_packet(0x6a, packet)
    end

    # Returns the power state of the smart plug.
    def power?
      packet = Bytes.new(16)
      packet[0] = 1
      response = send_packet(0x6a, packet)
      error = response[0x22].to_u16 | (response[0x23].to_u16 << 8)
      if error == 0
        payload = decrypt(response[0x38, response.size - 0x38])
        if payload[0x4] == 1 || payload[0x4] == 3
          state = true
        else
          state = false
        end
        return state
      end
    end

    # Returns the power state of the smart plug.
    def nightlight?
      packet = Bytes.new(16)
      packet[0] = 1
      response = send_packet(0x6a, packet)
      error = response[0x22].to_u16 | (response[0x23].to_u16 << 8)
      if error == 0
        payload = decrypt(response[0x38, response.size - 0x38])
        if payload[0x4] == 1 || payload[0x4] == 3
          state = true
        else
          state = false
        end
        return state
      end
    end

    ENERGY_PACKET = Bytes[8, 0, 254, 1, 5, 1, 0, 0, 0, 45, 0, 0, 0, 0, 0, 0]

    def energy
      response = send_packet(0x6a, ENERGY_PACKET)
      error = response[0x22].to_u16 | (response[0x23].to_u16 << 8)
      if error == 0
        payload = decrypt(response[0x38, response.size - 0x38])
        centiwatts = payload[0x05].to_u16 + (payload[0x06].to_u16 | (payload[0x07].to_u16 << 8))
        centiwatts/100.0
      end
    end
  end

  # Setup a new Broadlink device via AP Mode. Review the README to see how to enter AP Mode.
  # Only tested with Broadlink RM3 Mini (Blackbean) & SP2 Mini (Urant Wifi Smart Power Plug)
  def setup(ssid : String, password : String, security_mode : UInt8)
    payload = Bytes.new(0x88)

    payload[0x26] = 0x14 # This seems to always be set to 14

    # Add the SSID to the payload
    ssid_start = 68
    ssid_length = 0
    ssid.each_char do |char|
      payload[ssid_start + ssid_length] = char.ord.to_u8
      ssid_length += 1
    end

    # Add the WiFi password to the payload
    pass_start = 100
    pass_length = 0
    password.each_char do |char|
      payload[pass_start + pass_length] = char.ord.to_u8
      pass_length += 1
    end

    payload[0x84] = ssid_length   # Character length of SSID
    payload[0x85] = pass_length   # Character length of password
    payload[0x86] = security_mode # Type of encryption (00 - none, 01 = WEP, 02 = WPA1, 03 = WPA2, 04 = WPA1/2)

    checksum = 0xbeaf
    payload.each do |value|
      checksum += value
      checksum = checksum & 0xffff
    end

    payload[0x20] = checksum.to_u8 # Checksum 1 position
    payload[0x21] = checksum >> 8  # Checksum 2 position

    sock = UDPSocket.new
    sock.broadcast = true
    sock.reuse_address = true
    sock.send(payload, to: Socket::IPAddress.new("255.255.255.255", 80))
  end
end

puts "Discovering..."
# devices = Broadlink.discover(timeout: 1)
devices = Broadlink.discover(timeout: 1, local_ip_address: "10.42.0.1")
devices.each do |device|
  if device.auth?
    puts
    puts "Device found!".colorize(:green)
    data = {
      "Type": device.type,
      "Hex":  "0x#{device.devtype.to_s(16)}",
      "Host": device.host,
      "Mac":  device.mac.map(&.to_s(16)).join,
    }
    data.each do |field, value|
      puts "#{field}:\t #{value}"
    end
    if device.responds_to? :temperature
      puts "Temperature:\t#{device.temperature}"
    end
  else
    puts "Error authenticating with device #{device.type} at #{device.host}".colorize(:red)
  end
end

device = Broadlink::Sp2.new("10.42.0.116", "7eefc1d43b4".to_slice, 0x2728_u16)
if device.auth?
  puts "Connected"
  puts "Testing power..."
  p! device.power?
  # device.power = false
  # p! device.power?
  # sleep 2
  # device.power = true
  # p! device.power?
  p! device.energy
  # puts "Testing nightlight..."
  # p! device.nightlight?
  # p! device.nightlight = false
  # p! device.nightlight?
  # sleep 1
  # p! device.nightlight = true
  # sleep 1
  # p! device.nightlight?
end
