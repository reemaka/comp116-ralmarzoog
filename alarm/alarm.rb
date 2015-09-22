require 'packetfu'
require 'base64'

def print_alert(incident_num, incident, source_ip, protocol, payload)
    alert = "#{incident_num}. ALERT: #{incident} is detected from "
    alert += "#{source_ip} (#{protocol}) (#{payload})!"
    puts alert
end

def parse_payload(payload)
    if !payload.empty?
        puts Base64.encode64(payload)
    end
end

def parse_log_line(line)
    if !line.empty?
        space_line = line.split(" ")
        source_ip = space_line.length > 0 ?  space_line[0] : ""
        quote_line = line.split('"')
        request = quote_line.length > 1 ? quote_line[1] : ""
        split_request = request.split(" ")
        protocol = split_request.length > 2 ? split_request[2] : ""
        split_protocol = protocol.split("/")
        protocol = split_protocol.length > 0 ? split_protocol[0] : ""
        payload = split_request.length > 1 ? split_request[0]  + " " + split_request[1] : ""
    end
    return source_ip, request, protocol, payload
end

args = ARGV
opt_index = args.index("-r")
index = 0

if (opt_index != nil)
    if args.length < opt_index + 2
        # error
    else
        begin
            log_file_name = args[opt_index + 1]
            File.open(log_file_name, "r") do |file|
                while (line = file.gets)
                    downcase_line = line.downcase
                    no_space_line = line.gsub(/\s+/, "")
                    source_ip, request, protocol, payload = parse_log_line(line)
                    if line.include?("phpmyadmin")
                        print_alert(index, "Someone looking for phpMyAdmin stuff", source_ip, protocol, payload)
                        index += 1
                    elsif line.include?("nmap")
                        print_alert(index, "Nmap scan", source_ip, protocol, payload)
                        index += 1
                    elsif line.include?("masscan")
                        print_alert(index, "Masscan", source_ip, protocol, payload)
                        index += 1
                    elsif no_space_line.include?("(){:;};")
                        print_alert(index, "Potential Shellshock scan", source_ip, protocol, payload)
                        index += 1
                    end
                end
            end
        rescue
            puts "Error"
        end
    end
else
    stream = PacketFu::Capture.new(start: true, iface: 'eth0', promisc: true,
                                  filter: 'tcp', save: true)
    #stream.show_live()

    stream.stream.each do |packet|
        pkt = PacketFu::Packet.parse(packet)
        parse_payload(pkt.payload)
        if pkt.class == PacketFu::TCPPacket
            puts pkt.tcp_flags
            flags = pkt.tcp_flags
            if flags.syn == 0 and flags.rst == 0 and flags.ack == 0
                if flags.select{ |f| f == 1}.empty?
                    print_alert(index, "NULL scan", pkt.ip_src, pkt.proto().last, pkt.payload.to_s)
                    index += 1
                end
                if flags.fin == 1 and flags.urg == 0 and flags.psh == 0
                    print_alert(index, "FIN scan", pkt.ip_src, pkt.proto().last, pkt.payload.to_s)
                    index += 1
                end
                if flags.fin == 1 and flags.psh == 1 and flags.urg == 1
                    print_alert(index, "XMAS scan", pkt.ip_src, pkt.proto().last, pkt.payload.to_s)
                    index += 1
                end
            end
        end
    end 
end


