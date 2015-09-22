require 'packetfu'

stream = PacketFu::Capture.new(start: true, iface: 'eth0', promisc: true,
                              filter: 'tcp', save: true)
#stream.show_live()


stream.stream.each do |packet|
    pkt = PacketFu::Packet.parse(packet)
    puts pkt.class
    if pkt.class == PacketFu::TCPPacket
        puts pkt.tcp_flags
        flags = pkt.tcp_flags
        if flags.syn == 0 and flags.rst == 0 and flags.ack == 0
            if flags.select{ |f| f == 1}.empty?
                puts "ALERT: NULL scan detected from #{pkt.ip_src} (TCP)"
            end
            if flags.fin == 1 and flags.urg == 0 and flags.psh == 0
                puts "ALERT: FIN scan detected from #{pkt.ip_src} (TCP)"
            end
            if flags.fin == 1 and flags.psh == 1 and flags.urg == 1
                puts "ALERT: XMAS scan detected from #{pkt.ip_src} (TCP)"
            end
        end
    end
end 


