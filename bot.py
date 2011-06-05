# Pcap bot
# Copyright(c) 2005 Jeremy Aldrich <jeremy@jeremyaldrich.net>
# MIT Licensed


import pcap, dpkt
import os
from struct import unpack
from binascii import hexlify

def readNullTerminatedString(data, index):
    i = 0
    while data[index + i] != '\x00':
        i += 1
    return data[index:index + i]

class Hal9000:
    segmentedPacket = ''
    segmentedPacketLength = 0
    
    def __init__(self,ip,debug=False):
        pc = pcap.pcap()
        pc.setfilter('udp and ip src %s'%(ip))
        if debug:
            self.debug = True
            path = os.path.join(os.path.expanduser('~'), 'bot', 'dump.txt')
            self.debugFile = open(path,'w')
        else: self.debug = False
        for ts, pkt in pc:
            # there seems to be an extra useless byte appended to
            # every packet.
            data = dpkt.ethernet.Ethernet(pkt).data.data.data[:-1]                              
            self.handlePacket(data)
            #self.debugDump(data)
            
    def debugDump(self,data,guess=None):
        """ Dump unknown packets into a file for later analyzation. If you supply a guess, it will be appended 
        to that packet. Only used if self.debug == True """
        f = self.debugFile
        i = data[0]
        flag = data[1]
        f.write('\n\n')
        if guess:            
            print 'GUESS:',guess
            f.write('GUESS: %s \n'%(guess))
        else: print 'Unknown Packet'
        counter = 0 
        firstPass = True
        if len(data) <= 4: 
            f.write('FIRST 2 OFFSETS: |0|%s->%s  |1|%s->%s \n'%(repr(data[0]),hexlify(data[0]),
                                                            repr(data[1]),hexlify(data[1])))
        else:
            f.write('FIRST 5 OFFSETS: |0|%s,%s  |1|%s,%s  |2|%s,%s  |3|%s,%s |4|%s,%s  \n'%(repr(data[0]),hexlify(data[0]),
                                                                             repr(data[1]),hexlify(data[1]),
                                                                             repr(data[2]),hexlify(data[2]),
                                                                             repr(data[3]),hexlify(data[3]),
                                                                             repr(data[4]),hexlify(data[4])))
        
        #Ghetto
        uglyData = '' 
        prettyData = ''
        for x in data:
            uglyData += str(hexlify(x))
            uglyData += ' '
            if ord(x) in xrange(32,125): prettyData += chr(ord(x))
            else: prettyData += '.'                
        #f.write('DATA: %s \n'%(hexlify(data)))
        
        f.write('DATA: %s \n'%(uglyData))
        f.write('PRETTY: %s \n'%(prettyData))
        for i,x in enumerate(data):
            counter += 1
            if counter >= 13: 
                f.write('\n')
                counter = 0
            else: 
                #Check For firstpass so first line / byte wont get tabbed. Looks prettier.
                if not firstPass:
                    f.write('\t')
                else:
                    firstPass = False
            f.write('|%s|:%s,%s'%(i,repr(x),hexlify(x)))           
        
    
    def handlePacket(self, data):        
        i = data[0]
        if i == '\x00':            
            self.handleCorePacket(data)
        elif i == '\x03':
            self.handlePlayerEntering(data)
        elif i == '\x04':
            self.handlePlayerLeaving(data)
        elif i == '\x09':
            # looks like message packets
            # offset 1 most likely indicates the type message (team, pub, etc.)
            #
            # if this is anything like the ?history message structure, then
            # possible types are:
            # 00 Public
            # 01 PublicMacro
            # 02 Private
            # 03 Team
            # 04 Enemy
            # 05 Arena
            # 06 Chat
            # 07 Squad
            # 08 Kill
            # 09 Info
            self.handleChatMessage(data)
        elif i == '\x0B':
            # possible unspec packet
            # player ID at offsets 1 and 2
            return
        elif i == '\x0C':
            # possible team change packet
            # player ID at offsets 1 and 2
            return
        elif i == '\x1B':
            # looks like another type of player position packet
            # these only seem to occur outside of spec
            return
        elif i == '\x28':
            self.handlePlayerPosition(data)
        else:
            # print 'Unknown packet type:', hexlify(i)
            return
    
    def handleCorePacket(self, data):
        i = data[1]
        if i == '\x03':
            # looks like another type of clustered packet with structure
            # like so:
            # Offset  Size  Comment
            # 0       1     type 0x00
            # 1       1     type 0x03
            # 2       1     length
            # 3       ?     payload
            #
            # this is similar to the clustered multi-type packet structure
            # below, with length + payload repeating throughout
            #
            # seems to be most commonly used for grouping together player
            # position packets
            #
            # in addition, this type of packet, and presumably others of a
            # clustered nature, can contain more clusters within it
            # i.e. I have observed 0x03 packexts which contain multi-type 0x09
            # clustered packets
            # I am not sure how deep this recursion runs...
            self.handleDiffRepeatingPackets(data)
        elif i == '\x06':
            # print 'Encountered core packet type 0x06:'
            # print hexlify(data)
            # print
            return
        elif i == '\x08':
            # print 'Encountered core packet type 0x08:'
            # print hexlify(data)
            # print
            return
        elif i == '\x09':
            #--> Reliable Chat  
            if data[4] == '\x09':
                self.handleChatMessage(data[4:])
            elif data[4] == '\x0f':
                self.handleKill(data[4:]) 
            else:
                self.handleClusterPacket(data)                                       
        elif i == '\x0D':
            self.handleSegmentedClusterPacket(data)
        elif i == '\x0E':
            # print 'Encountered core packet type 0x0E:'
            # print hexlify(data)
            # print
            return
        elif i == '\x15':
            # some sort of counter, perhaps used to keep packets in sync
            return
        elif i == '\x19':
            self.handleDiffRepeatingPackets(data)
        else:           
            if self.debug:
                self.debugDump(data)
            else: print 'Unknown core packet type:', hexlify(i)
    
   
    def handleClusterPacket(self, data, header = 1):
        """  
        Offset  Size  Comment
        0       1     type 0x00
        1       1     type 0x09
        2       2     some sort of counter
        4       ?     payload
    
         TODO: investigate offset 2 further
    
         If the first two bytes at offset 4 are 0x00 0x19, this seems to indicate
         that the cluster will contain multiple packet types. The following byte
         (offset 6) will indicate the length of the first packet. If the length
         were 108, you would read the first 108 bytes, and the 109th would contain
         the length of the next packet, and so on.
    
         I think it is safe to assume that if the 4th offset is not 0x00, no
         special handling is required and the cluster will contain only one type
         of packet. In this case, it does not provide the size of each packet.
         Luckily packet types like 0x03 seem to have a fixed size which makes
         processing easier.
        """
        if header:
            data = data[4:]
        i = data[0]
        if i == '\x00':
            self.handleCorePacket(data)               
        else:
            self.handleRepeatingPackets(data)
    
    def handleRepeatingPackets(self, data):
        i = data[0]
        if i == '\x03':
            pktLen = 108                 
        else:
            return
        for p in range(0, len(data) / pktLen):
            start = pktLen * p
            end = start + pktLen
            self.handlePacket(data[start:end])
    
   
    def handleDiffRepeatingPackets(self, data):
        """
        If a byte of 0xFF is found where a single packet length byte is expected,
        it seems to indicate that a group of same repeating packets should be
        handled. The length of this group is then a short at the next 2 offsets.
        """
        start = 2
        while 1:
            if data[start] == '\xFF':
                pktLen = unpack('!h', data[start + 1:start + 3])[0]
                start += 3
                end = start + pktLen
                self.handleRepeatingPackets(data[start:end])
            else:
                pktLen = ord(data[start])
                start += 1
                end = start + pktLen
                self.handlePacket(data[start:end])
            if end >= len(data):
                break
            start = end
    

    def handleSegmentedClusterPacket(self, data):
        """
        Offset  Size  Comment
         0       1     type 0x00
         1       1     type 0x09
         2       2     some sort of counter
         4       2     unknown
         6       2     length of all segments
         8       ?     payload
    
         TODO: investigate offsets 2 and 4 further
        """
        if self.segmentedPacketLength == 0:
            self.segmentedPacketLength = unpack('>h', data[6:8])[0]
            self.segmentedPacket = data[8:]
        else:
            self.segmentedPacket += data[4:]
        if len(self.segmentedPacket) >= self.segmentedPacketLength:
            self.segmentedPacketLength = 0
            self.handleClusterPacket(self.segmentedPacket, 0)
            self.segmentedPacket = ''
    

    def handlePlayerEntering(self, data):
        """
        Offset  Size  Comment
        0       1     type 0x03
        1       32    team
        33      32    alias
        65      32    squad
        97      2     player id
        99 
    
        TODO: figure out offsets 99 - 120
    
         - All packets of this sort seem to be a fixed 120 bytes.
         - Player IDs are zone-specific, and possibly even arena-specific?
         - Strings are null-padded and null-terminated.
        """
        #if self.debug: self.debugDump(data,guess="Player Entering")
        team  = data[1:32].rstrip('\x00')
        alias = data[33:64].rstrip('\x00')
        squad = data[65:96].rstrip('\x00')
        pid   = unpack('<h', data[97:99])[0]
        
        print 'Player entering:'
        print '    Alias:', alias
        print '       ID:', pid
        print '     Team:', team
        print '    Squad:', squad
    
   
    def handlePlayerLeaving(self, data):
        """
        Offset  Size  Comment
        0       1     type 0x04
        1       2     player id
        """
        pid = unpack('<h', data[1:])[0]
        #print 'Player leaving:', pid
    
   
    def handleChatMessage(self, data):
        """
        Offset  Size  Comment
         0       1     type 0x03
         1       1     message type
         2       1     sound type
         3       ?     message
        """
        messageType = ord(data[1:2])
        soundType   = ord(data[2:3])
        player      = readNullTerminatedString(data, 3)
        message     = readNullTerminatedString(data, len(player) + 4)
        
        #print 'Chat Message:'
        #print '    Message Type:', messageType
        #print '      Sound Type:', soundType
        #print '          Player:', player
        #print '         Message:', repr(message)
    
    def handlePlayerPosition(self, data):
        return
    
    def handleKill(self,data):
        self.debugDump(data,guess='KILL PACKET')
        killerID = unpack('<h',data[4:6])[0]
        victimID = unpack('<h',data[6:8])[0]      
        points = unpack('<h',data[10:12])[0]

        print 'KILL DETECTED'
        print 'Killer: ', killerID
        print 'Victim: ', victimID
        print 'Points: ', points
        print
    

if __name__ == '__main__':
    Hal9000(ip='', debug=True)
