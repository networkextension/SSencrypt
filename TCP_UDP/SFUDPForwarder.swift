//
//  UDPReplayer.swift
//  Surf
//
//Copyright (c) 2016, networkextension
//All rights reserved.
//
//Redistribution and use in source and binary forms, with or without
//modification, are permitted provided that the following conditions are met:
//
//* Redistributions of source code must retain the above copyright notice, this
//list of conditions and the following disclaimer.
//
//* Redistributions in binary form must reproduce the above copyright notice,
//this list of conditions and the following disclaimer in the documentation
//and/or other materials provided with the distribution.
//
//* Neither the name of SSencrypt nor the names of its
//contributors may be used to endorse or promote products derived from
//this software without specific prior written permission.
//
//THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import Foundation
// UDP 直接转发器
class SFUDPForwarder:SFUDPConnector, GCDAsyncUdpSocketDelegate {
    
 
    
    var socket:GCDAsyncUdpSocket?
    var targetHost:String = "" //cache dest ip
    //var targetPort:UInt16 = 0
    
    
    var rule:SFRuler?
    
    override init(sip:NSData, dip:NSData,packet:UDPPacket) {
        super.init(sip: sip, dip: dip, packet: packet)
        //targetHost =
        //AxLogger.log("current only udp port 53 process, other port packet drop",level:.Warning)
        
        
        //socket = GCDAsyncUdpSocket.init(delegate: self, delegateQueue: dispatchQueue)
        //let rec:GCDAsyncUdpSocketReceiveFilterBlock = (NSData!, NSData!, AutoreleasingUnsafeMutablePointer<AnyObject?>) {
        
        //}
        targetHost = datatoIP(dip)
        start()
        
    }
    func start() {
        
        socket = GCDAsyncUdpSocket.init(delegate: self, delegateQueue: SFTCPConnectionManager.manager.dispatchQueue)
        
        do {
            //try socket?.connectToHost("192.168.11.1", onPort: 53)
            socket?.setDelegate(self)
            socket?.setDelegateQueue(SFTCPConnectionManager.manager.dispatchQueue)
            
            let message = String.init(format: "start udp %@:%d", targetHost ,dstPort)
            AxLogger.log(message,level: .Trace)
            try socket?.connectToHost(targetHost, onPort: dstPort)
            
        } catch let e as NSError {
            //AxLogger.log("can't connectToHost \(server)",level: .Erro)
            //NSLog("DNS can't connectToHost \(server) \(port) error:\(e)")
            AxLogger.log("DNS can't connectToHost \(e.description) ",level: .Error)
        }
    }
    func udpSocket(sock: GCDAsyncUdpSocket, didConnectToAddress address: NSData) {
        
        do {
            try sock.beginReceiving()
            connected = true
            processQuery()
        }catch let e as NSError {
            AxLogger.log("DNS:\(reqID) beginReceiving error :\(e.localizedDescription) ", level: .Error)
        }
        
    }
    override func addQuery(packet udp:UDPPacket!) {
        //let ip = IPv4Packet(PacketData:data)
        //let udp = UDPPacket.init(PacketData: ip.payloadData())
        sendingQueue.append(udp)
        
        
//        if  dstPort != 53 {
//            //AxLogger.log("dst \(dstPort) udp packet  drop")
//            if dstPort >= 16384 &&  dstPort <= 16386{
//                //AxLogger.log("Apple use udp  \(dstPort) Apple FaceTime, Apple Game Center (RTP/RTCP) http://www.speedguide.net/port.php?port=16386")
//            }
//            self.delegate!.serverDidClose(self)
//            return
//        }
        //let packet:DNSPacket = DNSPacket.init(data: udp.payloadData())
        //clientAddress = 0xf0070109.bigEndian// ip.srcIP
        // NSLog("DNS queryDomains:\(packet.queryDomains) via \(SFNetworkInterfaceManager.instances.dnsAddress())")
        // dstAddress = ip.destinationIP
        
        //let inden = packet.identifier
        //waittingQueriesMap[Int(queryIDCounter)] = inden
        //waittingQueriesTimeMap[inden] = NSDate()
        //AxLogger.log("inden:\(inden) clientPort:\(clientPort)",level: .Debug)
        //AxLogger.log("\(packet.queryDomains),waittingQueriesMap \(waittingQueriesMap)",level: .Debug)
        //let packet:DNSPacket = DNSPacket.init(packetData: data)
        
        //queries.append(packet!.rawData)
        processQuery()
        
    }
    
    func processQuery() {
        
//        //AxLogger.log("\(packet.rawData)")
//        
//        if (queryIDCounter == UInt16(UINT16_MAX)) {
//            queryIDCounter = 0
//        }
//        queryIDCounter += 1
        
     
        //let  queryID:UInt16 = queryIDCounter++;
        //data.replaceBytesInRange(NSMakeRange(0, 2), withBytes: queryID)
        
        //[data replaceBytesInRange:NSMakeRange(0, 2) withBytes:&queryID];
        //how to send data
        //waittingQueriesMap[queryID] = data
        //socket?.sendData(data, toHost: "192.168.0.245", port: 53, withTimeout: 10, tag: 0)
        //AxLogger.log("send dns request data: \(packet.rawData)",level: .Trace)
        
        activeTime = NSDate()
        let udp:UDPPacket = sendingQueue.removeFirst()
        //let clientPort = udp.sourcePort
        _ = udp.destinationPort
        if let s = socket {
            dispatch_async(SFTCPConnectionManager.manager.socketQueue){ [unowned self] in
                s.sendData(udp.payloadData(), withTimeout: 10, tag: 0)
            }
            
        }
        
    }
    internal func udpSocket(sock: GCDAsyncUdpSocket, didReceiveData tempdata: NSData, fromAddress address: NSData, withFilterContext filterContext: AnyObject?) {
        //收到dns replay packet
        activeTime = NSDate()
        AxLogger.log("UDP-\(reqID) recv data len:\(tempdata.length)", level: .Trace)
        var r:NSRange
        if address.length == 4{
            r = NSMakeRange(0, 4)
        }else {
            //10020035 c0a800f5 00000000 00000000 这个是ipv6?
            //addr = address.subdataWithRange(NSMakeRange(4, 4))
            r = NSMakeRange(4, 4)
        }
        
        var srcip:UInt32 = 0//0xc0a800f5//0b01 // 00f5
        //var dstip:UInt32 =  0xf0070109 //bigEndian//= 0xc0a80202
        //if let c = clientAddress {
        //c.getBytes(&dstip, length: 4)
        address.getBytes(&srcip, range: r)
        //}
        
        let data:NSData = tempdata
        
        
        //AxLogger.log("\(data) from address \(address.subdataWithRange(r))",level: .Trace)
        let data_len = 1460 - 28 //ip header + udp header
        if data.length != 0 {
            //NSLog("udpSocket recv data:%@", data)
            if data.length > data_len {
                var used:Int = 0
                let total:Int = data.length
                while used < total {
                    var buffer:NSData
                    if total - used > data_len {
                        buffer = data.subdataWithRange(NSMakeRange(used, data_len))
                        used += data_len
                    }else {
                        buffer = data.subdataWithRange(NSMakeRange(used, total - used))
                        used += total - used
                    }
                    writePacketData(buffer)
                }
            }else {
                 writePacketData(data)
            }
           
            
        }else {
            AxLogger.log("DNS request data error!",level: .Error)
            self.delegate!.serverDidClose(self)
        }
        
    }
    internal func writePacketData(data:NSData){
        //这里要修改
        //NSLog("dns packet %@", data)
        
        let  srcip:UInt32 = inet_addr(targetHost.cStringUsingEncoding(NSUTF8StringEncoding)!) //0xc0a800f5//0b01 // 00f5
        let dstip:UInt32 = inet_addr("240.7.1.9".cStringUsingEncoding(NSUTF8StringEncoding))//= 0xc0a80202
        
        let h = ipHeader(20+data.length+8, srcip ,dstip,queryIDCounter.bigEndian,UInt8(IPPROTO_UDP))
        queryIDCounter += 1
        
        //NSLog("DNS 111")
        
//        var udp:UDPPacket
//        var ip:IPv4Packet
//        var  packet:DNSPacket
//        if let cacheData = cacheData {
//            
//            cacheData.appendData(data)
//            packet = DNSPacket.init(data: cacheData)
//        }else {
//            packet = DNSPacket.init(data: data)
//        }
        //NSLog("DNS 222")
    
        let d = NSMutableData()
        d.appendData(h)
        
        let sport:UInt16 = dstPort
        d.write(sport.bigEndian)
        let cPort = clientPort //  waittingQueriesMap[inden]{
        d.write(UInt16((cPort.bigEndian)))
        
        let ulen = data.length + 8
        d.write(UInt16(ulen).bigEndian)
        d.write(UInt16(0))
        //        d.appendBytes(&(a.bigEndian), length: sizeof(a))
        //        d.appendBytes(&(srcport?.bigEndian) ,length: 2)
        d.appendData(data)
        //waittingQueriesMap.removeValueForKey(inden)
        if let delegate = self.delegate {
            delegate.serverDidQuery(self, data: d,close:  false)
        }
    }
     func udpSocket(sock: GCDAsyncUdpSocket, didNotConnect error: NSError){
        //NSLog("DNS didNotConnect: \(error)")
//        if let p = proxy {
//            let message = String.init(format: "#### %@:%d didNotConnect", p.serverAddress,p.serverPort)
//            AxLogger.log(message,level: .Error)
//            p.udpRelay = false
//            AxLogger.log("####  \(p.serverAddress):\(p.serverPort) UDP RELAY Error",level: .Warning)
//        }
        
        dispatch_async(dispatch_get_main_queue(), {
            if let d  = self.delegate {
                d.serverDidClose(self)
            }
        })
        
        
        
    }
    func udpSocket(sock: GCDAsyncUdpSocket, didSendDataWithTag tag: Int){
        //NSLog("DNS didSendDataWithTag")
    }
    func udpSocketDidClose(sock: GCDAsyncUdpSocket, withError error: NSError){
        //NSLog("DNS udpSocketDidClose \(error)")
        //socket?.setDelegate( nil)
        
        //socket = nil
        //self.start()
        if let d = delegate {
            d.serverDidClose(self)
        }
        
    }
    internal func udpSocket(sock: GCDAsyncUdpSocket, didNotSendDataWithTag tag: Int, dueToError error: NSError){
        //NSLog("DNS didNotSendDataWithTag \(error)")
        // self.delegate!.serverDidClose(self)
        if let d = delegate {
            d.serverDidClose(self)
        }
    }
    func shutdownSocket(){
        //maybe crash
        if let s = socket {
            s.setDelegate(nil)
            s.setDelegateQueue(nil)
            s.close()
        }
    }
    deinit {
        
        if let s = socket {
            s.setDelegate( nil)
            
            //s = nil
        }
        AxLogger.log("DNS-Server deinit",level: .Debug)
    }
    
}
