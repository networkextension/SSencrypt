//
//  DNSServer.swift
//  SimpleTunnel
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
//

import Foundation

import Darwin
import NetworkExtension

//
//let dispatchQueue = dispatch_queue_create("DNSServer", nil);
//let socketQueue = dispatch_queue_create("com.abigt.socket.dns", nil);
public  class SFDNSForwarder:SFUDPConnector, GCDAsyncUdpSocketDelegate{
    
//    var decrypt_ctx:SEContextRef =  SEContextRef.alloc(1)//enc_ctx_create()//
//    var encrypt_ctx:SEContextRef =  SEContextRef.alloc(1)//enc_ctx_create()//SEContextRef.alloc(1)
//    let sbuf:bufferRef = bufferRef.alloc(1)
//    let rbuf:bufferRef = bufferRef.alloc(1)
    
    var domains:[String] = []
    
    //var packet:DNSPacket?
    var socket:GCDAsyncUdpSocket?
    var waittingQueriesMap:[Int:UInt16] = [:]// iden:port
    var queries:[DNSPacket] = []
    //var queryIDCounter:UInt16 = 0
    var targetHost:String = ""
    let targetPort:UInt16 = 53
    
    var proxy:SFProxy!
    var startTime:NSDate = NSDate()
    var dnsSetting:DNSServer?
    var cacheData:NSMutableData?
    override init(sip: NSData, dip: NSData, packet: UDPPacket) {
        
        //targetHost = server
        super.init(sip: sip, dip: dip, packet: packet)
        
         start()
    }
    func config() -> Bool{
        
        //        decrypt_ctx = enc_ctx_create()
        //        encrypt_ctx = enc_ctx_create()
        if let p = ProxyGroupSettings.share.findProxy("Proxy") {
            if p.type == .SS && p.udpRelay {
                proxy = p
                let m = 0// settingSS(proxy!.password,method: proxy!.method)
                if m == -1 {
                    return false
                }
//                enc_ctx_init(m, encrypt_ctx, 1);
//                enc_ctx_init(m, decrypt_ctx, 0);
//                
//                balloc(sbuf,Int(TCP_CLIENT_SOCKS_RECV_BUF_SIZE_UInt))
//                balloc(rbuf,Int(TCP_CLIENT_SOCKS_RECV_BUF_SIZE_UInt))
                
                return true

            }
            

        }
        
        //        if targetHost.characters.count > 0 {
        //            buildHead()
        //        }
        
        return false
    }

    func buildHead() ->NSData {
        let header = NSMutableData()
        //NSLog("TCPSS %@:%d",targetHost,targetPort)
        //targetHost is ip or domain
        var addr_len = 0
        
        //        let  buf:bufferRef = bufferRef.alloc(1)
        //        balloc(buf,BUF_SIZE)
        let  request_atyp:SOCKS5HostType = validateIpAddr(targetHost)
        if  request_atyp  == .IPV4{
            
            header.write(SOCKS_IPV4)
            addr_len += 1
            //AxLogger.log("\(cIDString) target host use ip \(targetHost) ",level: .Debug)
            let i :UInt32 = inet_addr(targetHost.cStringUsingEncoding(NSUTF8StringEncoding)!)
            header.write(i)
            header.write(targetPort.byteSwapped)
            addr_len  +=  sizeof(UInt32) + 2
            
        }else if request_atyp == .DOMAIN{
            
            header.write(SOCKS_DOMAIN)
            addr_len += 1
            let name_len = targetHost.characters.count
            header.write(UInt8(name_len))
            addr_len += 1
            header.write(targetHost)
            addr_len += name_len
            header.write(targetPort.byteSwapped)
            addr_len += 2
        }else {
            //ipv6
            header.write(SOCKS_IPV6)
            addr_len += 1
            if let data =  toIPv6Addr(targetHost) {
                
                
                //AxLogger.log("\(cIDString) convert \(targetHost) to Data:\(data)",level: .Info)
                header.write(data)
                header.write(targetPort.byteSwapped)
            }else {
                //AxLogger.log("\(cIDString) convert \(targetHost) to in6_addr error )",level: .Warning)
                //return
            }
            //2001:0b28:f23f:f005:0000:0000:0000:000a
            //            let ptr:UnsafePointer<Int8> = UnsafePointer<Int8>.init(bitPattern: 32)
            //            let host:UnsafeMutablePointer<Int8> = UnsafeMutablePointer.init(targetHost.cStringUsingEncoding(NSUTF8StringEncoding)!)
            //            inet_pton(AF_INET6,ptr,host)
        }
        return header
    }

    func start() {
        
        //SFNetworkInterfaceManager.instances.updateInfo()
        if !targetHost.isEmpty && targetHost != proxyIpAddr{
            dnsSetting =  DNSServer.init(ip:targetHost,sys:true)
        }else{
            dnsSetting = SFDNSManager.manager.giveMeAserver()
        }
        guard let dnsSetting = dnsSetting else {return}
        AxLogger.log("use dns server:\(dnsSetting.ipaddr)",level: .Debug)
        socket = GCDAsyncUdpSocket.init(delegate: self, delegateQueue: SFTCPConnectionManager.manager.dispatchQueue)
        var port:UInt16 = 53
        do {
            //try socket?.connectToHost("192.168.11.1", onPort: 53)
            socket?.setDelegate(self)
            socket?.setDelegateQueue(SFTCPConnectionManager.manager.dispatchQueue)
            if config() {
                
                if let proxy = proxy {
                    if proxy.udpRelay {
                        //server = proxy.serverAddress
                        //port = UInt16(proxy.serverPort)!
                    }
                }
            }
           // let message = String.init(format: "DNS START UDP %@:%d", server ,port)
            //debugLog(message)
            try socket?.connectToHost(dnsSetting.ipaddr, onPort: port)
            
        } catch let e as NSError {
            AxLogger.log("DNS can't connectToHost \(dnsSetting.ipaddr) \(e)",level: .Error)
        }
    }
    override func addQuery(packet udp:UDPPacket!) {
        //let ip = IPv4Packet(PacketData:data)
        //let udp = UDPPacket.init(PacketData: ip.payloadData())
        //en queue
        sendingQueue.append(udp)
        if connected {
            processQuery()
        }else {
            AxLogger.log("UDP:\(reqID) not connected packet en queue",level: .Error)
        }
        
    }
   
    func processQuery() {
        let udp:UDPPacket = sendingQueue.removeFirst()
        clientPort = udp.sourcePort
        
        
        
        
        let packet:DNSPacket = DNSPacket.init(data: udp.payloadData())
        //clientAddress = 0xf0070109.bigEndian// ip.srcIP
        
        AxLogger.log("DNS queryDomains:\(packet.queryDomains) ",level:.Verbose)
        // dstAddress = ip.destinationIP
        
        let inden = packet.identifier
        waittingQueriesMap[Int(queryIDCounter)] = inden
        waittingQueriesTimeMap[inden] = NSDate()
        //AxLogger.log("inden:\(inden) clientPort:\(clientPort)",level: .Debug)
        //AxLogger.log("\(packet.queryDomains),waittingQueriesMap \(waittingQueriesMap)",level: .Debug)
        //let packet:DNSPacket = DNSPacket.init(packetData: data)
        
        queries.append(packet)
        
        
        //AxLogger.log("\(packet.rawData)")
        AxLogger.log("DNSFORWARDER now send query \(packet.queryDomains.first!)",level: .Verbose)
        if (queryIDCounter == UInt16(UINT16_MAX)) {
            queryIDCounter = 0
        }
        queryIDCounter += 1
        
        if let domain = packet.queryDomains.first {
            if !domain.isEmpty {
                
                //去点操作
                let d = domain.delLastN(1)
                var ip:String = ""
                if let x = SFSettingModule.setting.queryDomain(d) where !x.isEmpty {
                    AxLogger.log("\(idString) hit HOST \(domain):\(ip) Found",level: .Notify)
                    ip = x
                }else {
                    if let x = SFSettingModule.setting.searchDomain(domain) where !x.isEmpty {
                        ip = x
                        AxLogger.log("\(idString) hit CACHE \(domain):\(ip) Found",level: .Notify)

                    }
                }
                    
                if !ip.isEmpty {
                    
                    let respData = DNSPacket.genPacketData(ip, domain: d, identifier: packet.identifier)
                    
                    //                NSLog("%@", packet.rawData)
                    //                NSLog( "%@ " ,respData)
                    //                NSLog(  domain+ip)
                    writeDNSPacketData(respData,cache: false)
                    return
                }
            }else {
                AxLogger.log("\(idString) req:\(packet.rawData)",level: .Error)
            }
            
            
        }
        
        //let  queryID:UInt16 = queryIDCounter++;
        //data.replaceBytesInRange(NSMakeRange(0, 2), withBytes: queryID)
        
        //[data replaceBytesInRange:NSMakeRange(0, 2) withBytes:&queryID];
        //how to send data
        //waittingQueriesMap[queryID] = data
        //socket?.sendData(data, toHost: "192.168.0.245", port: 53, withTimeout: 10, tag: 0)
       //AxLogger.log("send dns request data: \(packet.rawData)",level: .Trace)
        
        activeTime = NSDate()
        if let _ = proxy {
//            let temp = NSMutableData()
//            let head = buildHead()
//            temp.appendData(head)
//            temp.appendData(packet.rawData)
//            brealloc(sbuf,temp.length,CLIENT_SOCKS_RECV_BUF_SIZE)
//            buffer_t_copy(sbuf,UnsafePointer(temp.bytes),temp.length)
//            var  len = buffer_t_len(sbuf)
//            let ret = ss_encrypt(sbuf,encrypt_ctx,len)
//            if ret != 0 {
//                //abort()
//                //AxLogger.log("\(cIDString) ss_encrypt error ",level: .Error)
//            }
//            len = buffer_t_len(sbuf)
//            let result = NSData.init(bytes: buffer_t_buffer(sbuf), length: len)
//
//            if let s = socket {
//                s.sendData(result, withTimeout: 0.5, tag: Int(packet.identifier))
//            }
        }else {
            if let s = socket {
                startTime = NSDate()
                dispatch_async(SFTCPConnectionManager.manager.socketQueue){
                    s.sendData(packet.rawData, withTimeout: 0.5, tag: Int(packet.identifier))
                }
                
            }
            
            
        }
        
        
    }
    var idString:String{
        return "UDP-DNS:\(reqID)"
    }
    public func udpSocket(sock: GCDAsyncUdpSocket, didConnectToAddress address: NSData) {
        do {
            try sock.beginReceiving()
            AxLogger.log("\(idString) start recv", level: .Trace)
        }catch let e as NSError {
            AxLogger.log("\(idString) beginReceiving error :\(e.localizedDescription) ", level: .Error)
        }
        connected = true
        processQuery()
        
    }
    public func udpSocket(sock: GCDAsyncUdpSocket, didReceiveData tempdata: NSData, fromAddress address: NSData, withFilterContext filterContext: AnyObject?) {
        //收到dns replay packet
        activeTime = NSDate()
       
        var r:NSRange
        if address.length == 4{
            r = NSMakeRange(0, 4)
        }else {
            //10020035 c0a800f5 00000000 00000000 这个是ipv6?
            //addr = address.subdataWithRange(NSMakeRange(4, 4))
            r = NSMakeRange(4, 4)
        }
        
        var srcip:UInt32 = 0//0xc0a800f5//0b01 // 00f5
        var dstip:UInt32 = 0xf0070109 //bigEndian//= 0xc0a80202
        //if let c = clientAddress {
            //c.getBytes(&dstip, length: 4)
            address.getBytes(&srcip, range: r)
        //}
        
        var data:NSData?
        if let p = proxy {
//            buffer_t_copy(rbuf,UnsafePointer(tempdata.bytes),tempdata.length)
//            let ret = ss_decrypt(rbuf, decrypt_ctx,tempdata.length)
//            //let x = tag+1
//            if ret != 0  {
//                //AxLogger.log("\(cIDString) ss_decrypt error ",level: .Error)
//                //self.readDataWithTimeout(0.1, length: 2048, tag: x)
//                logStream.write("DNS decrypt error!")
//            }else {
//                let len = buffer_t_len(rbuf)
//                let result  = NSData.init(bytes: buffer_t_buffer(rbuf), length: len)
//                //AxLogger.log("\(cIDString) decrypt \(out)",level: .Debug)
//                //let type:SOCKS5HostType = .IPV4
//                data = result.subdataWithRange(NSMakeRange(7, result.length-7))
//            }
            //NSLog("dns packet 333")
        }else {
            
            data = tempdata
        }
        
       //AxLogger.log("\(data) from address \(address.subdataWithRange(r))",level: .Trace)
        if let data = data {
            //NSLog("udpSocket recv data:%@", data)
            writeDNSPacketData(data,cache: true)

        }else {
            AxLogger.log("DNS request error!",level: .Error)
            self.delegate!.serverDidClose(self)
        }
        
    }
     func writeDNSPacketData(data:NSData,cache:Bool){
        //NSLog("dns packet %@", data)
        
        let  srcip:UInt32 = inet_addr(proxyIpAddr.cStringUsingEncoding(NSUTF8StringEncoding)!) //0xc0a800f5//0b01 // 00f5
        let dstip:UInt32 = inet_addr(tunIP.cStringUsingEncoding(NSUTF8StringEncoding)!)//= 0xc0a80202
        
        let h = ipHeader(20+data.length+8, srcip ,dstip,queryIDCounter.bigEndian,UInt8(IPPROTO_UDP))
        queryIDCounter += 1
        //NSLog("DNS 111")
        var  packet:DNSPacket
        if let cacheData = cacheData {
            
            cacheData.appendData(data)
            packet = DNSPacket.init(data: cacheData)
        }else {
            packet = DNSPacket.init(data: data)
        }
        //NSLog("DNS 222")
        let inden = packet.identifier
        if packet.finished == false {
            if let c = cacheData {
                c.appendData(data)
            }else {
                cacheData = NSMutableData.init(data: data)
            }
            
        }else {
            AxLogger.log("DNSFORWARDER  \(packet.queryDomains.first!) Finished",level: .Debug)
            if let rData = waittingQueriesTimeMap[inden]{
                waittingQueriesTimeMap.removeValueForKey(inden)
                let now = NSDate()
                let second = now.timeIntervalSinceDate(rData)
                // debugLog("DNS Response Fin" + packet.queryDomains.first!)
                let message = String.init(format:"DNS Response Fin %@ use %.2f second",packet.queryDomains.first!, second)
                AxLogger.log(message,level: .Trace)
            }
            
            //NSLog("DNS %@",packet.queryDomains)
            //AxLogger.log("domains answer:\(packet.queryDomains) iden :\(inden) clientPort:\(cPort) use second:\(second)",level: .Debug)
            //        waittingQueriesTimeMap.removeValueForKey(inden)
            waittingQueriesMap.removeValueForKey(Int(inden))
            cacheData?.length = 0
            
           // NSLog("DNS Response Fin %@", packet.queryDomains.first!,packet.answerDomains)
           
        }
        
        
        
        
        
        
        let d = NSMutableData()
        d.appendData(h)
        //可能经过代理
        let sport:UInt16 = 53
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
            delegate.serverDidQuery(self, data: d,close:  packet.finished)
        }
    }
    public func udpSocket(sock: GCDAsyncUdpSocket, didNotConnect error: NSError){
       //NSLog("DNS didNotConnect: \(error)")
        if let p = proxy {
            let message = String.init(format: "#### %@:%d didNotConnect", p.serverAddress,p.serverPort)
            
            p.udpRelay = false
            AxLogger.log("####  \(p.serverAddress):\(p.serverPort) UDP RELAY Error \(message)",level: .Error)
        }
       
            dispatch_async(dispatch_get_main_queue(), { 
                 if let d  = self.delegate {
                    d.serverDidClose(self)
                }
            })
            
        
       
    }
    public func udpSocket(sock: GCDAsyncUdpSocket, didSendDataWithTag tag: Int){
       //NSLog("DNS didSendDataWithTag")
    }
    public func udpSocketDidClose(sock: GCDAsyncUdpSocket, withError error: NSError){
       //NSLog("DNS udpSocketDidClose \(error)")
        //socket?.setDelegate( nil)
        
        //socket = nil
        //self.start()
        if let d = delegate {
            d.serverDidClose(self)
        }
        
    }
    public func udpSocket(sock: GCDAsyncUdpSocket, didNotSendDataWithTag tag: Int, dueToError error: NSError){
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
        if let _ = proxy {
//            bfree(sbuf)
//            sbuf.dealloc(1)
//            bfree(rbuf)
//            rbuf.dealloc(1)
//            free_enc_ctx(encrypt_ctx)
//            free_enc_ctx(decrypt_ctx)
        }
        if let s = socket {
            s.setDelegate( nil)
            
            //s = nil
        }
        AxLogger.log("DNS-Server deinit",level: .Debug)
    }
    
}
