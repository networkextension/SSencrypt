//
//  ProxyConnectorSOCKS5.swift
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





public enum SFSocks5Stage:Int8,CustomStringConvertible{
    case Auth = 0
    case AuthSend = 2
    case Bind = 1
    case Connected = 5
    public var description: String {
        switch self {
        case Auth :return "Auth"
        case AuthSend: return "AuthSend"
        case Bind: return "Bind"
        case Connected: return "Connected"
        }
    }
}

//
//
// 050000010000000001BB

public class Socks5Connector:ProxyConnector{
    var host:String?
    var port:UInt16 = 0
    var stage:SFSocks5Stage = .Auth
    var recvBuffer:NSMutableData?
    static func connectorWithSelectorPolicy(selectorPolicy:SFPolicy ,targetHostname hostname:String, targetPort port:UInt16,p:SFProxy) ->Socks5Connector{
        let c:Socks5Connector = Socks5Connector(spolicy: selectorPolicy, p: p)
        //c.manager = man
        
        c.targetHost = hostname
        c.targetPort = port
        c.cIDFunc()
        //c.start()
        return c
    }
    func sendAuth(){
        let buffer = NSMutableData() //req 050100
        buffer.write(SOCKS_VERSION)
        if proxy.method.isEmpty && proxy.password.isEmpty {
            let authCount:CChar = 0x01 //支持认证
            buffer.write(authCount)
            let auth:CChar = 0x00
            buffer.write(auth)
        }else {
            let authCount:CChar = 0x02 //支持认证
            buffer.write(authCount)
            let auth:CChar = 0x00
            buffer.write(auth)
            let authup:CChar = 0x02
            buffer.write(authup)

        }
        
       //AxLogger.log("\(cIDString) send  .Auth req \(buffer)",level:.Trace)
        self.writeData(buffer, timemout: 3, tag: 0)
    }
    func sendUserAndPassword(){
        let buffer = NSMutableData()
        //buffer.write(SOCKS_VERSION)
        let auth:CChar = 0x01
        buffer.write(auth) //auth version
        var len:UInt8 = UInt8(proxy.method.characters.count)
        buffer.write(len)
        buffer.write(proxy.method)
        len = UInt8(proxy.password.characters.count)
        buffer.write(len)
        buffer.write(proxy.password)
        
        self.writeData(buffer, timemout: 3, tag: 0)
        
    }
    func sendBind(){
        //req 050100030F6170692E747769747465722E636F6D01BB
        let buffer = NSMutableData() //req 050100
        buffer.write(SOCKS_VERSION)
        let connect:CChar = 0x01
        buffer.write(connect)
        
        let reserved:CChar = 0x00
        buffer.write(reserved)
        let  request_atyp:SOCKS5HostType = validateIpAddr(targetHost)
        if  request_atyp == .IPV4{
            //ip
            
            buffer.write(SOCKS_IPV4)
            let i :UInt32 = inet_addr(targetHost.cStringUsingEncoding(NSUTF8StringEncoding)!)
            buffer.write(i)
            buffer.write(targetPort.byteSwapped)
        }else if request_atyp == .DOMAIN {
            //domain name
            
            buffer.write(SOCKS_DOMAIN)
            let name_len = targetHost.characters.count
            buffer.write(UInt8(name_len))
            buffer.write(targetHost)
            buffer.write(targetPort.byteSwapped)
        }else  if request_atyp == .IPV6 {
            buffer.write(SOCKS_IPV6)
            if let data =  toIPv6Addr(targetHost) {
                
             
               //AxLogger.log("\(cIDString) convert \(targetHost) to Data:\(data)",level: .Info)
                buffer.write(data)
                buffer.write(targetPort.byteSwapped)
            }else {
               //AxLogger.log("\(cIDString) convert \(targetHost) to in6_addr error )",level: .Warning)
                return
            }
            
        }
    
       //AxLogger.log("\(cIDString) send  .Bind req \(buffer)",level: .Trace)
        self.writeData(buffer, timemout: 3, tag: 0)
    }
    public override func socket(sock: GCDAsyncSocket!, didConnectToHost host: String!, port: UInt16){
       //AxLogger.log("\(cIDString) \(targetHost):\(targetPort) didConnectToHost \(host) and port \(port) via:\(proxy.serverAddress):\(proxy.serverPort)",level:.Info)
        remoteIPaddress = host
        isConnected = true
        if stage == .Auth {
           //AxLogger.log("\(cIDString) send  .Auth req",level: .Trace)
            sendAuth()
        }
    }
    public override func socket(sock: GCDAsyncSocket, didReadData data: NSData, withTag tag: Int) {
        if stage == .Auth {
            //ans 0500
            if recvBuffer == nil {
                recvBuffer = NSMutableData()
            }
            recvBuffer?.appendData(data)
           //AxLogger.log("\(cIDString)  .Auth  respon buf \(recvBuffer)",level: .Trace)
            guard var buffer = recvBuffer else {return }
            let version : UnsafeMutablePointer<Int8> =  UnsafeMutablePointer<Int8>.alloc(1)
            buffer.getBytes(version, length: 1)
            
            let auth : UnsafeMutablePointer<UInt8> =  UnsafeMutablePointer<UInt8>.alloc(1)
            buffer.getBytes(auth, range: NSMakeRange(1,1))
            if version.memory == SOCKS_VERSION {
                
                //buffer
                if auth.memory == 0x00 {
                    //no auth
                    if buffer.length > 2 {
                        buffer = NSMutableData.init(data: buffer.subdataWithRange(NSMakeRange(2, buffer.length-2)))
                    }else {
                        recvBuffer = NSMutableData()
                    }
                    stage = .Bind
                   //AxLogger.log("\(cIDString) recv .Auth respon and send Bind req",level: .Debug)
                    sendBind()
                }else if auth.memory == 0x02 {
                    //user/password auth
                    if buffer.length > 2 {
                        buffer = NSMutableData.init(data: buffer.subdataWithRange(NSMakeRange(2, buffer.length-2)))
                    }else {
                        recvBuffer = NSMutableData()
                    }
                    stage = .AuthSend
                    sendUserAndPassword()
                }else if auth.memory == 0xff {
                   //AxLogger.log("\(cIDString) don't have auth type, need close",level: .Error)
                    sock.disconnect()
                } else {
                   //AxLogger.log("\(cIDString) auth type:\(auth.memory) don't support, need close",level: .Error)
                    sock.disconnect()
                }
                
            }else {
               //AxLogger.log("\(cIDString) don't recv  respon ver error ver:\(version.memory)",level: .Debug)
            }
            version.dealloc(1)
            auth.dealloc(1)
        }else if stage == .AuthSend {
            if recvBuffer == nil {
                recvBuffer = NSMutableData()
            }
            recvBuffer?.appendData(data)
           //AxLogger.log("\(cIDString)  .AuthSend   respon buf \(recvBuffer)",level: .Debug)
            guard var buffer = recvBuffer else {return }
            let version : UnsafeMutablePointer<Int8> =  UnsafeMutablePointer<Int8>.alloc(1)
            buffer.getBytes(version, length: 1)
            
            let result : UnsafeMutablePointer<Int8> =  UnsafeMutablePointer<Int8>.alloc(1)
            buffer.getBytes(result, range: NSMakeRange(1,1))
            if version.memory == SOCKS_AUTH_VERSION && result.memory == SOCKS_AUTH_SUCCESS {
                if buffer.length > 2 {
                    buffer = NSMutableData.init(data: buffer.subdataWithRange(NSMakeRange(2, buffer.length-2)))
                }else {
                    recvBuffer = NSMutableData()
                }
               //AxLogger.log("\(cIDString)  .Auth Success and send BIND CMD",level: .Warning)
                sendBind()
                stage = .Bind
            }else {
               //AxLogger.log("\(cIDString)  .Auth failure",level: .Warning)
                sock.disconnect()
            }
            version.dealloc(1)
            result.dealloc(1)
        }else if stage == .Bind {
            if recvBuffer == nil {
                recvBuffer = NSMutableData()
            }
            recvBuffer?.appendData(data)
           //AxLogger.log("\(cIDString)  .Bind  respon buf \(recvBuffer)",level: .Debug)
            //05000001 c0a80251 c4bf
            guard let buffer = recvBuffer else {return }
            let version : UnsafeMutablePointer<Int8> =  UnsafeMutablePointer<Int8>.alloc(1)
            buffer.getBytes(version, length: 1)
            
            let result : UnsafeMutablePointer<Int8> =  UnsafeMutablePointer<Int8>.alloc(1)
            buffer.getBytes(result, range: NSMakeRange(1,1))
            if version.memory == SOCKS_VERSION && result.memory == 0x00 {
                
                //buffer
                let reserved: UnsafeMutablePointer<Int8> =  UnsafeMutablePointer<Int8>.alloc(1)
                buffer.getBytes(reserved, range: NSMakeRange(2,1))
                
                let type: UnsafeMutablePointer<Int8> =  UnsafeMutablePointer<Int8>.alloc(1)
                 buffer.getBytes(type, range: NSMakeRange(3,1))
                if type.memory == 1 {
                    let ip: UnsafeMutablePointer<UInt32> =  UnsafeMutablePointer<UInt32>.alloc(1)
                    buffer.getBytes(ip, range: NSMakeRange(4,4))
                    
                    let port: UnsafeMutablePointer<UInt16> =  UnsafeMutablePointer<UInt16>.alloc(1)
                    buffer.getBytes(port, range: NSMakeRange(8,2))
                   //AxLogger.log("\(cIDString) Bind respond \(ip.memory):\(port.memory)",level: .Debug)
                    if buffer.length > 10  {
                        recvBuffer = NSMutableData.init(data: buffer.subdataWithRange(NSMakeRange(10, buffer.length-10)))
                    }else {
                        recvBuffer = nil
                    }
                    ip.dealloc(1)
                    port.dealloc(1)
                }else if type.memory == SOCKS_DOMAIN  {
                    let length: UnsafeMutablePointer<Int8> =  UnsafeMutablePointer<Int8>.alloc(1)
                    buffer.getBytes(length, range: NSMakeRange(4,1))
                    let domainname = buffer.subdataWithRange(NSMakeRange(5,Int(length.memory)))
                    let port: UnsafeMutablePointer<UInt16> =  UnsafeMutablePointer<UInt16>.alloc(1)
                    buffer.getBytes(port, range: NSMakeRange(5+Int(length.memory),2))
                   //AxLogger.log("\(cIDString) Bind respond domain name length:\(length.memory) \(domainname):\(port.memory)",level: .Debug)
                    let len = 5+Int(length.memory) + 2
                    if buffer.length >  len {
                        recvBuffer = NSMutableData.init(data: buffer.subdataWithRange(NSMakeRange(len, buffer.length-len)))
                    }else {
                        recvBuffer = nil
                    }
                    length.dealloc(1)
                    port.dealloc(1)
                }else if type.memory == SOCKS_IPV6 {
                    //AxLogger.log("\(cIDString) Bind respond ipv6 currnetly don't support",level:.Error)
                }
                
                stage = .Connected
               //AxLogger.log("\(cIDString) recv .Bind respon and Connected now \(recvBuffer)",level: .Debug)
                sock5connected()
                reserved.dealloc(1)
                type.dealloc(1)
            }else {
               //AxLogger.log("\(cIDString) don't recv .Bind respon",level: .Debug)
            }
            version.dealloc(1)
            result.dealloc(1)
        }else if stage == .Connected {
            if let buffer = recvBuffer  {
                buffer.appendData(data)
                if let d = delegate {
                    d.connector(self, didReadData: buffer, withTag: Int64(tag))
                }
                
                recvBuffer = nil
            }else {
                if let d = delegate {
                    d.connector(self, didReadData: data, withTag: Int64(tag))
                }
                
                
            }
        }
    }
    func sock5connected(){
        if let d = delegate {
            d.connectorDidBecomeAvailable(self)
        }
        
    }
//    public override func socket(sock: GCDAsyncSocket!, didReadPartialDataOfLength partialLength: UInt, tag: Int){
//        
//    }
    public override func socket(sock: GCDAsyncSocket, didWriteDataWithTag tag: Int){
        socks_writing = false
        if stage == .Connected {
           //AxLogger.log("\(cIDString) didWriteDataWithTag   \(tag)", level: .Debug)
            if let d = delegate {
                d.connector(self, didWriteDataWithTag: Int64(tag))
            }
            
        }else {
           
           //AxLogger.log("\(cIDString) socks5 handshaking \(tag)", level: .Debug)
            self.readDataWithTimeout(socketReadTimeout, length: CLIENT_SOCKS_RECV_BUF_SIZE_UInt, tag: 0)
        }
    }
//    public func socket(sock: GCDAsyncSocket!, didWritePartialDataOfLength partialLength: UInt, tag: Int){
//        
//    }
//    public override func socket(sock: GCDAsyncSocket!, shouldTimeoutReadWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval{
//        return 3
//    }
//  override   public func socket(sock: GCDAsyncSocket!, shouldTimeoutWriteWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval{
//        return 0.1
//    }
    public func socketDidCloseReadStream(sock: GCDAsyncSocket!){
        let e = NSError(domain:errDomain , code: 0,userInfo:["reason":"socketDidCloseReadStream"])
       //AxLogger.log("socketDidCloseReadStream \(e)",level:.Error);
        if let d = delegate {
           // self.socket = nil
            d.connectorDidDisconnect(self, withError: e)
        }
        
    }
//    public override func readDataWithTimeout(timeout :Double ,length:UInt32,  tag  :CLong){
//        //        guard let buffer = self.receivedData else{
//        //           //AxLogger.log("read error withtag   \(tag) \(length)")
//        //            return;
//        //        }
//        //
//        //socket?.readDataToLength(length: length , timeout : timeout, tag: tag)
//        // socket?.readDataToLength(UInt( length), withTimeout: timeout, tag: CLong(tag))
//        socket?.readDataWithTimeout(timeout, buffer: nil, bufferOffset: 0, maxLength: UInt(length) , tag: tag)
//        
//    }
//    public override func socketDidDisconnect(sock: GCDAsyncSocket!, withError err: NSError!){
//       //AxLogger.log("\(cIDString) socketDidDisconnect,err: \(err)",level:.Error)
//        var e:NSError
//        if let _ = err {
//            e = NSError(domain:errDomain , code: err.code,userInfo: err.userInfo)
//        }else{
//            e = NSError(domain:errDomain , code: 0,userInfo: ["info":"debug"])
//        }
//        if let d = delegate {
//            //self.socket = nil
//            d.connectorDidDisconnect(self, withError: e)
//        }
//        
//    }
    public override func start() {
        tlsSupport = proxy.tlsEnable
        super.start()
    }
    public func writeData(d:NSData ,timemout:Double ,tag:CLong){
        if isConnected == true {
            socks_writing = true
            socket?.writeData(d, withTimeout: timemout, tag: Int(tag))
        }else {
           //AxLogger.log("\(cIDString) socket don't ESTABLISH \(stage) ",level:.Error)
        }
    }
}
