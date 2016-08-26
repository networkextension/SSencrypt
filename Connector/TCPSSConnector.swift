//
//  TCPSSConnector.swift
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


#if os(OSX)
//iOS 不需要这个代码，先留着
func settingSS(passwd:String,method:String) ->Int32 {
    if SFSettingModule.setting.method == -1 {
        
        let md = passwd.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        let mm = method.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        guard let pptr = md, mptr = mm else { return -1}
       
        //let pptr : UnsafeMutablePointer<Int8> = UnsafeMutablePointer.init(passwd.cStringUsingEncoding(NSUTF8StringEncoding)!)
        //let mptr : UnsafeMutablePointer<Int8> = UnsafeMutablePointer.init(method.cStringUsingEncoding(NSUTF8StringEncoding)!)
       
        //guard let pd = md, xd = mm else { return -1}
        SFSettingModule.setting.method = enc_init(UnsafePointer(pptr.bytes), UnsafePointer(mptr.bytes),pptr.length,mptr.length  )
    }
    return SFSettingModule.setting.method
    
}
#endif
let  ONETIMEAUTH_FLAG:CChar = 0x10
public class  TCPSSConnector:ProxyConnector{
    //config_encryption(password, method);
    
    //var
    var aes:SSEncrypt?
    var ota:Bool = false
    var headSent:Bool = false
    //var auth:Bool = false
    func config() -> Bool{
        
        let password = proxy.password
        
        aes = SSEncrypt.init(password: password, method: proxy.method)
        
        return true
    }
    deinit {
        
        //maybe crash
        
    }


    func buildHead() ->NSData {
        let header = NSMutableData()
        //NSLog("TCPSS %@:%d",targetHost,targetPort)
        //targetHost is ip or domain
        var addr_len = 0
        
//        let  buf:bufferRef = bufferRef.alloc(1)
//        balloc(buf,BUF_SIZE)
        let  request_atyp:SOCKS5HostType = validateIpAddr(targetHost)
        var atype:CChar = SOCKS_IPV4
        if  request_atyp  == .IPV4{
           
            header.write(SOCKS_IPV4)
            addr_len += 1
           //AxLogger.log("\(cIDString) target host use ip \(targetHost) ",level: .Debug)
            let i :UInt32 = inet_addr(targetHost.cStringUsingEncoding(NSUTF8StringEncoding)!)
            header.write(i)
            header.write(targetPort.byteSwapped)
            addr_len  +=  sizeof(UInt32) + 2
            
        }else if request_atyp == .DOMAIN{
            atype = SOCKS_DOMAIN
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
            atype = SOCKS_IPV6
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
        if ota {
            atype |= ONETIMEAUTH_FLAG
            header.replaceBytesInRange(NSMakeRange(0, 1), withBytes: &atype, length: 1)
            let hash = aes!.ss_onetimeauth(header)
            header.appendData(hash)
        }
        return header

        
    }
    
    public override func socket(sock: GCDAsyncSocket, didConnectToHost host: String!, port: UInt16){
        
       let message = String.init(format: "\(targetHost):\(targetPort) UP \(host):\(port)")
        isConnected = true
        remoteIPaddress = host
        AxLogger.log(message,level:.Debug)
        if let d = delegate {
            d.connectorDidBecomeAvailable(self)
        }
        
        //        for (index ,packet) in packets.enumerate() {
        //           //AxLogger.log("writeData \(packet)")
        //            socket?.writeData(packet, withTimeout: 10, tag: 0)
        //            packets.removeAtIndex(index)
        //        }
    }
  
    public override func socket(sock: GCDAsyncSocket, didReadData data: NSData, withTag tag: Int) {
       //AxLogger.log("\(cIDString) didReadData \(data.length) \(tag)",level: .Trace)
        //receivedData = data
        //NSLog("TCSS read data len:%d",data.length)
        if data.length > 0 {
        
            //receivedData.appendData(data)
            //AxLogger.log("\(cIDString) buffer \(data)",level: .Trace)
//            let recvb:bufferRef = bufferRef.alloc(1)
//            balloc(recvb,receivedData.length)
            if let engine = aes {
                if let cipher = engine.decrypt(data){
                    if let d = delegate {
                        //debugLog("recv:\(cipher)")
                        d.connector(self, didReadData: cipher, withTag: Int64(tag))
                    }else {
                        AxLogger.log("\(cIDString) didReadData Connection deal drop data ",level: .Warning)
                    }
                }else {
                    AxLogger.log("\(cIDString) SS Decrypt Error ",level: .Error)
                }

            }else {
                AxLogger.log("\(cIDString) SS engine not setup Error ",level: .Error)
            }
        }
        
        //socket?.readDataWithTimeout(0.5, tag: self.tag++)
    }
//    public override func socket(sock: GCDAsyncSocket!, didReadPartialDataOfLength partialLength: UInt, tag: Int){
//       //AxLogger.log("\(cIDString) didReadPartialDataOfLength",level: .Warning)
//        if let d = delegate {
//            d.connector(self, didReadData: self.receivedData, withTag: Int64( tag))
//        }
//        
//    }
    public override func socket(sock: GCDAsyncSocket, didWriteDataWithTag tag: Int){
       //AxLogger.log("\(cIDString) didWriteDataWithTag   \(tag)",level:.Warning)
        //NSLog("TCPSS didwrite tag %d",tag )
        socks_writing = false
        if let d = delegate {
            d.connector(self, didWriteDataWithTag: Int64(tag))
        }else {
            //NSLog("TCPSS delegate invalid %d",tag )
        }
        
    }
    public func beginRead(){
        socket?.readDataWithTimeout(socketReadTimeout, tag: 0)
    }
//    public override func readDataWithTimeout(timeout :Double ,length:UInt32,  tag  :CLong){
//        //        guard let buffer = self.receivedData else{
//        //           //AxLogger.log("read error withtag   \(tag) \(length)")
//        //            return;
//        //        }
//        //
//        //socket?.readDataToLength(length: length , timeout : timeout, tag: tag)
//        // socket?.readDataToLength(UInt( length), withTimeout: timeout, tag: CLong(tag))
//        
//        socket?.readDataWithTimeout(timeout, buffer: nil, bufferOffset: 0, maxLength: UInt(length) , tag: tag)
//        
//    }
    public func socket(sock: GCDAsyncSocket!, didWritePartialDataOfLength partialLength: UInt, tag: Int){
       //AxLogger.log("\(cIDString) didWritePartialDataOfLength \(partialLength) \(tag)",level:.Trace)
    }
//    public override func socket(sock: GCDAsyncSocket!, shouldTimeoutReadWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval{
//       //AxLogger.log("\(cIDString) shouldTimeoutReadWithTag ", level:.Warning)
//        return 10
//    }
//    public override func socket(sock: GCDAsyncSocket!, shouldTimeoutWriteWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval{
//       //AxLogger.log("\(cIDString) shouldTimeoutWriteWithTag ", level:.Warning)
//        return 10
//    }
    public func socketDidCloseReadStream(sock: GCDAsyncSocket!){
        
        let e = NSError(domain:errDomain , code: 0,userInfo:["reason":"socketDidCloseReadStream"])
       AxLogger.log("\(cIDString) socketDidCloseReadStream \(e.localizedDescription)", level:.Warning)
        if let d = delegate {
            //self.socket = nil
            d.connectorDidDisconnect(self, withError: e)
        }
        
        
    }
//    public override func socketDidDisconnect(sock: GCDAsyncSocket!, withError err: NSError!){
//       //AxLogger.log("\(cIDString) socketDidDisconnect,err: \(err)",level:  .Error)
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
//        
//    }

    public override func start() {
        ota = proxy.tlsEnable
        
        //proxy.tlsEnable supper class use tlsSuport 判断是非要TLS
        //AxLogger.log("\(ota) \(proxy.tlsEnable)")
        super.start()
    }
//    public func test_encryptor(buffer:NSData)  {
//        //let tmp = NSData.init(data: buffer)
//        
//        print(buffer)
//        let sendb:bufferRef = bufferRef.alloc(1)
//        balloc(sendb,2048)
//        buffer_t_copy(sendb,UnsafePointer(buffer.bytes),buffer.length)
//        var ret = ss_encrypt(sendb,encrypt_ctx,buffer.length)
//        if ret != 0 {
//            //abort()
//           //AxLogger.log("\(cIDString) ss_encrypt error ",level: .Error)
//        }
//        var  len = buffer_t_len(sendb)
//        
//        let recvb:bufferRef = bufferRef.alloc(1)
//        balloc(recvb,2048)
//        buffer_t_copy(recvb,buffer_t_buffer(sendb),len)
//        ret = ss_decrypt(recvb,decrypt_ctx,len)
//        if ret != 0 {
//            //abort()
//           //AxLogger.log("\(cIDString) ss_decrypt error ",level: .Error)
//        }
//        len = buffer_t_len(recvb)
//        let out = NSData.init(bytesNoCopy:buffer_t_buffer(recvb) , length: len, freeWhenDone: false);
//        print(out)
//        sendb.dealloc(1)
//        recvb.dealloc(1)
//    }
    public override func writeData(d:NSData, timeout:Double, tag:Int64){
        //
        
        //AxLogger.log("writedata \(d)",level: .Trace)
        if isConnected == true {
            
            //test_encryptor(buffer)
            var data:NSData?
            if !headSent {
                let temp = NSMutableData()
                let head = buildHead()
                temp.appendData(head)
                headSent = true
                if ota {
                    let chunk = aes!.ss_gen_hash(d, counter: Int32(tag))
                    temp.appendData(chunk)
                    temp.appendData(d)
                }else {
                    temp.appendData(d)
                }
                
                
                
                
                
                data = temp
               //AxLogger.log("\(cIDString) will send \(head.length) \(head) ",level: .Trace)
            }else {
                if ota {
                    
                    let chunk = aes!.ss_gen_hash(d, counter: Int32(tag))
                    let temp = NSMutableData.init(data: chunk)
                    temp.appendData(d)
                    data = temp
                }else {
                    data = d
                }
                
            }
           //AxLogger.log("\(cIDString) will send \(d.length)  ",level: .Trace)
            
            if let dd = data ,e = aes{
                if let cipher =  e.encrypt(dd) {
                    socks_writing = true
//                    debugLog("org \(d)")
//                    debugLog("en \(dd)")
//                    debugLog("en \(cipher)")
//                    let dx = aes!.decrypt(cipher)
//                    debugLog("de \(dx)")
//                    if dx!.isEqualToData(dd){
//                        debugLog("engine on")
//                    }
                    socket?.writeData(cipher, withTimeout: timeout, tag: Int(tag))
                    
                    
                }
            }else {
                AxLogger.log("encrypt init error or data length 0",level: .Error)
            }
            
            
            
            
        }else{
            //packets.append(d);
           //AxLogger.log("\(cIDString) packets.append",level:.Trace)
        }
        
    }
    
    static func connectorWithSelectorPolicy(selectorPolicy:SFPolicy ,targetHostname hostname:String, targetPort port:UInt16,p:SFProxy) ->TCPSSConnector{
        let c:TCPSSConnector = TCPSSConnector(spolicy: selectorPolicy, p: p)
        //c.manager = man
        //c.policy = selectorPolicy
        //TCPSSConnector.swift.[363]:12484608:12124160:360448:Bytes
        c.cIDFunc()
        c.targetHost = hostname
        c.targetPort = port
        
        //c.start()
        return c
    }

}

