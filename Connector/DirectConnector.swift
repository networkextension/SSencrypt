//
//  DirectConnector.swift
//  Surf
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


public class DirectConnector:Connector{
    var interfaceName:String?
    
    //var ipAddress:String?
    
    public override func socket(sock: GCDAsyncSocket, didReadData data: NSData, withTag tag: Int) {
        
        //receivedData = data
        if data.length > 0 {
//            if targetPort == 80 {
//                let debug = NSString.init(data: data, encoding: NSUTF8StringEncoding)
//                if debug != nil {
//                   //AxLogger.log("readData \(debug)")
//                }
//                
//            }
            if let d = delegate {
               //AxLogger.log("\(cIDString) didReadData \(data.length) \(tag)",level: .Debug)
                d.connector(self, didReadData: data, withTag: Int64(tag))
            }
            
        }
        
        
    }
    
    public override func socket(sock: GCDAsyncSocket, didWriteDataWithTag tag: Int){
        socks_writing = false
       //AxLogger.log("\(cIDString) didWriteDataWithTag   \(tag)", level: .Debug)
        if let d = delegate {
            d.connector(self, didWriteDataWithTag: Int64(tag))
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
//        socket?.readDataWithTimeout(timeout, buffer: nil, bufferOffset: 0, maxLength: UInt(length) , tag: tag)
//        
//    }
    public func socket(sock: GCDAsyncSocket!, didWritePartialDataOfLength partialLength: UInt, tag: Int){
       //AxLogger.log("\(cIDString) didWritePartialDataOfLength \(partialLength) \(tag)",level:.Trace)
    }
//    public func socket(sock: GCDAsyncSocket!, shouldTimeoutReadWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval{
//       //AxLogger.log("\(cIDString) shouldTimeoutReadWithTag ")
//        return 3
//    }
//    public func socket(sock: GCDAsyncSocket!, shouldTimeoutWriteWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval{
//       //AxLogger.log("\(cIDString) shouldTimeoutWriteWithTag ")
//        return 0.1
//    }
    public func socketDidCloseReadStream(sock: GCDAsyncSocket!){
        
        let e = NSError(domain:errDomain , code: 0,userInfo:["reason":"socketDidCloseReadStream"])
       //AxLogger.log("\(cIDString) socketDidCloseReadStream \(e)",level:.Error)
        isDisconnected = true
        if let d = delegate {
            //socket = nil
            d.connectorDidDisconnect(self, withError: e)
        }
        
    }
    public override func socketDidDisconnect(sock: GCDAsyncSocket, withError err: NSError!){
        //AxLogger.log("\(cIDString) socketDidDisconnect,err: \(err)",level:.Error)
        isDisconnected = true
        var e:NSError
        if let _ = err {
            e = NSError(domain:errDomain , code: err.code,userInfo: err.userInfo)
        }else{
            e = NSError(domain:errDomain , code: 0,userInfo: ["info":"socketDidDisconnect"])
        }
        if let d = delegate {
            //socket = nil
            d.connectorDidDisconnect(self, withError: e)
        }
        
        
    }
    public override func start() {
        let q = SFTCPConnectionManager.shared().dispatchQueue
        socket = GCDAsyncSocket.init(delegate: self, delegateQueue: q, socketQueue:  self.socketQueue())
        guard let s = socket else{
            return
        }
        s.userData = cIDString
        let message = String.init(format: "URL:%@:%d connect", targetHost, targetPort)
       
        AxLogger.log("\(cIDString) connectToHost now \(message)",level:.Debug)
        do {
           
            try s.connectToHost(targetHost, onPort: UInt16(targetPort))
            
        } catch {
           //AxLogger.log("\(cIDString) connectToHost error",level:.Error)
            let e = NSError(domain:errDomain , code: -1, userInfo: ["reason": "connectToHost error"])
            if let d = delegate {
                d.connectorDidSetupFailed(self, withError: e)
            }
            let message = String.init(format: "URL:%@:%d connect failure  %@", targetHost, targetPort,e.description)
             AxLogger.log(message,level:.Debug)
        }
       //AxLogger.log("\(cIDString) connectToHost \(targetHost) \(targetPort)",level:.Info)
        return
    }
    
    
    
    static func connectorWithSelectorPolicy(selectorPolicy:SFPolicy ,targetHostname hostname:String, targetPort port:UInt16) ->DirectConnector{
        let c:DirectConnector = DirectConnector(policy: "Direct")
        //c.manager = man
        c.cIDFunc()
        c.targetHost = hostname
        c.targetPort = port
        //c.start()
        c.cIDFunc()
        return c
    }
    //public func
}


