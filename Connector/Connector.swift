//
//  Connector.swift
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


let GCDMutilSocketQueue = false //理论没问题，就是内存受不了
var SFConnectorID:Int = 0
@objc public protocol ConnectorDelegate{
    
    func connector(connector:Connector , didReadData  data:NSData ,withTag tag:Int64) ->Void
    func connectorDidDisconnect(connector:Connector ,withError:NSError)
    func connector(connector:Connector , didWriteDataWithTag  tag:Int64) ->Void
    func connectorDidSetupFailed(connector:Connector, withError:NSError)
    func connectorDidBecomeAvailable(connector:Connector)
    func connector(connector:Connector,shouldTimeoutReadWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval
}
public class Connector:NSObject,GCDAsyncSocketDelegate {
    weak var delegate:ConnectorDelegate?
    var mode:SFConnectionMode = .TCP
    var targetHost:String = ""
    var targetPort:UInt16 = 0
    var remoteIPaddress:String = ""
    var socket:GCDAsyncSocket?
    var socks_reading = false
    var socks_writing  = false
    var socket_Queue:dispatch_queue_t?
    var connectTime:Int = 0
    //weak var manager:ConnectorDispatchQueueProvider?
    var initialized:Bool?
    var retry:Int?
    func interfaceAddr() ->String?{
        if let socket = socket {
            let ipaddress = socket.localHost
            return ipaddress
            
        }
        return nil
    }
    var shoudClose = false
    var policy:SFPolicy = .Direct
    
    var cID:Int = 0
    var cIDString = ""
    var isConnected:Bool = false
    var isDisconnected:Bool = true
    func socketQueue () -> dispatch_queue_t?{
        //return dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0)
        if GCDMutilSocketQueue {
            if socket_Queue == nil {
                socket_Queue = dispatch_queue_create("com.yarshure.socketqueue_\(self.cID)", DISPATCH_QUEUE_SERIAL)
            }
           return socket_Queue!
        }else {
            let q = SFTCPConnectionManager.shared().dispatchQueue
            //guard let m = manager else {fatalError()}
            return q//m.socketQueue()
        }
        //return nil
    }
    public override init() {
        SFConnectorID += 1
        cID = SFConnectorID
        super.init()
    }
    public init(policy:String){
        
       SFConnectorID += 1
       
        cID = SFConnectorID
        super.init()
    }
    func cIDFunc(){
        cIDString = "[" + objectClassString(self) + "-\(cID)" + "]" //self.classSFName()
    }
    func socketDead() ->Bool {
        if socket != nil {
            return false
        }
        return true
    }
    deinit{
        
        //dispatch_release(socket_Queue!)
        if delegate != nil {
            delegate = nil
        }
        if let s =  socket {
            s.synchronouslySetDelegate(nil)
            //socket = nil
//            if !isDisconnected {
//                if s.isDisconnected {
//                    s.disconnect()
//                }
//            }
            
            AxLogger.log("\(cIDString) deinit socket not nil",level: .Debug)
        }
//        if let s = socket {
//            s.delegate = nil
//            if isDisconnected() {
//                //AxLogger.log("socket shoud disconnect",level: .Debug)
//                
//                //socket = nil
//            }else if isConnected() {
//                s.disconnect()
//                //s.disconnectAfterReadingAndWriting()
//                //socket = nil
//                
//            }
//        }
       //AxLogger.log("[Connector-\(cID)] deinit",level:  .Debug)
        
    }
//    static func connectorWithSelectorPolicy(selectorPolicy:SFPolicy ,targetHostname hostname:String, targetPort port:UInt16) ->Connector{
//        
//        
//        let c:Connector = Connector(p: selectorPolicy)
//        //c.manager = man
//        c.targetHost = hostname
//        c.targetPort = port
//        
//        return c
//    }

    public func disconnectWithError(error:NSError){
        
        
        
//        let q = SFTCPConnectionManager.shared().socketQueue
//        dispatch_sync(q) { [weak self]  in
//            if let strongSelf = self {
//            }
//            
//        }
        AxLogger.log("\(targetHost)\(targetPort) closing",level: .Verbose)
        shoudClose = true
        
            if let s = socket {
                //s.synchronouslySetDelegate(nil)
                //如果有callback 怎么办?
                
                if isDisconnected {
                    //AxLogger.log("socket shoud disconnect",level: .Debug)
                    //s.disconnect()
                    isDisconnected = true
                    //socket = nil
                    AxLogger.log("\(cIDString) isDisconnected Connector: disconnectWithError " + error.localizedDescription,level: .Verbose)
                }else if isConnected {
                    AxLogger.log("\(cIDString) isConnected Connector: disconnectWithError " + error.description,level: .Verbose)
                    s.disconnect()
                    //socket = nil
                    
                }
            }
        
        
//
//        if isConnected() {
//            if let s = socket {
//                s.delegate = nil
//                s.disconnect()
//                socket = nil
//            }
//            
//        }else {
//            socket?.disconnect()
//            if let delegate = delegate {
//                //delegate.connectorDidDisconnect(self, withError: error)
//            }
//        }

//        
//        if let delegate = delegate {
//            delegate.connectorDidDisconnect(self, withError: error)
//            self.delegate = nil
//            self.manager = nil
//        }
//        
    }
    public func socketDidDisconnect(sock: GCDAsyncSocket, withError err: NSError?){
        var e:NSError
        if let _ = err {
            e = NSError(domain:errDomain , code: err!.code,userInfo: err!.userInfo)
        }else{
            e = NSError(domain:errDomain , code: 0,userInfo: ["info":"debug"])
        }
        isDisconnected = true
        

        AxLogger.log("\(cIDString) socket closed:\((e.localizedDescription)) \(targetHost):\(targetPort)",level: .Warning)

        if let d = delegate{
            
            d.connectorDidDisconnect(self, withError: e)
            //socket = nil
        }
    }
    public func writeData(d:NSData, timeout:Double, tag:Int64){
        //
        
//        if targetPort == 80 {
//            let debug = NSString.init(data: d, encoding: NSUTF8StringEncoding) as! String
//           //AxLogger.log("\(cIDString) writeData \(debug)",level: .Debug)
//        }
        if isConnected == true {
            socks_writing = true
            socket?.writeData(d, withTimeout: timeout, tag: Int(tag))
            
        }
        
    }
    public func socket(sock: GCDAsyncSocket, didWriteDataWithTag tag: Int){
        socks_writing = false
    }
    public func socket(sock: GCDAsyncSocket, didReadData data: NSData, withTag tag: Int) {
        
    }
    public func start(){
    
    }
    public  func readDataWithTimeout(timeout :Double ,length:UInt,  tag  :CLong){
        //        guard let buffer = self.receivedData else{
        //           //AxLogger.log("read error withtag   \(tag) \(length)")
        //            return;
        //        }
        //
        //socket?.readDataToLength(length: length , timeout : timeout, tag: tag)
        // socket?.readDataToLength(UInt( length), withTimeout: timeout, tag: CLong(tag))
//        if receivedData.length > 0 {
//            receivedData = NSMutableData.init(length: BUF_SIZE)!
//        }
//        if let tempBuffer  = NSMutableData.init(capacity: BUF_SIZE){
//            socket?.readDataWithTimeout(timeout, buffer: tempBuffer, bufferOffset: 0, maxLength: UInt(length) , tag: tag)
//        }else {
//            fatalError()
//        }
        
       // socket?.readDataWithTimeout(timeout, buffer: receivedData, bufferOffset: 0, maxLength: UInt(length) , tag: tag)
        //DLog("will read %d host:%@:%d",tag,targetHost,targetPort)
        socket?.readDataWithTimeout(timeout, buffer: nil, bufferOffset: 0, maxLength: length , tag: tag)
        //socket?.readDataWithTimeou
        
    }
    
    public  func socket(sock: GCDAsyncSocket, didConnectToHost host: String, port: UInt16){
        
       //AxLogger.log("\(cIDString) \(targetHost):\(targetPort) didConnectToHost \(host) and port \(port)",level:.Info)
        isConnected = true
        sock.userData = cIDString
        remoteIPaddress = host
        if let delegate = delegate {
            delegate.connectorDidBecomeAvailable(self)
        }
        
    }
//    public func socket(sock: GCDAsyncSocket!, didReadPartialDataOfLength partialLength: UInt, tag: Int){
//       //AxLogger.log("\(cIDString)  didReadPartialDataOfLength",level:.Error)
//        if let delegate = delegate {
//            delegate.connector(self, didReadData: self.receivedData, withTag: Int64( tag))
//        }
//    }
    public func readDataToLength(length: UInt, withTimeout timeout: NSTimeInterval, tag: Int){
        socket?.readDataToLength(length, withTimeout: timeout, tag: tag)
    }
    public  func socket(sock: GCDAsyncSocket, shouldTimeoutReadWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval{
        //AxLogger.log("\(cIDString) shouldTimeoutReadWithTag \(elapsed) \(length) tag:\(tag)", level:.Warning)
        
        if let d = delegate {
            return d.connector(self, shouldTimeoutReadWithTag: tag, elapsed: elapsed, bytesDone: length)
        }
        
        return 0.0
    }
    public  func socket(sock: GCDAsyncSocket, shouldTimeoutWriteWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval{
       //AxLogger.log("\(cIDString) shouldTimeoutWriteWithTag \(elapsed) \(length)", level:.Warning)
//        if elapsed > TCP_TimeOut {
//            return 0
//        }
        return AsyncSocketWriteTimeOut
    }
    
}

