//
//  DNSPacket.swift
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
import Darwin


public enum QTYPE:UInt16,CustomStringConvertible{
    case A = 0x0001
    case NS = 0x0002
    case CNAME = 0x005
    case SOA = 0x0006
    
    case WKS = 0x000B
    case PTR = 0x000C
    case MX = 0x000F
    case SRV = 0x0021

    case A6 = 0x0026
    case ANY = 0x00FF


    public var description: String {
        switch self {
        case A: return  "A"
        case NS : return "NS"
        case CNAME : return "CNAME"
        case SOA : return "SOA"
            
        case WKS : return "WKS"
        case PTR : return "PTR"
        case MX : return "MX"
        case SRV : return "SRV"
            
        case A6 : return  "A6"
        case ANY : return "ANY"
        }
    }
}


class DNSPacket: NSObject {
    var identifier:UInt16 = 0
    var queryDomains:[String] = []
    var answerDomains:[String:String] = [:]
    var rawData:NSData
    var qr:CChar = 0
    var count:UInt16 = 0
    var qType:UInt16 = 0
    var qClass:UInt16 = 0
    var reqCount:UInt16 = 0
    var answerCount:UInt16 = 0
    var ipString:[String] = []
    var finished:Bool = true
//    override init() {
//        
//    }


    init(data:NSData) {
        if data.length < 12 {
            
            AxLogger.log("DNS data error data",level: .Error)
        }
       
        rawData = data
        super.init()
        let bytes:UnsafePointer<UInt16> =  UnsafePointer<UInt16>.init(rawData.bytes)
        var p:UnsafePointer<UInt16> = bytes
        identifier = bytes.memory
        p = bytes + 1
        let op = p.memory.bigEndian
        //print("#######################")
        qr = CChar(op >> 15)
        if qr == 0{
            //NSLog("#######################DNS req")
        }else {
            let c = p.memory.bigEndian & 0x000F
            if c == 0 {
                //NSLog("#######################DNS resp OK")
            }else {
                //NSLog("#######################DNS resp err:\(c)")
            }
            
            
        }
        
        p = p + 1
        reqCount = p.memory.bigEndian
        p = p + 1
        answerCount = p.memory.bigEndian
        p = p + 1
        
        p += 2 
        var ptr:UnsafePointer<UInt8> = UnsafePointer<UInt8>.init(p)
        if qr == 0 {
            count = reqCount
        }else {
            count = answerCount
        }
        let  endptr:UnsafePointer<UInt8> = ptr.advancedBy(rawData.length-6*2)
        for _ in 0..<reqCount {
            var domainString:String = ""
            var  domainLength = 0
            while (ptr.memory != 0x0) {
                let len = Int(ptr.memory)
                ptr = ptr.successor()
                
                if ptr.distanceTo(endptr) < len   {
                    AxLogger.log("DNS error return ",level: .Debug)
                    
                }else {
                    if let s = NSString.init(bytes: ptr, length: len, encoding: NSUTF8StringEncoding){
                        domainString = domainString + (s as String) + "."
                        ptr = ptr + Int(len)
                        domainLength += len
                        
                        domainLength += 1
                    }
                    
                    
                }
                
            }
            ptr += 1
            memcpy(&qType, ptr, 2)
            qType = qType.bigEndian
            ptr += 2
            memcpy(&qClass, ptr, 2)
            qClass = qClass.bigEndian
            ptr += 2
            
            queryDomains.append(domainString)
            if qr == 1  {
                if (ptr.distanceTo(endptr) <= 0 ) { return }
            }
        }
        //NSLog("---- %@", data)
        if qr == 1{
            for _ in 0..<answerCount {
                if (ptr.distanceTo(endptr) <= 0 ) {
                    finished = false
                    return
                }
                var px:UInt16 = 0
                memcpy(&px, ptr, 2)
                ptr += 2
                px = px.bigEndian
                let pxx = px >> 14
                var domain:String = ""
                if pxx == 3 {
                    //NSLog("cc %d", pxx)
                    let offset:UInt16 = px & 0x3fff
                    var ptr0:UnsafePointer<UInt8> = UnsafePointer<UInt8>.init(bytes)
                    
                    ptr0 =  ptr0.advancedBy(Int(offset))
                    
                    domain = DNSPacket.findLabel(ptr0)
                }else {
                    // packet 不全，导致后面无法解析
                    finished = false
                    return
                }
                
                
                var t:UInt16 = 0
                
                memcpy(&t, ptr, 2)
                t = t.bigEndian
                guard let type :QTYPE = QTYPE(rawValue: t) else {
                    return
                }
                ptr += 2
                var qclass:UInt16 = 0
                memcpy(&qclass, ptr, 2)
                qclass = qclass.bigEndian
                ptr += 2
                var ttl:Int32 = 0
                memcpy(&ttl, ptr, 4)
                ttl = ttl.byteSwapped
                ptr += 4
                
                var len:UInt16 = 0

                memcpy(&len, ptr, 2)
                len = len.bigEndian
                ptr += 2
                
                var domainString:String = ""
                var  domainLength = 0
                if type == .A {
                    var ip:Int32 = 0
                    memcpy(&ip, ptr, Int(len))
                    ip = ip.byteSwapped
                    domainString = "\(ip>>24 & 0xFF).\(ip>>16 & 0xFF).\(ip>>8 & 0xFF).\(ip & 0xFF)"
                    ptr += Int(len)
                    ipString.append(domainString)
                }else if type == .A6 {
                    
                    let buffer = NSMutableData()
                    memcpy(buffer.mutableBytes, ptr, Int(len))
                    ptr += Int(len)
                    AxLogger.log("IPv6 AAAA record found \(buffer)",level: .Notify)
                }else {
                    while (ptr.memory != 0x0) {
                        let len = Int(ptr.memory)
                        ptr = ptr.successor()
                        
                        if ptr.distanceTo(endptr) < len   {
                            finished = false
                            return
                            //NSLog("error return ")
                        }
                        if let s = NSString.init(bytes: ptr, length: len, encoding: NSUTF8StringEncoding) {
                           domainString = domainString + (s as String) + "."
                        }
                        
                        
                        ptr = ptr + Int(len)
                        domainLength += len
                        
                        domainLength += 1
                    }
                    ptr += 1
                }
                
                AxLogger.log(" \(domain) \(domainString)",level: .Debug)
                
            }
        }
        
        
        if let d = queryDomains.first {
            if qr == 0 {
                AxLogger.log("DNS Request: \(d) ",level: .Debug)
                
            }else {
                //NSLog("DNS Response Packet %@", d)
                AxLogger.log("DNS Response: \(d) :\(ipString) ",level: .Debug)
                if    !self.ipString.isEmpty {
                    let r = DNSCache.init(d: d, i: ipString)
                    SFSettingModule.setting.addDNSCacheRecord(r)
                    AxLogger.log("DNS \(d) IN A \(ipString)", level: .Trace)
                }else {
                     AxLogger.log("DNS \(d) IN not found record", level: .Trace)
                }
            }
            
        }
        
        
        //super.init()
    }
    static func findLabel(ptr0:UnsafePointer<UInt8>) ->String {
        var ptr:UnsafePointer<UInt8> = ptr0
        var domainString:String = ""
        var  domainLength = 0
        while (ptr.memory != 0x0) {
            let len = Int(ptr.memory)
            ptr = ptr.successor()
            
     //       if ptr.distanceTo(endptr) < len   {
//                NSLog("error return ")
//            }
            if let s =  NSString.init(bytes: ptr, length: len, encoding: NSUTF8StringEncoding)  {
                
                
                domainString = domainString + (s as String)  + "."
            }
            
            ptr = ptr + Int(len)
            domainLength += len
            
            domainLength += 1
        }

        return domainString
    }
    deinit{
         AxLogger.log("DNSPacket deinit",level: .Debug)
    }
    static func genPacketData(ip:String,domain:String,identifier:UInt16) ->NSData {
        //IPv4
        let respData = NSMutableData()
        respData.write(identifier)
        let x:UInt16 = 0x8180
        let y:UInt32 = 0x00010001
        let z:UInt32 =  0x00000000
        respData.write(x.bigEndian)
        respData.write(y.bigEndian)
        respData.write(z.bigEndian)
        let xx = domain.componentsSeparatedByString(".")
        for p in xx {
            let len:CChar = Int8(p.characters.count)
            respData.write(len)
            respData.write(p)
        }
        respData.write(CChar(0x00)) // .在那里
        respData.write(UInt16(0x0001).bigEndian)
        respData.write(UInt16(0x0001).bigEndian)
        respData.write(UInt16(0xC00C).bigEndian)
        respData.write(UInt16(0x0001).bigEndian)
        respData.write(UInt16(0x0001).bigEndian)
        respData.write(UInt32(0x000d2f00).bigEndian)
        respData.write(UInt16(0x0004).bigEndian)
        
        let ipD:UInt32  = inet_addr(ip.cStringUsingEncoding(NSUTF8StringEncoding)!)
        respData.write(ipD)
        return respData
    }
}
