//
//  DNSServer.swift
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
import Darwin
class DNSServer :CustomStringConvertible {
    var ipaddr:String
    var system:Bool = false
    var type:SFNetWorkIPType
    var successCount:Int = 0
    var failureCount:Int = 0
    var totalTime:Double = 0.0
    init(ip:String,sys:Bool){
        ipaddr = ip
        system = sys
        type = SFNetWorkIPType.init(ip: ip)
    }
    static func currentSystemDns() ->[String] {
        let dnss = loadSystemDNSServer()
        return dnss
    }
    static func createSetting() ->DNSServer {
        let count = DNSServer.default_servers.count
        let value = Int(arc4random()) % count;
        let x = DNSServer.default_servers[value]
        let r = DNSServer.init(ip: x, sys: false)
        return r
    }
    static let tunIPV4DNS = ["240.7.1.10"]
    static let  default_servers = ["119.29.29.29","223.6.6.6", "223.5.5.5"]
    var description: String {
        return "\(ipaddr)"
    }
}
