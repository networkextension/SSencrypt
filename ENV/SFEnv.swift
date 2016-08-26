//
//  SFEnv.swift
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
import NetworkExtension
import Darwin


enum SFNetWorkIPType:Int32,CustomStringConvertible {
    case ipv4  = 2//AF_INET
    case ipv6  = 30//AF_INET6
    internal var description: String {
        switch self {
        case .ipv4:return "IPV4"
        case .ipv6:return "IPV6"
        
        }
    }
    init(ip:String) {
        var sin = sockaddr_in()
        var sin6 = sockaddr_in6()
        var t:Int32 = 0
        if ip.withCString({ cstring in inet_pton(AF_INET6, cstring, &sin6.sin6_addr) }) == 1 {
            // IPv6 peer.
            t = AF_INET6
        }
        else if ip.withCString({ cstring in inet_pton(AF_INET, cstring, &sin.sin_addr) }) == 1 {
            // IPv4 peer.
            t = AF_INET
        }
        self = SFNetWorkIPType.init(rawValue: t)!

    }
}
//物理层type
enum SFNetWorkType:Int,CustomStringConvertible {
    case wifi  = 0
    case bluetooth  = 1
    case cell = 2
    case cellshare = 3 //cell share 模式
    internal var description: String {
        switch self {
        case .wifi:return "WI-FI"
        case .bluetooth:return "BlueTooth"
        case .cell:return "Cell"
        case .cellshare:return "Cell Share"
        }
    }
    init(interface:String) {
        
        var t = -1
        switch interface {
        case "en0":
            t = 0
        case "awdl0":
            t = 0
        case "pdp_ip0":
            t = 2
        case "pdp_ip1":
            t = 3
        default:
            t = 1
        }
        self = SFNetWorkType.init(rawValue: t)!
        
    }

}
class SFEnv {
    static let env:SFEnv = SFEnv()
    var session:SFVPNSession = SFVPNSession()
    var ipType:SFNetWorkIPType = .ipv4
    var hwType:SFNetWorkType = .cell

    init() {
    }
    func updateEnv(ip:String,interface:String){
        ipType = SFNetWorkIPType.init(ip: ip)
        hwType = SFNetWorkType.init(interface: interface)
    }
    func updateEnvIP(ip:String){
        if !ip.isEmpty{
            ipType = SFNetWorkIPType.init(ip: ip)
        }
        
    }
    func updateEnvHW(interface:String){
        hwType = SFNetWorkType.init(interface: interface)
    }
    func updateEnvHWWithPath(path:NWPath?){
        if let p = path{
            if p.expensive {
                hwType = .cell
            }else {
                hwType = .wifi
            }
            AxLogger.log("Now Network Type: \(hwType.description)",level:.Info)
            SFNetworkInterfaceManager.instances.updateIPAddress()
            
        }
    }
}
