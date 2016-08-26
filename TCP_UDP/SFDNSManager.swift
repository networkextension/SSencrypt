//
//  SFDNSManager.swift
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

class SFDNSManager {
    static let manager = SFDNSManager()
    var settings:[DNSServer] = []
    var index:Int = 0
    var userSetDNS = false
    var dnsServers:[String] = []
    func setUpConfig(opt:[String]?) ->[DNSServer]{
        
        var result:[DNSServer] = []
        if let opt = opt where !opt.isEmpty {
            userSetDNS = true
            for o in opt{
                let uper = o.uppercaseString
                if uper == "SYSTEM"{
                    addSystemDNS(&result)
                }else {
                    let d = DNSServer.init(ip: o,sys:false)
                    //settings.append(d)
                    result.append(d)
                }
            }
        }else {
            addSystemDNS(&result)
        }
        return result
        //maybe add default
    }
    func addSystemDNS(inout result:[DNSServer]) {
        let system = DNSServer.currentSystemDns()
        for s in system {
            if  s == proxyIpAddr {
                AxLogger.log("DNS invalid \(s) ",level: .Error)
            }else {
                
                if !s.isEmpty{
                    let d = DNSServer.init(ip: s,sys:true)
                    //settings.append(d)
                    result.append(d)
                    
                    SFEnv.env.updateEnvIP(s)
                    AxLogger.log("systen dns \(s) type:\( SFEnv.env.ipType)",level: .Info)
                }
                
            }
            
        }
    }
    func currentDNSServer() -> [String] {
        
        
        let dnss = loadSystemDNSServer()
        if let f = dnss.first where f == proxyIpAddr {
            AxLogger.log("DNS don't need  update",level: .Info)
        }else {
            dnsServers.removeAll()
            for item in dnss{
                dnsServers.append(item)
            }
            AxLogger.log("System DNS \(dnsServers)",level: .Info)
        }
        
        
        
        return dnsServers
        
    }
    func giveMeAserver() ->DNSServer{
        
        
        if index == settings.count  {
            index = 0
        }
        
        if index < settings.count{
            let s = settings[index]
            index += 1
            return s

        }else {
            return DNSServer.createSetting()
        }
        
        
        
    }
    func tunDNSSetting() ->[String]{
        if SFEnv.env.ipType == .ipv6 {
            return DNSServer.currentSystemDns()
        }else {
            return  DNSServer.tunIPV4DNS
        }
    }
    func updateSetting() ->[DNSServer]{
        
        var result:[DNSServer]
        if let r = SFSettingModule.setting.rule, let g = r.general{
             result  = setUpConfig(g.dnsserver)
        }else {
            result = setUpConfig(nil)
        }
        settings = result
        
        //SFNetworkInterfaceManager.instances.updateIPAddress()
        //settings.removeAll()
        //settings.appendContentsOf(result)
       
        return result
    }
}
