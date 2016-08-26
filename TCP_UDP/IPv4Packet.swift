//
//  IPv4Packet.swift
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

import Foundation
import NetworkExtension


public class IPv4Packet:NSObject{
    var proto:UInt8 = 0
    let srcIP:NSData?
    let _rawData:NSData
    let destinationIP:NSData?
    var headerLength:Int32 = 0
    let payloadLength:Int32 = 0
    init(PacketData:NSData){
        
        if PacketData.length < 20 {
            //AxLogger.log("PacketData lenth error",)
            fatalError()
        }
        _rawData = PacketData;
        
        
        var p = _rawData.subdataWithRange(NSRange.init(location: 9, length: 1))
        proto = UInt8(data2Int(p,len: 1))
        srcIP = _rawData.subdataWithRange(NSRange.init(location: 12, length: 4))
        destinationIP = _rawData.subdataWithRange(NSRange.init(location: 16, length: 4))
        
        p = _rawData.subdataWithRange(NSRange.init(location: 0, length: 1))
        let len = data2Int(p, len: 1) & 0x0F
        headerLength = len * 4
        
        super.init()
        
    }
    func payloadData() ->NSData{
        return _rawData.subdataWithRange(NSRange.init(location: Int(headerLength), length: _rawData.length - Int(headerLength)))
    }
    override public var debugDescription: String {
        return "\(srcIP) \(destinationIP)"
    }
    deinit{
        //debugLog("IPv4Packet deinit")
    }
}
