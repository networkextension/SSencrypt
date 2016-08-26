//
//  UDPPacket.swift
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


public class UDPPacket:NSObject{
    var sourcePort:UInt16 = 0
    var destinationPort:UInt16 = 0
    var _rawData:NSData?
    init(PacketData:NSData){
        //debugLog("UDPPacket init")
        _rawData = PacketData
        var p = _rawData?.subdataWithRange(NSRange.init(location: 0, length: 2))
        var d = data2Int(p!, len: 2)
        sourcePort = UInt16(d).byteSwapped
        p = _rawData?.subdataWithRange(NSRange.init(location: 2, length: 2))
        d = data2Int(p!, len: 2)
        
        destinationPort = UInt16(d).byteSwapped
        super.init()
    }
    func payloadData() -> NSData{
        return (_rawData?.subdataWithRange(NSRange.init(location: 8, length: (_rawData?.length)! - 8)))!
    }
    deinit{
        //debugLog("UDPPacket deinit")
    }
}
