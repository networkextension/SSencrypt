//
//  ProxyConnector.swift
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
public class ProxyConnector: Connector {
    var proxy:SFProxy
    var tlsSupport:Bool = false
    #if os(iOS)
    let acceptableCipherSuites = [
        
        NSNumber(unsignedShort: TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256),
        NSNumber(unsignedShort: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
        NSNumber(unsignedShort: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        NSNumber(unsignedShort: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
        NSNumber(unsignedShort: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
        NSNumber(unsignedShort: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        NSNumber(unsignedShort: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
        
        
    ]
    #else
    let acceptableCipherSuites = [
    NSNumber(unsignedInt: TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256),
    NSNumber(unsignedInt: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
    NSNumber(unsignedInt: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
    NSNumber(unsignedInt: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
    NSNumber(unsignedInt: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
    NSNumber(unsignedInt: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
    NSNumber(unsignedInt: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
    
    ]
    #endif
    var pFrontAddress:String = ""
    var pFrontPort:UInt16 = 0
    init(spolicy: SFPolicy,p:SFProxy) {
        proxy = p
        
        super.init()
        self.policy = spolicy
        cIDFunc()
    }
    func startTLS(){
        
        
        //        NSMutableDictionary *sslSettings = [[NSMutableDictionary alloc] init];
        //        NSData *pkcs12data = [[NSData alloc] initWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"client" ofType:@"bks"]];
        //        CFDataRef inPKCS12Data = (CFDataRef)CFBridgingRetain(pkcs12data);
        //        CFStringRef password = CFSTR("YOUR PASSWORD");
        //        const void *keys[] = { kSecImportExportPassphrase };
        //        const void *values[] = { password };
        //        CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
        //
        //        CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
        //
        //        OSStatus securityError = SecPKCS12Import(inPKCS12Data, options, &items);
        //        CFRelease(options);
        //        CFRelease(password);
        //
        //        if(securityError == errSecSuccess)
        //        NSLog(@"Success opening p12 certificate.");
        //
        //        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        //        SecIdentityRef myIdent = (SecIdentityRef)CFDictionaryGetValue(identityDict,
        //        kSecImportItemIdentity);
        //
        //        SecIdentityRef  certArray[1] = { myIdent };
        //        CFArrayRef myCerts = CFArrayCreate(NULL, (void *)certArray, 1, NULL);
        //
        //        [sslSettings setObject:(id)CFBridgingRelease(myCerts) forKey:(NSString *)kCFStreamSSLCertificates];
        //        [sslSettings setObject:NSStreamSocketSecurityLevelNegotiatedSSL forKey:(NSString *)kCFStreamSSLLevel];
        //        [sslSettings setObject:(id)kCFBooleanTrue forKey:(NSString *)kCFStreamSSLAllowsAnyRoot];
        //        [sslSettings setObject:@"CONNECTION ADDRESS" forKey:(NSString *)kCFStreamSSLPeerName];
        //        [sock startTLS:sslSettings];
        let  sslSettings:[String : NSNumber] = [:]
        
        
        socket?.startTLS(sslSettings)
    }
    internal func socket(sock: GCDAsyncSocket!, didReceiveTrust trust: SecTrust!, completionHandler: ((Bool) -> Void)!)
    {
        
        completionHandler(true)
        
        //        let  bgQueue:dispatch_queue_t = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)
        //        dispatch_async(bgQueue) {
        //            [weak self] in
        //            var identity1:SecIdentityRef
        //            var trust1:SecTrustRef
        //
        //
        //            let arrayRefTrust:CFArrayRef = SecTrustCopyProperties(trust)!
        //            var result = kSecTrustResultUnspecified//SecTrustResultType
        ////            var status:OSStatus = SecTrustEvaluate(trust, &result)
        ////
        ////           //AxLogger.log("evaluate with result \(result) and status \(status)")
        ////           //AxLogger.log("trust properties: \(arrayRefTrust)")
        ////
        ////            var myReturnedCertificate1:SecCertificateRef
        ////            var status3:OSStatus  = SecIdentityCopyCertificate (identity1, &myReturnedCertificate1)
        ////
        ////
        ////            var myReturnedCertificate2:SecCertificateRef
        ////            var status4:OSStatus = SecIdentityCopyCertificate (identity2, &myReturnedCertificate2);
        //
        //
        //            let  count:CFIndex = SecTrustGetCertificateCount(trust)
        //            var isMatching:Bool = false
        //            for i in 0 ..< count{
        //                let certRef:SecCertificateRef = SecTrustGetCertificateAtIndex(trust, i)!
        //
        //                if let name = NSString.init(UTF8String: CFStringGetCStringPtr(SecCertificateCopySubjectSummary(certRef), CFStringBuiltInEncodings.UTF8.rawValue)) {
        //                   //AxLogger.log("remote cert at index \(i) is \(name)'")
        //                    if name == self!.proxy.serverAddress {
        //                        isMatching = true
        //                    }
        //
        //                    var  trustManual:UnsafeMutablePointer<SecTrust?> =  UnsafeMutablePointer<SecTrust?>.alloc(1)
        //                    //var trust:SecTrust
        //                    var status:OSStatus = SecTrustCreateWithCertificates(trust, SecPolicyCreateBasicX509(), trustManual)
        //                   //AxLogger.log("certStatus \(status)'")
        //                    var result:UnsafeMutablePointer<SecTrustResultType> = UnsafeMutablePointer<SecTrustResultType>.alloc(1)
        //                    status =  SecTrustEvaluate(trust, result)
        //                   //AxLogger.log("certStatus \(status)'")
        //
        //                    let arrayRef:CFArrayRef = SecTrustCopyProperties(trust)!
        //                   //AxLogger.log("arrayRef \(arrayRef)'")
        //                }
        //
        //
        //            }
        //            if isMatching {
        //                completionHandler(true)
        //            }else {
        //                completionHandler(false)
        //            }
        //
        //        }
        
    }
    
    public override func start() {
        let q = SFTCPConnectionManager.shared().dispatchQueue
        let q2 = self.socketQueue()
        
        let s = GCDAsyncSocket.init(delegate: self, delegateQueue: q, socketQueue: q2 )
            //#if DEBUG
                s.userData = cIDString
            //    #endif
            
            socket = s
            
            do {
                let  host:String = proxy.connectHost
                                try s.connectToHost(host, onPort: UInt16(proxy.serverPort)!)
                AxLogger.log("now connect \(targetHost) via \(host)",level: .Debug)
                if tlsSupport {
                    var  sslSettings:[String : NSNumber] = [:]
                    //http://stackoverflow.com/questions/26906773/gcdasyncsocket-two-way-authentication
                    //https://source.ind.ie/project/pulse-swift/blob/454a9c3e679ab7178af2196479009bfa09862654/pulse-swift/TLS.swift
                    // abount tls
                    //let chain = NSString(format: kCFStreamSSLValidatesCertificateChain)
                    //sslSettings[GCDAsyncSocketManuallyEvaluateTrust] = NSNumber.init(bool: true)
                    //let identityout:SecIdentityRef; [sslSettings setObject:[[NSArray alloc] initWithObjects:(__bridge id)(identityout), nil] forKey:GCDAsyncSocketSSLCertificates];
                    //[self.asyncSocket startTLS:sslSettings];
                    sslSettings[GCDAsyncSocketSSLProtocolVersionMin] = NSNumber(int: SSLProtocol.TLSProtocol12.rawValue)//NSNumber(unsignedInt: kTLSProtocol12.rawValue)
                    //sslSettings[GCDAsyncSocketSSLCipherSuites] = acceptableCipherSuites
                    sslSettings[GCDAsyncSocketManuallyEvaluateTrust] = true
                    //AxLogger.log("\(cIDString)  \(proxy.serverAddress):\(proxy.serverPort) tls:\(sslSettings) ",level: .Warning)
                    socket?.startTLS(sslSettings)
                    
                }
                
            } catch {
                //AxLogger.log("\(cIDString)  connectToHost ",level: .Error)
                let e = NSError(domain:errDomain , code: 7, userInfo: ["reason": "connectToHost error"])
                if let d = delegate{
                    d.connectorDidSetupFailed(self, withError: e)
                }
                
            }
        
    
       //AxLogger.log("\(cIDString) connectToHost \(targetHost) \(targetPort) by \(proxy.serverAddress) \(proxy.serverPort)",level:.Info)
        //return
    }

    override public func socket(sock: GCDAsyncSocket, didConnectToHost host: String!, port: UInt16){
        
       //AxLogger.log("\(cIDString) \(targetHost):\(targetPort) didConnectToHost \(host) and port \(port) via:\(proxy.serverAddress):\(proxy.serverPort)",level:.Info)
        remoteIPaddress = host
        isConnected = true
        if let d = delegate {
            d.connectorDidBecomeAvailable(self)
        }
        
    }
//    public func socket(sock: GCDAsyncSocket!, shouldTimeoutReadWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval{
//       //AxLogger.log("\(cIDString) shouldTimeoutReadWithTag \(tag)")
//        return 3
//    }
//    public func socket(sock: GCDAsyncSocket!, shouldTimeoutWriteWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval{
//       //AxLogger.log("\(cIDString) shouldTimeoutWriteWithTag \(tag)")
//        return 3
//    }
}
