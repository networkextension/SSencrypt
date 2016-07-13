//
//  SFEncrypt.swift
//  SSencrypt
//
//  Created by 孔祥波 on 7/8/16.
//  Copyright © 2016 Kong XiangBo. All rights reserved.
//

import Foundation
//import CommonCrypto
import Security
var str = "Hello, playground"
let  config_ciphers = [
    "table":false,
    "rc4":false,
    "rc4-md5":false,
    "aes-128-cfb":false,
    "aes-192-cfb":false,
    "aes-256-cfb":true,
    "bf-cfb":false,
    "camellia-128-cfb":false,
    "camellia-192-cfb":false,
    "camellia-256-cfb":false,
    "salsa20":false,
    "chacha20":false,
    "chacha20-ietf":false
]

class enc_ctx {
    var method:String = "aes-256-cfb"
    var count:Int = 0
    var IV:NSData
    var ctx:CCCryptorRef
    static func create_enc(op:CCOperation,key:NSData,iv:NSData) -> CCCryptorRef {
        var  cryptor :CCCryptorRef = nil
        let  createDecrypt:CCCryptorStatus = CCCryptorCreateWithMode(op, // operation
            CCMode(kCCModeCFB), // mode CTR
            CCAlgorithm(kCCAlgorithmAES128),//kCCAlgorithmAES, // Algorithm
            CCPadding(ccNoPadding), // padding
            iv.bytes, // can be NULL, because null is full of zeros
            key.bytes, // key
            key.length, // keylength
            nil, //const void *tweak
            0, //size_t tweakLength,
            0, //int numRounds,
            0, //CCModeOptions options,
            &cryptor); //CCCryptorRef *cryptorRef
        if (createDecrypt == CCCryptorStatus(kCCSuccess)){
            return cryptor
        }else {
            return nil
        }
        
    }
    init(key:NSData,iv:NSData,encrypt:Bool){
        if encrypt {
            ctx = enc_ctx.create_enc(CCOperation(kCCEncrypt), key: key,iv: iv)
        }else {
            ctx = enc_ctx.create_enc(CCOperation(kCCDecrypt), key: key,iv: iv)
        }
        IV = iv
        
    }
    deinit {
        CCCryptorRelease(ctx)
    }
}
class SSEncrypt {
    var recv_buffer:NSData?
    var send_ctx:enc_ctx?
    var recv_ctx:enc_ctx?
    let block_size = 16
    static var ramdonKey:NSData?
    static var iv_cache:[NSData] = []
    static func have_iv(i:NSData) ->Bool {
        for x in SSEncrypt.iv_cache {
            if x.isEqualToData(i){
                return true
            }
        }
        
        return false
        
    }
    deinit {
        
    }
    init(password:String,method:String) {
        
        SSEncrypt.ramdonKey = SSEncrypt.evpBytesToKey(password,keyLen: password.characters.count)
        let iv =  getSecureRandom(16)
        //        let x = password.dataUsingEncoding(NSUTF8StringEncoding)!
        //        let data = NSMutableData.init(length: 32)
        //memcpy((data?.mutableBytes)!, x.bytes, x.length)
        //receive_ctx = create_enc(CCOperation(kCCDecrypt), key: key)
        send_ctx = enc_ctx.init(key: SSEncrypt.ramdonKey!, iv: iv, encrypt: true)
        SSEncrypt.iv_cache.append(iv)
        
    }
    func recvCTX(iv:NSData){
        if SSEncrypt.have_iv(iv){
            logStream.write("cryto iv dup error")
        }else {
            recv_ctx = enc_ctx.init(key: SSEncrypt.ramdonKey!, iv: iv, encrypt: false)
            SSEncrypt.iv_cache.append(iv)
        }
        
    }
    static func evpBytesToKey(password:String, keyLen:Int) ->NSData {
        let  md5Len:Int = 16
        
        let cnt = 1// (keyLen -1)/md5Len + 1
        let m = NSMutableData.init(length: cnt*md5Len)!
        let bytes = password.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!
        // memcpy((m?.mutableBytes)!, bytes.bytes , password.characters.count)
        let md5 = bytes.md5
        m.setData(md5)
        
        
        // Repeatedly call md5 until bytes generated is enough.
        // Each call to md5 uses data: prev md5 sum + password.
        let d = NSMutableData.init(length: md5Len+bytes.length)!
        //d := make([]byte, md5Len+len(password))
        var start = 0
        for _ in 0 ..< cnt {
            start += md5Len
            memcpy(d.mutableBytes,m.bytes , m.length)
            memcpy(d.mutableBytes+md5Len, bytes.bytes, bytes.length)
            let md5 = d.md5
            m.appendData(md5)
        }
        
        
        return m
    }
    func genData(encrypt_bytes:NSData) ->NSData?{
        
        //Empty IV: initialization vector
        
        //self.iv = ivt
        let cipher:NSData?
        if recv_ctx == nil {
            let iv  =  encrypt_bytes.subdataWithRange(NSMakeRange(0,16))
            recvCTX(iv)
            cipher = encrypt_bytes.subdataWithRange(NSMakeRange(16,encrypt_bytes.length-16));
        }else {
            cipher = encrypt_bytes
        }
        //        if let left = cipher {
        //            let tempbuffer = NSMutableData.init()
        //            if let last = recv_buffer {
        //                tempbuffer.appendData(last)
        //                tempbuffer.appendData(left)
        //                recv_buffer = NSData.init()
        //            }else {
        //                tempbuffer.setData(left)
        //            }
        //            let block_size = 128 / 8
        //            let left_size =  tempbuffer.length %  block_size
        //            if left_size != 0{
        //                recv_buffer = tempbuffer.subdataWithRange(NSMakeRange(tempbuffer.length - left_size, left_size))
        //                tempbuffer.length = tempbuffer.length - left_size
        //
        //            }
        //            AxLogger.log("recv cipher length:\(tempbuffer.length % 16)")
        //            return tempbuffer
        //        }
        return cipher
        
    }
    func decrypt(encrypt_bytes:NSData) ->NSData?{
        if (  encrypt_bytes.length == 0 ) {
            
            return nil;
            
        }
        
        if let left = genData(encrypt_bytes) {
            
            // Alloc Data Out
            let cipherDataDecrypt:NSMutableData = NSMutableData.init(length: left.length)!;
            
            //alloc number of bytes written to data Out
            var  outLengthDecrypt:NSInteger = 0
            
            //Update Cryptor
            let updateDecrypt:CCCryptorStatus = CCCryptorUpdate(recv_ctx!.ctx,
                                                                left.bytes, //const void *dataIn,
                left.length,  //size_t dataInLength,
                cipherDataDecrypt.mutableBytes, //void *dataOut,
                cipherDataDecrypt.length, // size_t dataOutAvailable,
                &outLengthDecrypt); // size_t *dataOutMoved)
            
            if (updateDecrypt == CCCryptorStatus(kCCSuccess))
            {
                //Cut Data Out with nedded length
                cipherDataDecrypt.length = outLengthDecrypt;
                
                // Data to String
                //NSString* cipherFinalDecrypt = [[NSString alloc] initWithData:cipherDataDecrypt encoding:NSUTF8StringEncoding];
                
                //Final Cryptor
                let final:CCCryptorStatus = CCCryptorFinal(recv_ctx!.ctx, //CCCryptorRef cryptorRef,
                    cipherDataDecrypt.mutableBytes, //void *dataOut,
                    cipherDataDecrypt.length, // size_t dataOutAvailable,
                    &outLengthDecrypt); // size_t *dataOutMoved)
                
                if (final != CCCryptorStatus( kCCSuccess))
                {
                    logStream.write("decrypt CCCryptorFinal failure")
                    //Release Cryptor
                    //CCCryptorStatus release =
                    //CCCryptorRelease(cryptor); //CCCryptorRef cryptorRef
                }
                
                return cipherDataDecrypt ;//cipherFinalDecrypt;
            }else {
                
                logStream.write("decrypt CCCryptorUpdate failure")
            }
        }else {
            logStream.write("decrypt no Data")
        }
        
        
        
        return nil
    }
    func getSecureRandom(bytesCount:Int) ->NSData {
        // Swift
        //import Security
        
        //let bytesCount = 4 // number of bytes
        //var randomNum: UInt32 = 0 // variable for random unsigned 32 bit integer
        var randomBytes = [UInt8](count: bytesCount, repeatedValue: 0) // array to hold randoms bytes
        
        // Gen random bytes
        SecRandomCopyBytes(kSecRandomDefault, bytesCount, &randomBytes)
        
        // Turn bytes into data and pass data bytes into int
        return NSData(bytes: randomBytes, length: bytesCount) //getBytes(&randomNum, length: bytesCount)
    }
    func padding(d:NSData) ->NSData{
        let l = d.length % block_size
        if l != 0 {
            let x = NSMutableData.init(data: d)
            x.length += l
            return x
        }else {
            return d
        }
    }
    func encrypt(encrypt_bytes:NSData) ->NSData?{
        
        //let iv:NSData = NSData();
        //[NSMutableData dataWithLength:kCCBlockSizeAES128]
        
        
        
        //let encrypt_bytes = padding(encrypt_bytes_org)
        //alloc number of bytes written to data Out
        var  outLength:NSInteger = 0 ;
        // Alloc Data Out
        let cipherData:NSMutableData = NSMutableData.init(length: encrypt_bytes.length)!;
        //Update Cryptor
        let  update:CCCryptorStatus = CCCryptorUpdate(send_ctx!.ctx,
                                                      encrypt_bytes.bytes,
                                                      encrypt_bytes.length,
                                                      cipherData.mutableBytes,
                                                      cipherData.length,
                                                      &outLength);
        if (update == CCCryptorStatus(kCCSuccess))
        {
            //Cut Data Out with nedded length
            cipherData.length = outLength;
            
            //Final Cryptor
            let final:CCCryptorStatus = CCCryptorFinal(send_ctx!.ctx, //CCCryptorRef cryptorRef,
                cipherData.mutableBytes, //void *dataOut,
                cipherData.length, // size_t dataOutAvailable,
                &outLength); // size_t *dataOutMoved)
            
            if (final == CCCryptorStatus(kCCSuccess))
            {
                
                //CCCryptorRelease(cryptor )
            }
            if send_ctx!.count == 0 {
                send_ctx!.count += 1
                let d:NSMutableData = NSMutableData()
                d.appendData(send_ctx!.IV);
                
                d.appendData(cipherData)
                return d
            }else {
                return cipherData
            }
            
            //AxLogger.log("cipher length:\(d.length % 16)")
            
            
        }
        
        return nil
    }
    
}
