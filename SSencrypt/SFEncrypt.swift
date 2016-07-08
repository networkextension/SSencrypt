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
struct enc_ctx {
    var method:String = "aes-256-cfb"
    var ramdonKey:String = ""
}
class SSEncrypt {
    var send_ctx:CCCryptorRef?
    var receive_ctx:CCCryptorRef?
    var iv:NSData?
    init(password:String,method:String) {
        
        
        iv =  getSecureRandom(16)
        receive_ctx = create_enc(CCOperation(kCCDecrypt), key: password.dataUsingEncoding(NSUTF8StringEncoding)!)
        send_ctx = create_enc(CCOperation(kCCEncrypt), key: password.dataUsingEncoding(NSUTF8StringEncoding)!)
        
    }
    func create_enc(op:CCOperation,key:NSData) -> CCCryptorRef {
        var  cryptor :CCCryptorRef = nil
        let  createDecrypt:CCCryptorStatus = CCCryptorCreateWithMode(op, // operation
            CCMode(kCCModeCFB), // mode CTR
            CCAlgorithm(kCCAlgorithmAES128),//kCCAlgorithmAES, // Algorithm
            CCPadding(ccNoPadding), // padding
            iv!.bytes, // can be NULL, because null is full of zeros
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
    func decrypt(encrypt_bytes:NSData) ->NSData?{
        if (  encrypt_bytes.length == 0 || encrypt_bytes.length < 16) {
            
            return nil;
            
        }
        
        
        
        //Empty IV: initialization vector
        //let ivt:NSData =  encrypt_bytes.subdataWithRange(NSMakeRange(0,16))
        let left:NSData = encrypt_bytes.subdataWithRange(NSMakeRange(16,encrypt_bytes.length-16));
        
        
            // Alloc Data Out
            let cipherDataDecrypt:NSMutableData = NSMutableData.init(length: left.length)!;
            
            //alloc number of bytes written to data Out
            var  outLengthDecrypt:NSInteger = 0
            
            //Update Cryptor
            let updateDecrypt:CCCryptorStatus = CCCryptorUpdate(receive_ctx!,
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
                let final:CCCryptorStatus = CCCryptorFinal(receive_ctx!, //CCCryptorRef cryptorRef,
                    cipherDataDecrypt.mutableBytes, //void *dataOut,
                    cipherDataDecrypt.length, // size_t dataOutAvailable,
                    &outLengthDecrypt); // size_t *dataOutMoved)
                
                if (final == CCCryptorStatus( kCCSuccess))
                {
                    //Release Cryptor
                    //CCCryptorStatus release =
                    //CCCryptorRelease(cryptor); //CCCryptorRef cryptorRef
                }
                
                return cipherDataDecrypt ;//cipherFinalDecrypt;
            }else {
                print("decrypt CCCryptorUpdate failure \(updateDecrypt) ")
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
    func encrypt(encrypt_bytes:NSData) ->NSData?{
        
        //let iv:NSData = NSData();
        //[NSMutableData dataWithLength:kCCBlockSizeAES128]
        
        
        
        
            //alloc number of bytes written to data Out
            var  outLength:NSInteger = 0 ;
            // Alloc Data Out
            let cipherData:NSMutableData = NSMutableData.init(length: encrypt_bytes.length)!;
            //Update Cryptor
            let  update:CCCryptorStatus = CCCryptorUpdate(send_ctx!,
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
                let final:CCCryptorStatus = CCCryptorFinal(send_ctx!, //CCCryptorRef cryptorRef,
                    cipherData.mutableBytes, //void *dataOut,
                    cipherData.length, // size_t dataOutAvailable,
                    &outLength); // size_t *dataOutMoved)
                
                if (final == CCCryptorStatus(kCCSuccess))
                {
                    
                    //CCCryptorRelease(cryptor )
                }
                let d:NSMutableData = NSMutableData()
                d.appendData(iv!);
                
                d.appendData(cipherData);
                return d;
                
            }
            
            
            
        
        
        return nil
    }

}
