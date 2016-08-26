//
//  EngineTest.swift
//  SSencrypt
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
// need add https://github.com/networkextension/A.BIG.T code 
import Foundation

class Engine {
    var recv_decryption_ctx:SEContextRef =  SEContextRef()
    var send_encryption_ctx:SEContextRef =  SEContextRef()
    var aes:SSEncrypt?
    let pass:String = "aHR0cHM6Ly9yYXcuZ2l0aHVidXN"
    var m:Int32 = 0
    var mem:String = "test"
    
    init(){
       
        aes = SSEncrypt.init(password: pass, method: "aes-256-cfb")
        self.config()
        // Do any additional setup after loading the view.
    }
    
    
    @IBAction func doAction(sender: AnyObject) {
        test3()
        // test2()
    }
    func config(){
        
        recv_decryption_ctx = enc_ctx_create()
        send_encryption_ctx = enc_ctx_create()
        m = settingSS(pass,method: "aes-256-cfb")
        
        enc_ctx_init(m, send_encryption_ctx, 1);
        enc_ctx_init(m, recv_decryption_ctx, 0);
        //test_encryptor(d!)
    }
    
    func test(){
        //for i in  67 {
        let i = Int(arc4random_uniform(1024*1000*1000)) + 1
        
        let data = aes!.getSecureRandom(i)
        //        var ptr = data.bytes
        //        let end = ptr + data.length
        let result = NSMutableData.init()
        var index = 0
        while index < data.length {
            //srand(UInt32(NSDate().timeIntervalSinceReferenceDate))//"218.75.4.130"
            var  randomNumber: Int = Int(arc4random_uniform(1024)) + 1// Int(rand()) % 1024
            if randomNumber + index >= data.length {
                randomNumber = data.length - index
            }
            let temp = data.subdataWithRange(NSMakeRange(index, randomNumber))
            index += randomNumber
            //print("*** \(randomNumber) ")
            let cipher = test_encryptor(temp)
            
            result.appendData(cipher)
            
            
        }
        
        index = 0
        let plain = NSMutableData.init()
        while index < result.length {
            //srand(UInt32(NSDate().timeIntervalSinceReferenceDate))//"218.75.4.130"
            var  randomNumber: Int = Int(arc4random_uniform(1024)) + 1
            if randomNumber + index >= result.length {
                randomNumber = result.length - index
            }
            let temp = result.subdataWithRange(NSMakeRange(index, randomNumber))
            index += randomNumber
            
            //print("### \(randomNumber) ")
            let plain2 = aes!.decrypt(temp)
            plain.appendData(plain2!)
            
            
        }
        
        let m1 = plain.md5
        let m2 = data.md5
        if plain.isEqualToData(data){
            print("FINAL \(i) PASS")
        }else {
            print("FINAL \(i) FALI")
        }
        print("\(m1)")
        print("\(m2)")
        //}
        
    }
    func test3(){
        //for i in  67 {
        let i = Int(arc4random_uniform(1024*1000*1000)) + 1
        
        let data = aes!.getSecureRandom(i)
        //        var ptr = data.bytes
        //        let end = ptr + data.length
        let result = NSMutableData.init()
        var index = 0
        while index < data.length {
            //srand(UInt32(NSDate().timeIntervalSinceReferenceDate))//"218.75.4.130"
            var  randomNumber: Int = Int(arc4random_uniform(1024)) + 1// Int(rand()) % 1024
            if randomNumber + index >= data.length {
                randomNumber = data.length - index
            }
            let temp = data.subdataWithRange(NSMakeRange(index, randomNumber))
            index += randomNumber
            //print("*** \(randomNumber) ")
            let cipher = aes!.encrypt(temp)!
            
            result.appendData(cipher)
            
            
        }
        
        index = 0
        let plain = NSMutableData.init()
        while index < result.length {
            //srand(UInt32(NSDate().timeIntervalSinceReferenceDate))//"218.75.4.130"
            var  randomNumber: Int = Int(arc4random_uniform(1024)) + 1
            if randomNumber + index >= result.length {
                randomNumber = result.length - index
            }
            let temp = result.subdataWithRange(NSMakeRange(index, randomNumber))
            index += randomNumber
            
            //print("### \(randomNumber) ")
            let plain2 = test_decryptor(temp)
            plain.appendData(plain2)
            
            
        }
        
        let m1 = plain.md5
        let m2 = data.md5
        if plain.isEqualToData(data){
            print("FINAL \(i) PASS")
        }else {
            print("FINAL \(i) FALI")
        }
        print("\(m1)")
        print("\(m2)")
        //}
        
    }
    func test2(){
        for i in  32 ... 1024 {
            
            var  data = aes!.getSecureRandom(i)
            let x = data.length % 16
            if x != 0 {
                let y = NSMutableData.init(data: data)
                y.length += x
                data = y
            }
            let cipher = aes?.encrypt(data)
            let plain = test_decryptor(cipher!)
            //let plain = aes!.decrypt(cipher)
            if plain.isEqualToData(data){
                print("222: \(i) PASS")
            }else {
                print("\(i) \(plain.length) FALI")
            }
        }
        
    }
    func test_encryptor(buffer:NSData) ->NSData {
        
        let sendb:bufferRef = bufferRef.alloc(1)
        balloc(sendb,buffer.length)
        buffer_t_copy(sendb,UnsafePointer(buffer.bytes),buffer.length)
        let ret = ss_encrypt(sendb,send_encryption_ctx,buffer.length)
        if ret != 0 {
            abort()
        }
        
        let  len = buffer_t_len(sendb)
        //let recvb:bufferRef = bufferRef.alloc(1)
        //balloc(recvb,cipher.length)
        let temp = NSData.init(bytes: buffer_t_buffer(sendb), length: len)
        bfree(sendb)
        sendb.dealloc(1)
        return temp
        
        
    }
    func test_decryptor(buffer:NSData) ->NSData {
        
        let sendb:bufferRef = bufferRef.alloc(1)
        balloc(sendb,buffer.length)
        buffer_t_copy(sendb,UnsafePointer(buffer.bytes),buffer.length)
        let ret = ss_decrypt(sendb,recv_decryption_ctx,buffer.length)
        if ret != 0 {
            abort()
        }
        
        let  len = buffer_t_len(sendb)
        //let recvb:bufferRef = bufferRef.alloc(1)
        //balloc(recvb,cipher.length)
        let temp = NSData.init(bytes: buffer_t_buffer(sendb), length: len)
        bfree(sendb)
        sendb.dealloc(1)
        return temp
        
        
    }
}
