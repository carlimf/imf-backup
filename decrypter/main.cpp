//
//  main.c
//  decrypter
//
//  Created by Carl on 25/06/2015.
//  Copyright (c) 2015 ImmortalFiles.(http://www.immortalfiles.com) All rights reserved.
//

#include <stdio.h>
#include <openssl/md5.h>
#include <openssl/rc4.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/aes.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <memory.h>
#include <string.h>
#include <assert.h>


#define AES_CBT_CHUNK          50921472ll
#define AES_CRYPT_SECTOR_SIZE  65536
#define MIN(x, y) (((x) < (y)) ? (x) : (y))


struct AESCtrInstance{
    AES_KEY         m_key;
    unsigned char   m_iv[AES_BLOCK_SIZE];
    bool            m_bencrypt = true;
    long long       m_offset = -1;
    AESCtrInstance() {
        memset(&m_key,0,sizeof(m_key));
        memset(&m_iv,0,sizeof(m_iv));
    }
};


bool aesCtrCreateInstance( const char key[], long long offset, void **ppinstance ) {
    
    *ppinstance = NULL;
    
    if( (offset % (AES_CBT_CHUNK + AES_BLOCK_SIZE)) != 0 )
        return false;
    
    AESCtrInstance *pinstance = NULL;
    pinstance = new AESCtrInstance;
//    if( strlen(alignedKey) < 32 ) {
//        size_t oldLength = strlen(alignedKey);
//        memset(alignedKey + oldLength, 0, 32 - oldLength );
//    }
    
    // setup key
    if(AES_set_encrypt_key((const unsigned char*)key, 256, &pinstance->m_key)) {
        delete pinstance;
        return false;
    }
    
    // real file offset - fix
    pinstance->m_offset = offset;
    
    *ppinstance = pinstance;
    
    return true;
}

inline void generateCryptCode( const AES_KEY *key, const unsigned char *iv, unsigned char *cout, unsigned char *pcode, long long offset ) {
    
    unsigned char *poffset = (unsigned char *)&offset;
    
    // combine random iv with offset
    for( int i = 0; i < sizeof(long long); i++)
        cout[i] = iv[i] ^ poffset[i];
    
    for( int i = sizeof(long long); i < AES_BLOCK_SIZE; i++)
        cout[i] = iv[i];
    
    AES_encrypt(cout, pcode, key);
}


long long   aesCtrSize( bool encrypt, long long size ) {
    // return code size based on size
    if( !size )
        return 0;
    if( encrypt ) {
        long long nchunks = ((size - 1) / AES_CBT_CHUNK) + 1;
        return size + nchunks * AES_BLOCK_SIZE;
    }
    
    long long nchunks = (size / (AES_CBT_CHUNK + AES_BLOCK_SIZE)) + 1;
    int chunkOffset = size % (AES_CBT_CHUNK + AES_BLOCK_SIZE);
    if( chunkOffset >= 0 && chunkOffset < AES_BLOCK_SIZE)
        return (nchunks-1)*AES_CBT_CHUNK;
    return size -= nchunks * AES_BLOCK_SIZE;
}


bool aesCtrEncrypt( void *pvinstance, const char *input, char *output, int insize, int &outsize ) {
    
    AESCtrInstance *pinstance = (AESCtrInstance *)pvinstance;
    
    if( !insize )
        return true;
    
    const unsigned char* pin = (const unsigned char*)input;
    int inLength =insize;
    
    int outBufferSize = inLength +  AES_BLOCK_SIZE*(inLength / AES_CBT_CHUNK + 2);
    unsigned char* pout = (unsigned char*)output;
    int outLength = 0;
    
    // case when offset is not border of block
    // finish block or less
    unsigned char count[AES_BLOCK_SIZE];
    unsigned char cryptCode[AES_BLOCK_SIZE];
    
    int blockOffset = pinstance->m_offset % AES_BLOCK_SIZE;
    if( blockOffset != 0 ) {
        // check if this is iv block number
        if( !pinstance->m_bencrypt) {
            int chunkOffset = pinstance->m_offset % (AES_CBT_CHUNK + AES_BLOCK_SIZE);
            if( chunkOffset >= 0 && chunkOffset < AES_BLOCK_SIZE) {
                
                int processLength = MIN( AES_BLOCK_SIZE - blockOffset, inLength );
                memcpy(pinstance->m_iv + blockOffset, pin, processLength);
                
                pin += processLength;
                inLength -= processLength;
                pinstance->m_offset += processLength;
                
                blockOffset = 0;
            }
        }
        
        if( blockOffset != 0 ) {
            
            long long realOffset = pinstance->m_offset - blockOffset;
            if( !pinstance->m_bencrypt)
                realOffset = aesCtrSize(false, realOffset );
            
            generateCryptCode(&pinstance->m_key, pinstance->m_iv, count, cryptCode, realOffset );
            
            int processLength = MIN( AES_BLOCK_SIZE - blockOffset, inLength );
            for( int i = 0; i < processLength; i++)
                pout[i] = cryptCode[blockOffset + i] ^ pin[i];
            
            pout += processLength;
            pin += processLength;
            inLength -= processLength;
            outLength += processLength;
            pinstance->m_offset += processLength;
        }
    }
        
    while( inLength >= AES_BLOCK_SIZE ) {
        
        if( (pinstance->m_offset % (AES_CBT_CHUNK + AES_BLOCK_SIZE)) == 0 ) {
            
            memcpy(pinstance->m_iv, pin, AES_BLOCK_SIZE);
            
            pinstance->m_offset += AES_BLOCK_SIZE;
            pin += AES_BLOCK_SIZE;
            inLength -= AES_BLOCK_SIZE;
        }
        else {
            
            long long realOffset = aesCtrSize(false, pinstance->m_offset );
            generateCryptCode(&pinstance->m_key, pinstance->m_iv, count, cryptCode, realOffset );
            
            for( int i = 0; i < AES_BLOCK_SIZE; i++)
                pout[i] = cryptCode[i] ^ pin[i];
            
            pinstance->m_offset += AES_BLOCK_SIZE;
            pout += AES_BLOCK_SIZE;
            pin += AES_BLOCK_SIZE;
            outLength += AES_BLOCK_SIZE;
            inLength -=  AES_BLOCK_SIZE;
        }
    }
    
    if( inLength ) {
        
        // decode last block
        if( (pinstance->m_offset % (AES_CBT_CHUNK + AES_BLOCK_SIZE)) == 0 ) {
            // last block is iv
            memcpy(pinstance->m_iv, pin, inLength);
            
            pinstance->m_offset += inLength;
            pin += inLength;
            inLength -=  inLength;
            
        }else {
            // last block is not iv
            long long realOffset = aesCtrSize(false, pinstance->m_offset );
            generateCryptCode(&pinstance->m_key, pinstance->m_iv, count, cryptCode, realOffset );
            
            for( int i = 0; i < inLength; i++)
                pout[i] = cryptCode[i] ^ pin[i];
            
            pinstance->m_offset += inLength;
            pout += inLength;
            pin += inLength;
            outLength += inLength;
            inLength -=  inLength;
        }
    }
    
    assert( outLength < outBufferSize );
    outsize = outLength;
    
    return true;
}


void aesCtrDestroyInstance( void *pvinstance ) {
    AESCtrInstance *pinstance = (AESCtrInstance *)pvinstance;
    delete pinstance;
}

class CAES {
protected:
    void *m_instance = NULL;
    
public:
    
    
    bool startCrypt( const char key[], long long fromOffset ) {
        long long offset = fromOffset;
        offset = aesCtrSize(true, fromOffset);
        if(!aesCtrCreateInstance(key, offset, &m_instance))
            return false;
        return true;
    }
    
    
    
    bool crypt( const char *input, char *output, int insize, int &outsize ) {
        if(!aesCtrEncrypt(m_instance, input, output, insize, outsize))
            return false;
        
        return true;
    }
    bool finishCrypt() {
        aesCtrDestroyInstance(m_instance);
        m_instance = NULL;
        return true;
    }
    
    long long sizeToProccess( long long size ) {
        // encrypt - is equal size - cause src file (decrypted) is size
        // decrypt - size to proccess is equal to encrypted size
        return aesCtrSize(true, size);
    }
    
    long long srcOffset( long long offset) {
        // encrypt - src offset is normal
        // decrypt - src offset is shiffted
        return sizeToProccess(offset);
    }
    
    long long dstOffset( long long offset) {
        // encrypt - dst offset is shifted
        // decrypt - dst offset is normal
        return offset;
    }
    
    ~CAES() {
        if( m_instance ) {
            finishCrypt();
        }
    }
};

bool PBKDF2FromBuffer(const char* pbuf, const int length, char key[]) {
    const unsigned char salt[] = "sdffkj3290rgfhgiosf923989rgdfff";
    if(!PKCS5_PBKDF2_HMAC_SHA1(pbuf, length, salt, sizeof(salt), 1, 32, (unsigned char *)key))
        return false;
    return true;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    
    if(argc < 4 ) {
        printf("usage: \"passoword\" encryptedfile decryptedfile\n");
        return 1;
    }
    
    FILE *infile, *outfile;
    
    infile=fopen(argv[2],"rb");
    if (!infile){
        printf("Unable to open input file\n");
        return 1;
    }
    
    outfile = fopen(argv[3], "wb");
    if (!outfile){
        fclose(infile);
        printf("Unable to open output file\n");
        return 1;
    }
    
    const char *tmp = argv[1];
    int len = strlen(tmp);
    char enckey[32];
    if(!PBKDF2FromBuffer(tmp, len, enckey)) {
        printf("Broken\n");
        return 1;
    }
    
    CAES    aes;
    aes.startCrypt(enckey, 0);
    
    /* Cycle until end of file reached: */
    char buffer[AES_CRYPT_SECTOR_SIZE * 7];
    char bufferout[AES_CRYPT_SECTOR_SIZE * 7];
    while( !feof( infile ) )
    {
        int insize = (int)fread( buffer, sizeof( char ), sizeof(buffer), infile );
        if( ferror( infile ) )      {
            perror( "Read error\n" );
            break;
        }
        
        int outsize;
        aes.crypt(buffer, bufferout, insize, outsize);
        
        fwrite(bufferout, sizeof(char), outsize, outfile);
        if( ferror( outfile ) )      {
            perror( "Write error\n" );
            break;
        }
    }
    
    aes.finishCrypt();
    
    fclose(outfile);
    fclose(infile);
    
    return 0;
}
