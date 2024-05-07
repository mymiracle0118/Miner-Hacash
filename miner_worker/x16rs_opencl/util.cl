#ifndef X16RX_UTIL_CL
#define X16RX_UTIL_CL


#ifdef __ENDIAN_LITTLE__

    #define WRITE_NONCE_BYTE4 bytes[offset+0] = nonce_ptr[3]; \
    bytes[offset+1] = nonce_ptr[2];\
    bytes[offset+2] = nonce_ptr[1];\
    bytes[offset+3] = nonce_ptr[0];

#else

    #define WRITE_NONCE_BYTE4 bytes[offset+0] = nonce_ptr[0];\
    bytes[offset+1] = nonce_ptr[1];\
    bytes[offset+2] = nonce_ptr[2];\
    bytes[offset+3] = nonce_ptr[3];

#endif


void write_nonce_to_bytes(int offset, unsigned char* bytes, unsigned int nonce) {
    // nonce bytes
    unsigned char *nonce_ptr = &nonce;
    WRITE_NONCE_BYTE4;
}


void write_nonce_to_global_bytes(int offset, __global unsigned char* bytes, unsigned int nonce) {
    // nonce bytes
    unsigned char *nonce_ptr = &nonce;
    WRITE_NONCE_BYTE4;
}


#endif