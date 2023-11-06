/**
* FILE decryption CAMELLIA + OFB (key MUST be 256 bit)
*/
int cl_decrypt_file_camellia_ofb(const char * infile, const char * outfile, const void * key, const void * iv){
    int insize = 102400;
    int outsize=102400+512;
    unsigned char inbuf[insize], outbuf[outsize];
    int ofh = -1, ifh = -1;
    int u_len = 0, f_len = 0;
    int iv_len=16;
    int len=0;
    int i;
    int read_size;
    char error[128]={"\0"};
    
    if((ifh = open(infile, O_RDONLY)) == -1) {
        sprintf(error,"056 -  Could not open input file %s, errno = %s\n", infile, strerror(errno));
        goto CLEANUP;
    }
    if((ofh = open(outfile, O_CREAT | O_TRUNC | O_WRONLY, 0644)) == -1) {
        sprintf(error,"057 -  Could not open output file %s, errno = %s\n", infile, strerror(errno));
        goto CLEANUP;    
    }
    EVP_CIPHER_CTX *ctx;    
    if(!(ctx = EVP_CIPHER_CTX_new())){
        strcpy(error,"058 - Error initialising the EVP_CIPHER, libssl may be wrong version or missing");
        goto CLEANUP;
    }
    if(1 != EVP_DecryptInit_ex(ctx, EVP_camellia_256_ofb(), NULL, NULL, NULL)){
        strcpy(error,"059 - Error initialising the CAMELLIA OFB libssl may be wrong version or missing");
        goto CLEANUP;
    }    
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)){
        strcpy(error,"054 - Error initialising the CAMELLIA OFB - KEY and IV");
        goto CLEANUP;
    }
    while((read_size = read(ifh, inbuf, insize)) > 0)
    {
        if(EVP_DecryptUpdate(ctx, outbuf, &len, inbuf, read_size) == 0){
           sprintf(error, "058 - EVP_DecryptUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
           goto CLEANUP;
        }
        if(write(ofh, outbuf, len) != len) {
            sprintf(error, "059 - Writing to the file %s failed. errno = %s\n", outfile, strerror(errno));
            goto CLEANUP;
	}
        u_len += len;
    }
    if(read_size == -1) {
        sprintf(error, "060 - Error Reading from the file %s failed. errno = %s\n", infile, strerror(errno));
        goto CLEANUP;
    }
    if(EVP_DecryptFinal_ex(ctx, outbuf, &f_len) == 0) {
        sprintf(error, "061 - Error EVP_DecryptFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto CLEANUP;
    }
    if(f_len) {
        if(write(ofh, outbuf, f_len) != f_len) {
            sprintf(error, "062 - Final write to the file %s failed. errno = %s\n", outfile, strerror(errno));
            goto CLEANUP;
	}
    }

    
    if(ifh != -1) close(ifh);
    if(ofh != -1) close(ofh);
    EVP_CIPHER_CTX_free(ctx);
    for(i=0;i<insize;i++) inbuf[0]=0;
    for(i=0;i<outsize;i++) outbuf[0]=0;
    for(i=0;i<128;i++) error[0];
    return(1);
    
    CLEANUP:
    fprintf(stderr,"%s\n",error);
    if(ifh != -1) close(ifh);
    if(ofh != -1) close(ofh);
    for(i=0;i<insize;i++) inbuf[0]=0;
    for(i=0;i<outsize;i++) outbuf[0]=0;
    for(i=0;i<128;i++) error[0];
    return(0);
    
}
/**
* FILE ENCRYPTION BY CAMELLIA +OFB (key MUST be 256 bit)
*/
int cl_encrypt_file_camellia_ofb(const char * infile, const char * outfile, const void * key, const void * iv){
    int insize = 102400;
    int outsize=102400+512;
    unsigned char inbuf[insize], outbuf[outsize];
    int ofh = -1, ifh = -1;
    int u_len = 0, f_len = 0;
    int iv_len=16;
    int len=0;
    int i;
    int read_size;
    char error[128]={"\0"};
    
    if((ifh = open(infile, O_RDONLY)) == -1) {
        sprintf(error,"036 -  Could not open input file %s, errno = %s\n", infile, strerror(errno));
        goto CLEANUP;
    }
    if((ofh = open(outfile, O_CREAT | O_TRUNC | O_WRONLY, 0644)) == -1) {
        sprintf(error,"037 -  Could not open output file %s, errno = %s\n", infile, strerror(errno));
        goto CLEANUP;    
    }
    EVP_CIPHER_CTX *ctx;    
    if(!(ctx = EVP_CIPHER_CTX_new())){
        strcpy(error,"031 - Error initialising the EVP_CIPHER, libssl may be wrong version or missing");
        goto CLEANUP;
    }
    if(1 != EVP_EncryptInit_ex(ctx, EVP_camellia_256_ofb(), NULL, NULL, NULL)){
        strcpy(error,"032 - Error initialising the CAMELLIA OFB, libssl may be wrong version or missing");
        goto CLEANUP;
    }    
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)){
        strcpy(error,"034 - Error initialising the CAMELLIA OFB - KEY and IV");
        goto CLEANUP;
    }
    while((read_size = read(ifh, inbuf, insize)) > 0)
    {
        if(EVP_EncryptUpdate(ctx, outbuf, &len, inbuf, read_size) == 0){
           sprintf(error, "038 - EVP_EncryptUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
           goto CLEANUP;
        }
        if(write(ofh, outbuf, len) != len) {
            sprintf(error, "039 - Writing to the file %s failed. errno = %s\n", outfile, strerror(errno));
            goto CLEANUP;
	}
        u_len += len;
    }
    if(read_size == -1) {
        sprintf(error, "040 - Error Reading from the file %s failed. errno = %s\n", infile, strerror(errno));
        goto CLEANUP;
    }
    if(EVP_EncryptFinal_ex(ctx, outbuf, &f_len) == 0) {
        sprintf(error, "041 - Error EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto CLEANUP;
    }
    if(f_len) {
        if(write(ofh, outbuf, f_len) != f_len) {
            sprintf(error, "042 - Final write to the file %s failed. errno = %s\n", outfile, strerror(errno));
            goto CLEANUP;
	}
    }
    if(ifh != -1) close(ifh);
    if(ofh != -1) close(ofh);
    EVP_CIPHER_CTX_free(ctx);
    for(i=0;i<insize;i++) inbuf[0]=0;
    for(i=0;i<outsize;i++) outbuf[0]=0;
    for(i=0;i<128;i++) error[0];
    return(1);
    
    CLEANUP:
    fprintf(stderr,"%s\n",error);
    if(ifh != -1) close(ifh);
    if(ofh != -1) close(ofh);
    for(i=0;i<insize;i++) inbuf[0]=0;
    for(i=0;i<outsize;i++) outbuf[0]=0;
    for(i=0;i<128;i++) error[0];
    return(0);
    
}


