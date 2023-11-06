/**
* FILE ENCRYPTION BY AES256 + GCM (key MUST be 256 bit)
*/
int cl_decrypt_file_aes_gcm(const char * infile, const char * outfile, const void * key, const void * iv,unsigned char * tag){
    int insize = 102400;
    int outsize=102400+512;
    unsigned char inbuf[insize], outbuf[outsize];
    int ofh = -1, ifh = -1;
    int u_len = 0, f_len = 0;
    int iv_len=12;
    int len=0;
    int i;
    int read_size;
    char error[1024]={"\0"};
    if(strlen(infile)>256){
        strcpy(error,"011a - Input file name is too long");
        goto CLEANUP;
    }
    if(strlen(outfile)>256){
        strcpy(error,"011b- Output file name is too long");
        goto CLEANUP;
    }
    
    if((ifh = open(infile, O_RDONLY)) == -1) {
        sprintf(error,"016 -  Could not open input file %s, errno = %s\n", infile, strerror(errno));
        goto CLEANUP;
    }
    if((ofh = open(outfile, O_CREAT | O_TRUNC | O_WRONLY, 0644)) == -1) {
        sprintf(error,"017 -  Could not open output file %s, errno = %s\n",outfile, strerror(errno));
        goto CLEANUP;    
    }
    EVP_CIPHER_CTX *ctx;    
    if(!(ctx = EVP_CIPHER_CTX_new())){
        strcpy(error,"011 - Error initialising the EVP_CIPHER, libssl may be wrong version or missing");
        goto CLEANUP;
    }
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)){
        strcpy(error,"012 - Error initialising the AES-256 GCM, libssl may be wrong version or missing");
        goto CLEANUP;
    }    
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)){
        strcpy(error,"013 - Error initialising the AES-256 GCM - IV LEN, libssl may be wrong version or missing");
        goto CLEANUP;
    }
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)){
        strcpy(error,"014 - Error initialising the AES-256 GCM - KEY and IV");
        goto CLEANUP;
    }
    while((read_size = read(ifh, inbuf, insize)) > 0)
    {
        if(EVP_DecryptUpdate(ctx, outbuf, &len, inbuf, read_size) == 0){
           sprintf(error, "018 - EVP_DecryptUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
           goto CLEANUP;
        }
        if(write(ofh, outbuf, len) != len) {
            sprintf(error, "019 - Writing to the file %s failed. errno = %s\n", outfile, strerror(errno));
            goto CLEANUP;
	}
        u_len += len;
    }
    if(read_size == -1) {
        sprintf(error, "020 - Error Reading from the file %s failed. errno = %s\n", infile, strerror(errno));
        goto CLEANUP;
    }
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)){
        sprintf(error, "021 - Error EVP_CIPHER_CTX_ctrl failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto CLEANUP;    
    }
    if(EVP_DecryptFinal_ex(ctx, outbuf, &f_len) == 0) {
        sprintf(error, "021 - Error EVP_DecryptFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto CLEANUP;
    }
    if(f_len) {
        if(write(ofh, outbuf, f_len) != f_len) {
            sprintf(error, "022 - Final write to the file %s failed. errno = %s\n", outfile, strerror(errno));
            goto CLEANUP;
	}
    }
    for(i=0;i<insize;i++) inbuf[0]=0;
    for(i=0;i<outsize;i++) outbuf[0]=0;
    for(i=0;i<128;i++) error[0];
    if(ifh != -1) close(ifh);
    if(ofh != -1) close(ofh);
    EVP_CIPHER_CTX_free(ctx);
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
* FILE ENCRYPTION BY AES256 + GCM (key MUST be 256 bit)
*/
int cl_encrypt_file_aes_gcm(const char * infile, const char * outfile, const void * key, const void * iv,unsigned char * tag){
    int insize = 102400;
    int outsize=102400+512;
    unsigned char inbuf[insize], outbuf[outsize];
    int ofh = -1, ifh = -1;
    int u_len = 0, f_len = 0;
    int iv_len=12;
    int len=0;
    int i;
    int read_size;
    char error[128]={"\0"};
    
    if((ifh = open(infile, O_RDONLY)) == -1) {
        sprintf(error,"006 -  Could not open input file %s, errno = %s\n", infile, strerror(errno));
        goto CLEANUP;
    }
    if((ofh = open(outfile, O_CREAT | O_TRUNC | O_WRONLY, 0644)) == -1) {
        sprintf(error,"007 -  Could not open output file %s, errno = %s\n", infile, strerror(errno));
        goto CLEANUP;    
    }
    EVP_CIPHER_CTX *ctx;    
    if(!(ctx = EVP_CIPHER_CTX_new())){
        strcpy(error,"001 - Error initialising the EVP_CIPHER, libssl may be wrong version or missing");
        goto CLEANUP;
    }
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)){
        strcpy(error,"002 - Error initialising the AES-256 GCM, libssl may be wrong version or missing");
        goto CLEANUP;
    }    
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)){
        strcpy(error,"003 - Error initialising the AES-256 GCM - IV LEN, libssl may be wrong version or missing");
        goto CLEANUP;
    }
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)){
        strcpy(error,"004 - Error initialising the AES-256 GCM - KEY and IV");
        goto CLEANUP;
    }
    while((read_size = read(ifh, inbuf, insize)) > 0)
    {
        if(EVP_EncryptUpdate(ctx, outbuf, &len, inbuf, read_size) == 0){
           sprintf(error, "008 - EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
           goto CLEANUP;
        }
        if(write(ofh, outbuf, len) != len) {
            sprintf(error, "009 - Writing to the file %s failed. errno = %s\n", outfile, strerror(errno));
            goto CLEANUP;
	}
        u_len += len;
    }
    if(read_size == -1) {
        sprintf(error, "010 - Error Reading from the file %s failed. errno = %s\n", infile, strerror(errno));
        goto CLEANUP;
    }
    if(EVP_EncryptFinal_ex(ctx, outbuf, &f_len) == 0) {
        sprintf(error, "011 - Error EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto CLEANUP;
    }
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)){
        sprintf(error, "011 - Error EVP_CIPHER_CTX_ctrl failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto CLEANUP;
    }
    if(f_len) {
        if(write(ofh, outbuf, f_len) != f_len) {
            sprintf(error, "012 - Final write to the file %s failed. errno = %s\n", outfile, strerror(errno));
            goto CLEANUP;
	}
    }
    if(ifh != -1) close(ifh);
    if(ofh != -1) close(ofh);
    for(i=0;i<insize;i++) inbuf[0]=0;
    for(i=0;i<outsize;i++) outbuf[0]=0;
    for(i=0;i<128;i++) error[0];
    EVP_CIPHER_CTX_free(ctx);
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


