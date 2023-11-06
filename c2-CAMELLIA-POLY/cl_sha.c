/**
* HASHING A BUFFER WITH SHA2-256
*/
int cl_sha3_256(unsigned char * source, int sourcelen,unsigned char * destination)
{
    int dlen;
    char error[256];
    error[0]=0;
    EVP_MD_CTX *mdctx;
    if((mdctx = EVP_MD_CTX_create()) == NULL){
        strcpy(error,"100 - Error creating hashing object, openssl library could miss or be wrong");
        goto CLEANUP;        
    }
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL)){
        strcpy(error,"101 - Error creating sha3-256 object, openssl library could miss or be wrong");
        EVP_MD_CTX_destroy(mdctx);
        goto CLEANUP;   
    }
    if(1 != EVP_DigestUpdate(mdctx, source, sourcelen)){
        strcpy(error,"102 - Error calculating the hash - sha3-256");
        EVP_MD_CTX_destroy(mdctx);
        goto CLEANUP; 
    }
    if(1 != EVP_DigestFinal_ex(mdctx, destination, &dlen)){
        strcpy(error,"103 - Error generating the hash - sha3-256");
        EVP_MD_CTX_destroy(mdctx);
        goto CLEANUP; 
    }
    EVP_MD_CTX_destroy(mdctx);
    return(dlen);

    CLEANUP:
    fprintf(stderr,"%s\n",error);
    return(0);
}
/**
* HASHING A BUFFER WITH SHA3-512
*/
int cl_sha3_512(unsigned char * source, int sourcelen,unsigned char * destination)
{
    int dlen;
    char error[256];
    error[0]=0;
    EVP_MD_CTX *mdctx;
    if((mdctx = EVP_MD_CTX_create()) == NULL){
        strcpy(error,"104 - Error creating hashing object, openssl library could miss or be wrong");
        goto CLEANUP;        
    }
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL)){
        strcpy(error,"105 - Error creating sha3-512 object, openssl library could miss or be wrong");
        goto CLEANUP;   
    }
    if(1 != EVP_DigestUpdate(mdctx, source, sourcelen)){
        EVP_MD_CTX_destroy(mdctx);
        strcpy(error,"106 - Error calculating the hash - sha3-512");
        goto CLEANUP; 
    }
    if(1 != EVP_DigestFinal_ex(mdctx, destination, &dlen)){
        EVP_MD_CTX_destroy(mdctx);
        strcpy(error,"107 - Error generating the hash - sha3-512");
        goto CLEANUP; 
    }
    EVP_MD_CTX_destroy(mdctx);
    return(dlen);
    CLEANUP:
    fprintf(stderr,"%s\n",error);
    return(0);
}

/**
* HASHING A BUFFER WITH SHA2-256
*/
int cl_sha2_256(unsigned char * source, int sourcelen,unsigned char * destination)
{
    int dlen;
    char error[256];
    error[0]=0;
    EVP_MD_CTX *mdctx;
    if((mdctx = EVP_MD_CTX_create()) == NULL){
        strcpy(error,"108 - Error creating hashing object, openssl library could miss or be wrong");
        goto CLEANUP;        
    }
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)){
        strcpy(error,"109 - Error creating sha256 object, openssl library could miss or be wrong");
        EVP_MD_CTX_destroy(mdctx);
        goto CLEANUP;   
    }
    if(1 != EVP_DigestUpdate(mdctx, source, sourcelen)){
        strcpy(error,"110 - Error calculating the hash - sha256");
        EVP_MD_CTX_destroy(mdctx);
        goto CLEANUP; 
    }
    if(1 != EVP_DigestFinal_ex(mdctx, destination, &dlen)){
        strcpy(error,"111 - Error generating the hash - sha256");
        EVP_MD_CTX_destroy(mdctx);
        goto CLEANUP; 
    }
    EVP_MD_CTX_destroy(mdctx);
    return(dlen);

    CLEANUP:
    fprintf(stderr,"%s\n",error);
    return(0);
}
/**
* HASHING A BUFFER WITH SHA2-512
*/
int cl_sha2_512(unsigned char * source, int sourcelen,unsigned char * destination)
{
    int dlen;
    char error[256];
    error[0]=0;
    EVP_MD_CTX *mdctx;
    if((mdctx = EVP_MD_CTX_create()) == NULL){
        strcpy(error,"112 - Error creating hashing object, openssl library could miss or be wrong");
        goto CLEANUP;        
    }
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL)){
        strcpy(error,"113 - Error creating sha512 object, openssl library could miss or be wrong");
        goto CLEANUP;   
    }
    if(1 != EVP_DigestUpdate(mdctx, source, sourcelen)){
        EVP_MD_CTX_destroy(mdctx);
        strcpy(error,"114 - Error calculating the hash - sha512");
        goto CLEANUP; 
    }
    if(1 != EVP_DigestFinal_ex(mdctx, destination, &dlen)){
        EVP_MD_CTX_destroy(mdctx);
        strcpy(error,"115 - Error generating the hash - sha512");
        goto CLEANUP; 
    }
    EVP_MD_CTX_destroy(mdctx);
    return(dlen);
    CLEANUP:
    fprintf(stderr,"%s\n",error);
    return(0);
}
