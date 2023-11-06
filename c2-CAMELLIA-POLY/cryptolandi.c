//*********************************************************************************************************
//** Cryptolandi encrypts/decrypts files with mulitple layers of encryption to reach 768 bits security
//*********************************************************************************************************
#include "cryptolandi.h"
void print_help(void);


int main (int argc, char *argv[])
{
  //check parameters
  if(argc<5)
    print_help();
  if(strcmp(argv[1],"-e")!=0 & strcmp(argv[1],"-d")!=0){
    printf("[Error] Wrong parameters\n");
    print_help();
  }
  //encrypt
  if(strcmp(argv[1],"-e")==0){ 
    if(cl_encrypt_file(argv[2],argv[3],argv[4])==0){
      fprintf(stderr,"[Error] Encryption failed");
      print_help();
    }
    printf("Encryption completed successfully\n");
  }
  //decrypt
  if(strcmp(argv[1],"-d")==0){ 
    if(cl_decrypt_file(argv[2],argv[3],argv[4])==0){
      fprintf(stderr,"[Error] Encryption failed");
      print_help();
    }
        printf("Decryption completed successfully\n");
  }
}
//print help
void print_help(void){
  printf("Cryptolandi encrypts/decrypts files with multiple layers of encryption based on AES 256 bit, CHACHA20 256 bit and CAMELLIA 256 bit, reaching 768 bit symmetric security.\n");
  printf("Example to ENCRYPT a file: cryptolandi -e originfilename encryptedfilename password\n");
  printf("Example to DECRYPT a file: cryptolandi -d encryptedfilename originfilename  password\n\n");
  printf("- You should use a strong and very long password.\n");
  printf("- For maximum security, please use 64 chars password.\n");
  printf("Cryptolandi makes a considerable effort to expand your password and to derive a 96 bytes key (768 bit)\n");
  exit(0);
}
/**
* DECRYPT FILE WITH AES256+GCM,CAMELLIA+OFB,CHACHA20
*/
int cl_decrypt_file(const char * infile, const char * outfilefinal, char *key){
  unsigned char rd[128];
  char error[128]={""};
  unsigned char keyaes[64];
  unsigned char ivaes[32];
  unsigned char tagaes[64];
  char tmpfileaes[256];
  unsigned char keycamellia[64];
  unsigned char ivcamellia[32];
  char tmpfilecamellia[256];
  unsigned char keychacha[64];
  unsigned char ivchacha[32];
  char outfile[512];
  int i,x;
  unsigned char hash[128];
  unsigned char hashbuf[128];
  unsigned char keyderived[256];
  int a,b,round,rounds,fd;
  // init variables with 0x0
  memset(rd,0x0,128);  
  memset(keyaes,0x0,128);
  memset(ivaes,0x0,32);
  memset(tmpfileaes,0x0,256);
  memset(keycamellia,0x0,64);
  memset(ivcamellia,0x0,32);
  memset(tmpfilecamellia,0x0,256);
  memset(tagaes,0x0,32);
  memset(error,0x0,128);
  memset(keychacha,0x0,64);
  memset(ivchacha,0x0,32);
  memset(hash,0x0,128);
  memset(hashbuf,0x0,128);
  memset(keyderived,0x0,256);
  
  if(strlen(outfilefinal)>256){
    strcpy(error,"[Error] - Destination name is too long max 256 chars");
    goto CLEANUP;
  }
  strcpy(outfile,outfilefinal);
  strcat(outfile,".tmp");
  // KEY DERIVATION/EXPANSION TO 768 BITS
  //compute hash of the key
  cl_sha3_512(key,strlen(key),hash); 
  // computer number of hashing rounds
  memcpy(&a,hash,sizeof(a));
  memcpy(&b,&hash[16],sizeof(b));
  rounds=a*b;   
  if(rounds<0) rounds=rounds*(-1);
  while(rounds>1000000)
        rounds=rounds/8;
  // apply multiple hashes
  for(i=0;i<rounds;i++){
      cl_sha3_512(hash,64,hashbuf);
      memcpy(hash,hashbuf,64);
  }
  cl_sha3_512(hash,64,hashbuf);
  memcpy(&hash[64],hashbuf,32);
  memcpy(keyderived,hash,96);  
  //cl_hexdump("keyderived decryption",keyderived,96);
  //END KEY DERIVATION OF 768 BITS
  // READ INFO FROM FOOTER OF THE FILE
  fd=open(infile,O_RDONLY);
  if(fd==-1)
      strcpy(error,"[Error] Error reading init vectors");
  i=lseek(fd,-64,SEEK_END);
  printf("position: %d \n",i);
  read(fd,tagaes,16);
  read(fd,ivaes,16);
  read(fd,ivcamellia,16);
  read(fd,ivchacha,16);
  close(fd);
  //cl_hexdump("tag from encryption",tagaes,16);
  //cl_hexdump("ivaes from encryption",ivaes,16);
  //cl_hexdump("ivcamellia from encryption",ivcamellia,16);
  //cl_hexdump("ivchacha from encryption",ivchacha,16);
  // DECRYPT CHACHA  
  memcpy(keychacha,&keyderived[64],32);
  sprintf(tmpfilecamellia,"%s.camellia",infile);  
  if(!cl_decrypt_file_chacha20(infile,tmpfilecamellia,keychacha,ivchacha)){
    strcpy(error,"[Error] Error decrypting the file CHACHA20");
    goto CLEANUP;
  }
  sprintf(tmpfileaes,"%s.aes",infile);
  memcpy(keycamellia,&keyderived[32],32);
  if(!cl_decrypt_file_camellia_ofb(tmpfilecamellia,tmpfileaes,keycamellia,ivcamellia)){
    strcpy(error,"[Error] Error decrypting the file CAMELLIA");
    goto CLEANUP;
  }
  unlink(tmpfilecamellia);
  memcpy(keyaes,&keyderived[0],32);
  if(!cl_decrypt_file_aes_gcm(tmpfileaes,outfile,keyaes,ivaes,tagaes)){
    strcpy(error,"[Error] Error decrypting the file AES");
    printf("tmpfileaes: %s\n outfile: %s\n",tmpfileaes,outfile);
    goto CLEANUP;
  }
  //remove temporary files
  unlink(tmpfileaes);
  unlink(outfilefinal);
  // rename to final name destination
  rename(outfile,outfilefinal);
  memset(rd,0x0,128);  
  memset(keyaes,0x0,128);
  memset(ivaes,0x0,32);
  memset(tmpfileaes,0x0,256);
  memset(keycamellia,0x0,64);
  memset(ivcamellia,0x0,32);
  memset(tmpfilecamellia,0x0,256);
  memset(tagaes,0x0,32);
  memset(error,0x0,128);
  memset(keychacha,0x0,64);
  memset(ivchacha,0x0,32);
  memset(hash,0x0,128);
  memset(hashbuf,0x0,128);
  memset(keyderived,0x0,256);   
  return(1);  
  
  CLEANUP:
  fprintf(stderr,"%s\n",error);
  memset(rd,0x0,128);  
  memset(keyaes,0x0,128);
  memset(ivaes,0x0,32);
  memset(tmpfileaes,0x0,256);
  memset(keycamellia,0x0,64);
  memset(ivcamellia,0x0,32);
  memset(tmpfilecamellia,0x0,256);
  memset(tagaes,0x0,32);
  memset(error,0x0,128);
  memset(keychacha,0x0,64);
  memset(ivchacha,0x0,32);
  memset(hash,0x0,128);
  memset(hashbuf,0x0,128);
  memset(keyderived,0x0,256); 
  return(0);
}

/**
* ENCRYPT FILE WITH AES256+GCM,CAMELLIA+OFB,CHACHA20
* the key received is expanded to 768 bits
*/
int cl_encrypt_file(const char * infile, const char * outfile, char *key){
  unsigned char rd[128];
  char error[128]={""};
  unsigned char keyaes[64];
  unsigned char ivaes[32];
  unsigned char tagaes[32];
  char tmpfileaes[256];
  unsigned char keycamellia[64];
  unsigned char ivcamellia[32];
  char tmpfilecamellia[256];
  unsigned char keychacha[64];
  unsigned char ivchacha[32];
  unsigned char hash[128];
  unsigned char hashbuf[128];
  unsigned char keyderived[256];
  int i,a,b,rounds,round,fd;
  char *ss;
  char originfilename[512];
  char encryptedfilename[512];
  char buffer[256];
  struct stat sb;
  int filesize=0;

  if(strlen(outfile)>256){
    strcpy(error,"[Error] - Destination name is too long max 256 chars");
    goto CLEANUP;
  }
  if(strlen(infile)>256){
    strcpy(error,"[Error] - Origin name is too long max 256 chars");
    goto CLEANUP;
  }
  // KEY DERIVATION/EXPANSION TO 768 BITS
  //compute hash of the key
  cl_sha3_512(key,strlen(key),hash); 
  // computer number of hashing rounds
  memcpy(&a,hash,sizeof(a));
  memcpy(&b,&hash[16],sizeof(b));
  rounds=a*b;	
  if(rounds<0) rounds=rounds*(-1);
  while(rounds>1000000)
        rounds=rounds/8;
  // appply multiple hashes
  for(i=0;i<rounds;i++){
      cl_sha3_512(hash,64,hashbuf);
      memcpy(hash,hashbuf,64);
  }
  cl_sha3_512(hash,64,hashbuf);
  memcpy(&hash[64],hashbuf,32);
  memcpy(keyderived,hash,96);  
  //cl_hexdump("keyderived encryption",keyderived,96);
  //END KEY DERIVATION OF 768 BITS

  // AES 256 ENCRYPTION
  memcpy(keyaes,&keyderived[0],32);  
  if(cl_crypto_random_data(rd)==0){
    strcpy(error,"116 - Error generating true random data");
    goto CLEANUP;
  }
  memcpy(ivaes,&rd[0],16);
  sprintf(tmpfileaes,"%s.aes",infile);
  if(!cl_encrypt_file_aes_gcm(infile,tmpfileaes,keyaes,ivaes,tagaes)){
    strcpy(error,"[Error] Error encrypting the file in AES");
    goto CLEANUP;
  }


  // END WRITING TAG AES  
  // CAMELLIA+OFB encryption
  memcpy(keycamellia,&keyderived[32],32);  
  if(cl_crypto_random_data(rd)==0){
    strcpy(error,"116 - Error generating true random data");
    goto CLEANUP;
  }
  memcpy(ivcamellia,&rd[0],16);
  sprintf(tmpfilecamellia,"%s.camellia",infile);
  if(!cl_encrypt_file_camellia_ofb(tmpfileaes,tmpfilecamellia,keycamellia,ivcamellia)){
    strcpy(error,"[Error] Error encrypting the file CAMELLIA");
    goto CLEANUP;
  }
  unlink(tmpfileaes);
  
  // CHACHA20 encryption
  memcpy(keychacha,&keyderived[64],32);  
  if(cl_crypto_random_data(rd)==0){
    strcpy(error,"116 - Error generating true random data");
    goto CLEANUP;
  }
  memcpy(ivchacha,&rd[0],16);
  if(!cl_encrypt_file_chacha20(tmpfilecamellia,outfile,keychacha,ivchacha)){
    strcpy(error,"[Error] Error encrypting the file CHACHA20");
    goto CLEANUP;
  }
  unlink(tmpfilecamellia);
  // write TAG AES AND ALL IV at the end of the file
  fd=open(outfile, O_RDWR|O_APPEND);
  if(write(fd, tagaes, 16) != 16) {
      sprintf(error, "[Error] - Writing to the file %s failed. errno = %s\n", outfile, strerror(errno));
      goto CLEANUP;
  }
  if(write(fd, ivaes, 16) != 16) {
      sprintf(error, "[Error] - Writing to the file %s failed. errno = %s\n", outfile, strerror(errno));
      goto CLEANUP;
  }  
  if(write(fd, ivcamellia, 16) != 16) {
      sprintf(error, "[Error] - Writing to the file %s failed. errno = %s\n", outfile, strerror(errno));
      goto CLEANUP;
  }  
  if(write(fd, ivchacha, 16) != 16) {
      sprintf(error, "[Error] - Writing to the file %s failed. errno = %s\n", outfile, strerror(errno));
      goto CLEANUP;
  }  
  close(fd);
  //cl_hexdump("tag from encryption",tagaes,16);
  //cl_hexdump("ivaes from encryption",ivaes,16);
  //cl_hexdump("ivcamellia from encryption",ivcamellia,16);
  //cl_hexdump("ivchacha from encryption",ivchacha,16);
  
  memset(rd,0x0,128);  
  memset(keyaes,0x0,128);
  memset(ivaes,0x0,32);
  memset(tmpfileaes,0x0,256);
  memset(keycamellia,0x0,64);
  memset(ivcamellia,0x0,32);
  memset(tmpfilecamellia,0x0,256);
  memset(tagaes,0x0,32);
  memset(error,0x0,128);
  memset(keychacha,0x0,64);
  memset(ivchacha,0x0,32);
  memset(originfilename,0x0,256);
  memset(encryptedfilename,0x0,256);
  memset(hash,0x0,128);
  memset(hashbuf,0x0,128);
  memset(keyderived,0x0,256);  
  return(1);  
  
  CLEANUP:
  fprintf(stderr,"%s\n",error);
  memset(rd,0x0,128);  
  memset(keyaes,0x0,128);
  memset(ivaes,0x0,32);
  memset(tmpfileaes,0x0,256);
  memset(keycamellia,0x0,64);
  memset(ivcamellia,0x0,32);
  memset(tmpfilecamellia,0x0,256);
  memset(tagaes,0x0,32);
  memset(error,0x0,128);
  memset(keychacha,0x0,64);
  memset(ivchacha,0x0,32);
  memset(originfilename,0x0,256);
  memset(encryptedfilename,0x0,256);
  memset(hash,0x0,128);
  memset(hashbuf,0x0,128);
  memset(keyderived,0x0,256);
  return(0);
}
#include "cl_encrypt_decrypt_file_aes_gcm.c"
#include "cl_encrypt_decrypt_file_camellia_ofb.c"
#include "cl_encrypt_decrypt_file_chacha20.c"
#include "cl_crypto_randomdata.c"
#include "cl_sha.c"
#include "cl_hexdump.c"