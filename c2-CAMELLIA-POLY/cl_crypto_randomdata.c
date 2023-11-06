/**
* FUNCTION TO GET 512 BITS (64 BYTES) OF CRYPTO RANDOM DATA
*/
int cl_crypto_random_data(char * rd){
	char buf[128];
	int i,r;
	long mt;
	struct timeval currentTime;
	char source[512],destination[512],tm[64];
	char error[256];
	//cleanup
	for(i=0;i<128;i++) buf[i]=0;
	for(i=0;i<64;i++) tm[i]=0;
	for(i=0;i<512;i++) destination[i]=0;
	for(i=0;i<512;i++) source[i]=0;
	for(i=0;i<256;i++) error[i]=0;
	r=0;
	//** read /dev/urandom
	int urnd = open("/dev/urandom", O_RDONLY);
	read(urnd, &buf[0], 32);
	close(urnd);
	//** get microtime
	gettimeofday(&currentTime, NULL);
	mt= currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;
        sprintf(tm,"%016ld\n",mt);
        memcpy(&buf[32],tm,16);
        gettimeofday(&currentTime, NULL);
	mt= currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;
        sprintf(tm,"%016ld\n",mt);
        memcpy(&buf[48],tm,16);
        // sha2 and sha3 with microtime	        
	if(!cl_sha3_256(buf,64,destination))
		return(0);
	memcpy(source,destination,32);
	gettimeofday(&currentTime, NULL);
	mt= currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;
        sprintf(tm,"%016ld\n",mt);
        memcpy(&source[32],tm,16);
	if(!cl_sha2_256(source,48,destination))
		return(0);		
		
	memcpy(source,destination,32);
	gettimeofday(&currentTime, NULL);
	mt= currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;
        sprintf(tm,"%016ld\n",mt);
        memcpy(&source[32],tm,16);
	if(!cl_sha3_256(source,48,destination))
		return(0);				

	memcpy(source,destination,32);
	gettimeofday(&currentTime, NULL);
	mt= currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;
        sprintf(tm,"%016ld\n",mt);
        memcpy(&source[32],tm,16);
	if(!cl_sha2_512(source,48,destination))
		return(0);						
		
	memcpy(source,destination,64);
	gettimeofday(&currentTime, NULL);
	mt= currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;
        sprintf(tm,"%016ld\n",mt);
        memcpy(&source[64],tm,16);
	r=cl_sha3_512(source,80,destination);
	if(r==0) return(0);
	//CLEANUP
	memcpy(rd,destination,64);		
	for(i=0;i<128;i++) buf[i]=0;
	for(i=0;i<64;i++) tm[i]=0;
	for(i=0;i<512;i++) source[i]=0;	
	for(i=0;i<512;i++) destination[i]=0;
	return(r);
}

