/**
* FUNCTION TO MAKE AN HEX DUMP OF A BINARY DATA
*/
void cl_hexdump(char *desc, void *addr, int len) 
{
int i;
unsigned char buff[17];
unsigned char *pc = (unsigned char*)addr;
if (desc != NULL)
printf ("%s:\n", desc);
for (i = 0; i < len; i++) {
if ((i % 16) == 0) {
if (i != 0)
printf("  %s\n", buff);
printf("  %04x ", i);
        }
printf(" %02x", pc[i]);
if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }
        buff[(i % 16) + 1] = '\0';
    }
while ((i % 16) != 0) {
printf("   ");
        i++;
    }
printf("  %s\n", buff);
return;
}
/**
* FUNCTION TO CONVERT A BINARY TO HEXDECIMAL PRINTABLE STRING
*/
void cl_bin2hex(unsigned char *binary,int binlen,char *destination) 
{
int i;
char buf[10];
destination[0]=0;
for(i=0;i<binlen;i++){
  sprintf(buf,"%x",binary[i]);
  strcat(destination,buf);  
}
return;
}
