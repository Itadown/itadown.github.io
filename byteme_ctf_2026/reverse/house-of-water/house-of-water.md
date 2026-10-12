I opened the file in Ghidra, looked at the setup function to find out this :
```
void setup(void)
{
  char *__s;
  FILE *__stream;
  char *pcVar1;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  __s = malloc(0x80);
  if (__s == (char *)0x0) {
    die("malloc failed");
  }
  memset(__s,0,0x80);
  __stream = fopen("./flag.txt","r");
  if (__stream == (FILE *)0x0) {
    builtin_strncpy(__s,"flag{missing_flag_txt}\n",0x18);
  }
  else {
    pcVar1 = fgets(__s,0x80,__stream);
    if (pcVar1 == (char *)0x0) {
      builtin_strncpy(__s,"flag{missing_flag_txt}\n",0x18);
    }
    fclose(__stream);
  }
  return;
}
```
Wecan clearly see that a chunk of 0x80 is allocated in the memory at the index 0x0.

We just needed to connect with :
nc 145.239.142.129 1341

And do a malloc of 0x80 at the index 0 and then show at the index 0 with 0 offset a size of 0x80. We then need to convert the hex obtained (
4f 57 41 53 50 7b 64 72 69 6e 6b 5f 66 72 30 6d 
5f 74 68 33 5f 70 30 69 73 30 6e 33 64 5f 74 63 
34 63 68 33 7d 0a
) in ASCII as usual and we obtain the flag :
OWASP{drink_fr0m_th3_p0is0n3d_tc4ch3}
