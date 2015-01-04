#include <stdio.h>
#include <string.h>

int unDES (char* inFileName, unsigned long long key);
int DES (char* inFileName, unsigned long long key);

//função principal, a qual gere todo o processo de encriptação e desencriptacao
int main(int argc, char *argv[])
{
	int erro;
	unsigned long long key;

	if(argc<=2 || ( strcmp("-e",argv[1])!=0 && strcmp("-d",argv[1])!=0) ){
		char description[]="This tool encrypts/decrypts/signs a document using the DES encryption algorithm and the MDC-4 cryptographic hash function.";
		char examples[]="\nExamples:\n\tdes -e archive.gz\n\tdes -d archive.gz.des";
		char options[]="\nOptions:\n\t-e\tencrypt\n\t-d\tdecrypt";
		printf("Usage: des [OPTION] [FILE]\n%s\n%s\n%s\n",description,examples,options);
		return 0;
	}
	//encrypt
	key = 0x0123456789ABCDEF;

	if(strcmp("-e",argv[1])==0){
		erro = DES(argv[2], key);
		if (erro != 0)
			return erro;
	}
		
	//decrypt
	if(strcmp("-d",argv[1])==0){
		erro = unDES(argv[2], key);
	}

	return erro;
}
