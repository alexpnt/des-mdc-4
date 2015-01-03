/*Author: Rui Pedro Paiva
Teoria da Informação, LEI, 2008/2009
// Alterado por:
// Alexandre Rui Santos Fonseca Pinto 2010131853
// Carlos Miguel Rosa Avim 2000104864*/

#include "DES.h"

//função para encriptação
int DES (char* inFileName, unsigned long long key)
{
	return DESgeneral(inFileName, key, 0);
}


//função para decriptação
int unDES (char* inFileName, unsigned long long key)
{
	return DESgeneral(inFileName, key, 1);
}


//função geral para encriptação (type = 0) e decriptação (type = 1) de um ficheiro 
int DESgeneral (char* inFileName, unsigned long long key, int type)
{
	FILE* DESInFile;
	unsigned char* inByteArray;
	long inFileSize;
	unsigned char *crpByteArray;
	char* outFileName;
	int write;
	char response;
	struct stat stFileInfo;
	FILE* DESOutFile;
	char suf[5];
	unsigned char *hash, *hash_decrypt;
	
	//abrir ficheiro e ler tamanho
	DESInFile = fopen(inFileName, "rb");
	if (DESInFile == NULL)
	{
		printf("Error opening file for reading. Exiting...\n");
		return 1;
	}
	fseek(DESInFile, 0L, SEEK_END);
	inFileSize = ftell(DESInFile);  //ignore EOF
	fseek(DESInFile, 0L, SEEK_SET);


	//ler ficheiro inteiro para array inByteArray	
	inByteArray = (unsigned char*) calloc(inFileSize, sizeof(unsigned char));
	fread(inByteArray, 1, inFileSize, DESInFile);
		
	//criar assinatura
	if (type == 0)  //encriptacao
	{
		hash = (unsigned char*)calloc(16,sizeof(char));								//aloca espaco para uma assinatura de 16 bytes
		signature(inByteArray, inFileSize, key, hash);								//gera o hash do ficheiro
		
		inByteArray = realloc(inByteArray, inFileSize + 16*sizeof(unsigned char));	//realoca espaco para mais 16 bytes( para a assiantura de 128 bits) 
		
		memcpy(inByteArray+inFileSize, hash, 16*sizeof(unsigned char));				//adiciona hash aos dados
		inFileSize+=16;																//actualiza o tamanho do ficheiro
		
		free(hash);																	//liberta espaco alocado para o hash
	}
	


	//encriptar/desencriptar dados e assinatura no array
	crpByteArray = encryptDES(inByteArray, inFileSize, key, type);


	//nome do ficheiro de saída
	if (type == 0)  //encriptação
	{
		outFileName = (char*) calloc(strlen(inFileName) + 5, sizeof(char)); 
		strcpy(outFileName, inFileName);
		strcat(outFileName, ".des");
	}
	else  //decriptação
	{
		strcpy(suf, &inFileName[strlen(inFileName) - 4]);
		if (strcmp(suf, ".des") == 0)
		{		
			outFileName = (char*) calloc(strlen(inFileName), sizeof(char)); 
			strcat(outFileName, inFileName);
			outFileName[strlen(outFileName) - 4] = 0;
		}
		else
		{
			outFileName = (char*) calloc(strlen(inFileName)+11, sizeof(char));
			strcpy(outFileName, inFileName);
			strcat(outFileName, "_decrypted");
		}

	}

	
	//verificar assinatura
	if (type == 1)
	{
		inFileSize -= 16;																	//actualiza novamente o tamanho do ficheiron desencriptado,sem assinatura 
		
		hash_decrypt = (unsigned char*)calloc(16,sizeof(char));								//aloca espaco de 16 bytes, para levar com o hash
		
		memcpy(hash_decrypt, crpByteArray+inFileSize , 16);									//copia e guarda o hash presente no fim do ficheiro
		if(!checkSignature(crpByteArray, inFileSize, key, hash_decrypt)) {				//verifica se o hash presente no fim do ficheiro e' igual ao hash que
																										//vai ser gerado novamente do ficheiro original  
			printf("Signature is not valid. File is not trustworthy!!\n");
			free(hash_decrypt);
			return 0;
		}
		free(hash_decrypt);																	//liberta espaco alocado para o hash

	}
	
	//criar ficheiro
	write = 1;
	if(stat(outFileName, &stFileInfo) == 0) //see if file already exists
	{
		printf ("File already exists. Overwrite (y/n)?: ");
		response = getchar();
		if (response == 'n')
			write = 0;
		printf("\n");
		fflush(stdin);
	}

	//flush do crpByteArray para ficheiro
	if (write)
	{
		DESOutFile = fopen(outFileName, "wb");
		if (DESOutFile == NULL)
		{
			printf("Error opening file for writing!!! Exiting...\n");
			return -1;
		}
		fwrite(crpByteArray, 1, inFileSize, DESOutFile);
		fclose(DESOutFile);
		
	}
	
	//finalizações
	free(inByteArray);
	free(outFileName);
	free(crpByteArray);
	fclose(DESInFile);

	return 0;	
}


// função para encriptação/decriptação de dados no array inByteArray, de dimensão dim
unsigned char* encryptDES(unsigned char* inByteArray, long dim, unsigned long long key, int type)
{
	unsigned long long subKeys[16];
	unsigned char* outByteArray;
	unsigned long long plain, cipher, aux=0;
	int i, j;

	
	//obtém sub-keys (16 de comprimento 48)
	DESKeySchedule(key, subKeys);

	if (type == 1) //decrypt --> inverter subKeys
	{
		for(i=0; i<8; i++)					//inverte o array das 16 subkeys
		{
			aux=subKeys[i];
			subKeys[i] = subKeys[15-i];
			subKeys[15-i] = aux;
		}
	}

	outByteArray = (unsigned char*) calloc(dim, sizeof(unsigned char)); 
	i = 0;
	plain = 0;
	while (i < dim)
	{
		plain = 0;
		j = i;
		while (j < i + 8 && j < dim)
		{
 			plain = plain | ((unsigned long long)inByteArray[j] << (64 - 8*(j-i+1)));
			j++;
		}
		
		//determina cifra
		if (j - i == 8)  //ficheiro é múltiplo de 8 bytes
		
			cipher = encryptDESplain(plain, subKeys);
		else
			cipher = plain;


		//guarda cifra no array de saída
		j = i;
		while (j < i + 8 && j < dim)
		{
			outByteArray[j] = (unsigned char) (cipher >> (56 - 8*(j-i)) & (0xFF));
			j++;
		}

		i = j;		
	}

	return outByteArray;
}


// função para encriptação de uma mensagem de 64 bits (plain), com base nas subKeys
//devolve a mensagem cifrada

unsigned long long encryptDESplain(unsigned long long plain, unsigned long long* subKeys)
{	//tabelas de permutacao iniciais e finais IP e IP-1
	int ip[] = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
	int ip_1[] = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
	unsigned long long aux=0, permut=0, output=0, final_swap=0;
	unsigned int i, r_prev=0, r_next=0, l_prev=0, l_next=0;

	//permutacao inicial do bloco de 64 bits, de acordo com a tabela IP
	for(i=0;i<64;i++)		
	{
		aux=plain;							//guarda o bloco inical
		aux=aux>>(64-ip[i])&0x01;			//guarda o bit que esta na posicao indicada pela tabela IP,do bloco inicial
		permut=(permut<<1)|aux;				//vai adicionando os bits permutados(obtidos anteriormente) ao bloco permutado
	}

	l_prev = permut>>32;					//guarda os 32 bits mais significativos
	r_prev = permut&0xffffffff;				//guarda os 32 bits menos significativos

	for (i=0; i<16; i++)
	{
		r_next = l_prev^f_transform(r_prev, subKeys[i]);	//guarda no proximo bloco rigth, um xor do bloco anterior left com o bloco rigth anterior tranformado
															// pela funcao f com a chave ki 
		l_next=r_prev;										//iguala o proximo bloco left ao bloco rigth anterior 
		
		l_prev = l_next;									//iguala o bloco anterior left ao proximo bloco left 
		r_prev = r_next;									//iguala o bloco anterior rigth ao proximo bloco rigth 
	}

	final_swap = r_next;									//irregular swap, coloca o ultimo bloco rigth no bloco final
	final_swap = (final_swap<<32)|l_next;					//coloca a seguir o bloco left no bloco final

	//permutacao final do bloco de 64 bits, de acordo com a tabela IP-1
	aux=0;
	for(i=0;i<64;i++)
	{
		aux=final_swap;
		aux=aux>>(64-ip_1[i])&0x01;
		output=(output<<1)|aux;
	}
	
	return output;							//devolve o bloco de 64 bits, encriptado com DES
}


// função para gerar sub-keys (uma chave para cada uma das 16 iterações)
void DESKeySchedule(unsigned long long key, unsigned long long* subKeys)
{	//tabelas de permutacao PC1 para os blocos Ci,PC1 para os blocos Di,PC2 para a geracao da chave Ki
	int pc1c[]={57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36};
	int pc1d[]={63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
	int pc2[]={14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
	int vi[]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};						//definicao dos shift's circulares a realizar
	unsigned long long ci=0,di=0,c_aux=0,d_aux=0,shift_aux=0;
	unsigned long long ki=0,ki_aux=0;
	int i,j,z;
	
	//geracao das duas sequencias iniciais de 28 bits,C0 e D0, permutadas de acordo com a tabela PC1
	for(i=0;i<28;i++)
	{
		c_aux=key;								//guarda a chave inicial
		c_aux=c_aux>>(64-pc1c[i])&0x01;			//guarda o bit que esta na posicao indicada pela tabela PC1c,da chave inicial
		ci=(ci<<1)|c_aux;						//vai adicionando os bits permutados(obtidos anteriormente) ao bloco ci
		
		
		d_aux=key;								
		d_aux=d_aux>>(64-pc1d[i])&0x01;			
		di=(di<<1)|d_aux;						
		
	}
	
	//geracao das 16 sub-chaves
	for(i=0;i<16;i++)
	{
		//shift circular
		for(j=0;j<vi[i];j++)		
		{
			shift_aux=ci>>27;						//guarda o bit mais significativo
			ci=((ci<<1)|shift_aux)&0x0fffffff;		//adiciona o bit ao fim e descarta o primeiro bit
				
			shift_aux=di>>27;						
			di=((di<<1)|shift_aux)&0x0fffffff;		
		}
		
		ki_aux=(ci<<28)|di;							//concatena as duas sequencias						
		
		//permutacao de ki de acordo com a tabela PC2
		for(z=0;z<48;z++)
		{
			c_aux=ki_aux;
			c_aux=c_aux>>(56-pc2[z])&0x01;
			ki=(ki<<1)|c_aux;				
		}
		
		subKeys[i]=ki;							//adiciona ki ao vector de subkeys
		ki=0;									//volta a reniciar ki para receber uma nova chave
	}
	
}

unsigned int f_transform(unsigned int ri, unsigned long long ki)
{	// tabela E da funcao de expansao, e tabela P de permutacao
	int e[] = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
	int p[] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
	unsigned int i, subst=0, f_final=0;
	unsigned long long aux=0, exp=0;
	

	
	for(i=0; i<48; i++)
	{
		aux=ri;							//guarda a o bloco anterior de entrada, de 32 bits R(i-1)
		aux=aux>>(32-e[i])&0x01;		//guarda o bit que esta na posicao indicada pela tabela E,do bloco R(i-1)
		exp=(exp<<1)|aux;				//vai adicionando os bits (obtidos anteriormente) ao bloco extendido para 48 bits
	}

	exp=exp^ki;							//executa um ou exclusivo(xor) com a chave de entrada, ki de 48 bits

	aux=0;
	for(i=0; i<8; i++)					//tranformacao dos 8 blocos de 6 bits em 8 blocos de 4 bits 
	{
		aux=exp;								//guarda o bloco extendido
		aux=aux>>(48-(6*(i+1)))&0x3f;			//guarda os 6 bits de cada bloco de 8 bits
		subst=(subst<<4)|s_boxes(aux, i);		//cria um novo bloco de 4 bits passando os 6 bits pela s-box correspondente a ordem do bloco 
	}
	
	//permutacao do bloco de 32 bits, de acordo com a tabela P
	aux=0;
	for(i=0; i<32; i++)
	{
		aux=subst;
		aux=aux>>(32-p[i])&0x01;
		f_final=(f_final<<1)|aux;
	}
	
	return f_final;					//devolve o bloco R(i-1) de 32 bits tranformado
	
}

unsigned int s_boxes(unsigned int block_in, int indice)
{
	unsigned int r, c;			//As S-boxes do Des
	char s[8][4][16] ={{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
					   {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
					   {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
					   {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
					   {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
					   {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
					   {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
					   {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};
	
	
	r = 2*(block_in>>5) + (block_in&0x01);			//calcula r de acordo com a formula: r=2.b1+b6   
	c = (block_in>>1)&0x0f;							//calcula c de acordo com a formula: c=b2b3b4b5
	
	return s[indice][r][c];							//devolve o valor dado pelas duas coordenadas, na box dada pelo indice(0...7)
	
}



// funcao para criacao de de uma hash a partir dos dados do ficheiro, usando MDC-4
void signature(unsigned char* inByteArray, long dim, unsigned long long key, unsigned char* hash)
{
	int i=0,j,k;
	unsigned long long plain[2], out[2], gi[2];
	
	gi[0] = 0x5252525252525252;							//constantes iniciais g e 'g
	gi[1] = 0x2525252525252525;

	while (i < dim)										//le blocos de 64 bits do ficheiro(inByteArray)
	{	
		plain[0] = 0;
		plain[1] = 0;
		j = i;
		for(k=0; k<2; k++) { 							//le duas vezes, ou seja dois blocos de 64 bits
			while (j < i + 8 && j < dim)
			{
				plain[k] = plain[k] | ((unsigned long long)inByteArray[j] << (64 - 8*(j-i+1)));
				j++;
			}
			i = j;	
		}

		mdc2(plain[0], plain[1], gi[0], gi[1], out);	//aplica o mdc2 ao primeiro bloco
		mdc2(gi[1], gi[0], out[0], out[1], out); 		//aplica o mdc2 ao segundo bloco
		
		gi[0]=out[0];									//actualiza os outputs
		gi[1]=out[1];

	}
	k=15;
	for(j=1; j>=0; j--)									//guarda o hash final criado no array passado na entrada (16 bytes de hash)
		for (i=7; i>=0; i--) {
			hash[k--] = gi[j]& 0xff;
			gi[j] = gi[j] >> 8;
		}

}


//funcao para verificacao da assinatura: verificar se a hash criada a partir dos dados Ž igual 'a hash recebida
int checkSignature(unsigned char* inByteArray,long dim,unsigned long long key, unsigned char* hash)
{
	unsigned char hash_true[16];
	int i, contador=0;

	signature(inByteArray, dim , key, hash_true);					//gera um novo hash do ficheiro original

	for(i=0;i<16;i++)
	{
		if(hash_true[i]==hash[i])									//verifica se o hash do ficheiro original,e' igual ao hash presente no fim do ficheiro
			contador++;
	}

	if(contador==16) {
		return 1;
	}
	return 0;
}


void mdc2(unsigned long long in1, unsigned long long in2, unsigned long long in3, unsigned long long in4, unsigned long long* output)
{
	unsigned long long ci1, ci2;
	
	ci1 = mmo(in1, in3, 0);		//aplica a funcao de Matyas-Meyer-Oseas aos bloco de  entrada in1 e in3(funcao g)
	ci2 = mmo(in2, in4, 1);		//aplica a funcao de Matyas-Meyer-Oseas aos bloco de  entrada in2 e in4(funcao 'g)
	
	output[0] = ((ci1&0xffffffff00000000)|(ci2 & 0xffffffff));		//primeiro output vai ser igual aos primeiros 32 bits de ci1(A) mais os ultimos 32 bits de ci2(D)
	output[1] = ((ci2&0xffffffff00000000)|(ci1 & 0xffffffff));		//segundo output vai ser igual aos primeiros 32 bits de ci2(C) mais os ultimos 32 bits de ci1(B)
	
	
}
//Algoritmo de Matyas-Meyer-Oseas
unsigned long long mmo(unsigned long long in1_2, unsigned long long in3_4, int flag_g)
{	
	//ignorou-se o descarte dos bits de paridade porque o proprio algoritmo do DES, descarta os bits de paridade
	unsigned long long subKeys[16];
	
	if (flag_g == 0) {							//se a flag estiver a zero entao pretende-se alterar o 2 e 3 bit para 10(funcao g)
		in3_4 = in3_4 | 0x4000000000000000;		//altera o 2 bit para 1
		in3_4 = in3_4 & 0xdfffffffffffffff;		//altera o 3 bit para 0
		
		DESKeySchedule(in3_4, subKeys);			//gera um array de 6 subkeys de acordo com a chave inicial in3_4
		return ( in1_2 ^ encryptDESplain(in1_2, subKeys) );		//devolve um xor entre a aplicao do DES a' entrada in1_2 com a propria entrada in1_2
	}
	
	else {										//se a flag nao estiver a zero entao pretende-se alterar o 2 e 3 bit para 01(funcao 'g)
		in3_4 = in3_4 | 0x2000000000000000;		//altera o 3 bit para 1
		in3_4 = in3_4 & 0xbfffffffffffffff;		//altera o 2 bit para 0
	
		DESKeySchedule(in3_4, subKeys);			//gera um array de 6 subkeys de acordo com a chave inicial in3_4
		return ( in1_2 ^ encryptDESplain(in1_2, subKeys) );		//devolve um xor entre a aplicao do DES a' entrada in1_2 com a propria entrada in1_2
	}
}
