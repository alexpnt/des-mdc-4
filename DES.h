/*Author: Rui Pedro Paiva
Teoria da Informação, LEI, 2008/2009*/
// Alterado por:
// Alexandre Rui Santos Fonseca Pinto 2010131853
// Carlos Miguel Rosa Avim 2000104864*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <math.h>

unsigned char* encryptDES(unsigned char* inByteArray, long dim, unsigned long long key, int type);
unsigned long long encryptDESplain(unsigned long long plain, unsigned long long* subKeys);
void DESKeySchedule(unsigned long long key, unsigned long long* subKeys);
int DESgeneral (char* inFileName, unsigned long long key, int type);
void signature(unsigned char* inByteArray, long dim, unsigned long long key,unsigned char*);
int checkSignature(unsigned char* inByteArray,long dim,unsigned long long key, unsigned char* hash);

int DES (char* inFileName, unsigned long long key);
int unDES (char* inFileName, unsigned long long key);

unsigned int f_transform(unsigned int ri, unsigned long long ki);
unsigned int s_boxes(unsigned int block_in, int indice);

unsigned long long mmo(unsigned long long in1_2, unsigned long long in3_4, int flag_g);
void mdc2(unsigned long long in1, unsigned long long in2, unsigned long long in3, unsigned long long in4,unsigned long long*);

