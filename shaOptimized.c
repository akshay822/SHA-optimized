/* sha.c
 * Yongge Wang 
 *
 * Code was written: November 12, 2016-November 26, 2016
 *
 * sha.c implements SHA-1 (SHA-160), SHA256, and SHA512 for RLCE
 *
 * This code is for prototype purpose only and is not optimized
 *
 * Copyright (C) 2016 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTR(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define Sigma1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

#define ROTL512(a,b) (((a) << (b)) | ((a) >> (64-(b))))
#define ROTR512(a,b) (((a) >> (b)) | ((a) << (64-(b))))
#define sigma5120(x) (ROTR512(x,1) ^ ROTR512(x,8) ^ ((x) >> 7))
#define sigma5121(x) (ROTR512(x,19) ^ ROTR512(x,61) ^ ((x) >> 6))
#define Sigma5120(x) (ROTR512(x,28) ^ ROTR512(x,34) ^ ROTR512(x,39))
#define Sigma5121(x) (ROTR512(x,14) ^ ROTR512(x,18) ^ ROTR512(x,41))

void sha1_process(unsigned int[], unsigned char[]);
void sha256_process(unsigned int[], unsigned char[]);
void sha512_process(unsigned long [], unsigned char []);
int testSHA(int shatype, int numT);

int main (int argc, char *argv[]) {
  int numofT=100;
  testSHA(1,numofT);
  testSHA(2,numofT);
  testSHA(3,numofT);
  exit(0);
}


void sha_msg_pad(unsigned char message[], int size, unsigned int bitlen,
		 unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<size; i++) {
    paddedmsg[i]=message[i];
  }
  paddedmsg[size]= 0x80;
  for (i=size+1; i<60; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[63] = bitlen;
  paddedmsg[62] = bitlen >> 8;
  paddedmsg[61] = bitlen >> 16;
  paddedmsg[60] = bitlen >> 24;
  return;
}

void sha_msg_pad0(unsigned int bitlen, unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<60; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[63] = bitlen;
  paddedmsg[62] = bitlen >> 8;
  paddedmsg[61] = bitlen >> 16;
  paddedmsg[60] = bitlen >> 24;
  return;
}

void sha1_md(unsigned char message[], int size, unsigned int hash[5]) {
  unsigned int bitlen = 8*size;
  hash[0] = 0x67452301;
  hash[1] = 0xEFCDAB89;
  hash[2] = 0x98BADCFE;
  hash[3] = 0x10325476;
  hash[4] = 0xC3D2E1F0;
  int i;

  unsigned char msgTBH[64]; /* 64 BYTE msg to be hashed */
  unsigned char paddedMessage[64]; /* last msg block to be hashed*/

  int Q= size/64;
  int R= size%64;
  unsigned char msg[R];
  memcpy(msg, &message[64*Q], R * sizeof(unsigned char));
  
  for (i=0; i<Q; i++) {
    memcpy(msgTBH, &message[64*i], 64 * sizeof(unsigned char));
    sha1_process(hash, msgTBH);
  }
  if (R>55) {
    memcpy(msgTBH, msg, R * sizeof(unsigned char));
    msgTBH[R]=0x80;
    for (i=R+1; i<64; i++) {
      msgTBH[i]=0x00;
    } 
    sha1_process(hash, msgTBH);
    sha_msg_pad0(bitlen,paddedMessage);
  } else {
    sha_msg_pad(msg, R, bitlen, paddedMessage);
  }
  sha1_process(hash, paddedMessage);
  return;
}

void sha1_process(unsigned int hash[], unsigned char msg[]) {
  const unsigned int K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
  unsigned int W[80];
  unsigned int A, B, C, D, E, T;
  int i;
  
//   for(i = 0; i < 16; i++) {
//     W[i] = (((unsigned) msg[i * 4]) << 24) +
//       (((unsigned) msg[i * 4 + 1]) << 16) +
//       (((unsigned) msg[i * 4 + 2]) << 8) +
//       (((unsigned) msg[i * 4 + 3]));
//   }
//   for(i = 16; i < 80; i++) {
//     W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];W[i] = ROTL(W[i],1);
//   }

W[0]=(((unsigned) msg[0 * 4]) << 24)+(((unsigned) msg[0 * 4 + 1]) << 16)+(((unsigned) msg[0 * 4 + 2]) << 8)+(((unsigned) msg[0 * 4 + 3]));
W[1]=(((unsigned) msg[1 * 4]) << 24)+(((unsigned) msg[1 * 4 + 1]) << 16)+(((unsigned) msg[1 * 4 + 2]) << 8)+(((unsigned) msg[1 * 4 + 3]));
W[2]=(((unsigned) msg[2 * 4]) << 24)+(((unsigned) msg[2 * 4 + 1]) << 16)+(((unsigned) msg[2 * 4 + 2]) << 8)+(((unsigned) msg[2 * 4 + 3]));
W[3]=(((unsigned) msg[3 * 4]) << 24)+(((unsigned) msg[3 * 4 + 1]) << 16)+(((unsigned) msg[3 * 4 + 2]) << 8)+(((unsigned) msg[3 * 4 + 3]));
W[4]=(((unsigned) msg[4 * 4]) << 24)+(((unsigned) msg[4 * 4 + 1]) << 16)+(((unsigned) msg[4 * 4 + 2]) << 8)+(((unsigned) msg[4 * 4 + 3]));
W[5]=(((unsigned) msg[5 * 4]) << 24)+(((unsigned) msg[5 * 4 + 1]) << 16)+(((unsigned) msg[5 * 4 + 2]) << 8)+(((unsigned) msg[5 * 4 + 3]));
W[6]=(((unsigned) msg[6 * 4]) << 24)+(((unsigned) msg[6 * 4 + 1]) << 16)+(((unsigned) msg[6 * 4 + 2]) << 8)+(((unsigned) msg[6 * 4 + 3]));
W[7]=(((unsigned) msg[7 * 4]) << 24)+(((unsigned) msg[7 * 4 + 1]) << 16)+(((unsigned) msg[7 * 4 + 2]) << 8)+(((unsigned) msg[7 * 4 + 3]));
W[8]=(((unsigned) msg[8 * 4]) << 24)+(((unsigned) msg[8 * 4 + 1]) << 16)+(((unsigned) msg[8 * 4 + 2]) << 8)+(((unsigned) msg[8 * 4 + 3]));
W[9]=(((unsigned) msg[9 * 4]) << 24)+(((unsigned) msg[9 * 4 + 1]) << 16)+(((unsigned) msg[9 * 4 + 2]) << 8)+(((unsigned) msg[9 * 4 + 3]));
W[10]=(((unsigned) msg[10 * 4]) << 24)+(((unsigned) msg[10 * 4 + 1]) << 16)+(((unsigned) msg[10 * 4 + 2]) << 8)+(((unsigned) msg[10 * 4 + 3]));
W[11]=(((unsigned) msg[11 * 4]) << 24)+(((unsigned) msg[11 * 4 + 1]) << 16)+(((unsigned) msg[11 * 4 + 2]) << 8)+(((unsigned) msg[11 * 4 + 3]));
W[12]=(((unsigned) msg[12 * 4]) << 24)+(((unsigned) msg[12 * 4 + 1]) << 16)+(((unsigned) msg[12 * 4 + 2]) << 8)+(((unsigned) msg[12 * 4 + 3]));
W[13]=(((unsigned) msg[13 * 4]) << 24)+(((unsigned) msg[13 * 4 + 1]) << 16)+(((unsigned) msg[13 * 4 + 2]) << 8)+(((unsigned) msg[13 * 4 + 3]));
W[14]=(((unsigned) msg[14 * 4]) << 24)+(((unsigned) msg[14 * 4 + 1]) << 16)+(((unsigned) msg[14 * 4 + 2]) << 8)+(((unsigned) msg[14 * 4 + 3]));
W[15]=(((unsigned) msg[15 * 4]) << 24)+(((unsigned) msg[15 * 4 + 1]) << 16)+(((unsigned) msg[15 * 4 + 2]) << 8)+(((unsigned) msg[15 * 4 + 3]));

W[16] = W[16-3] ^ W[16-8] ^ W[16-14] ^ W[16-16];W[16] = ROTL(W[16],1);
W[17] = W[17-3] ^ W[17-8] ^ W[17-14] ^ W[17-16];W[17] = ROTL(W[17],1);
W[18] = W[18-3] ^ W[18-8] ^ W[18-14] ^ W[18-16];W[18] = ROTL(W[18],1);
W[19] = W[19-3] ^ W[19-8] ^ W[19-14] ^ W[19-16];W[19] = ROTL(W[19],1);
W[20] = W[20-3] ^ W[20-8] ^ W[20-14] ^ W[20-16];W[20] = ROTL(W[20],1);
W[21] = W[21-3] ^ W[21-8] ^ W[21-14] ^ W[21-16];W[21] = ROTL(W[21],1);
W[22] = W[22-3] ^ W[22-8] ^ W[22-14] ^ W[22-16];W[22] = ROTL(W[22],1);
W[23] = W[23-3] ^ W[23-8] ^ W[23-14] ^ W[23-16];W[23] = ROTL(W[23],1);
W[24] = W[24-3] ^ W[24-8] ^ W[24-14] ^ W[24-16];W[24] = ROTL(W[24],1);
W[25] = W[25-3] ^ W[25-8] ^ W[25-14] ^ W[25-16];W[25] = ROTL(W[25],1);
W[26] = W[26-3] ^ W[26-8] ^ W[26-14] ^ W[26-16];W[26] = ROTL(W[26],1);
W[27] = W[27-3] ^ W[27-8] ^ W[27-14] ^ W[27-16];W[27] = ROTL(W[27],1);
W[28] = W[28-3] ^ W[28-8] ^ W[28-14] ^ W[28-16];W[28] = ROTL(W[28],1);
W[29] = W[29-3] ^ W[29-8] ^ W[29-14] ^ W[29-16];W[29] = ROTL(W[29],1);
W[30] = W[30-3] ^ W[30-8] ^ W[30-14] ^ W[30-16];W[30] = ROTL(W[30],1);
W[31] = W[31-3] ^ W[31-8] ^ W[31-14] ^ W[31-16];W[31] = ROTL(W[31],1);
W[32] = W[32-3] ^ W[32-8] ^ W[32-14] ^ W[32-16];W[32] = ROTL(W[32],1);
W[33] = W[33-3] ^ W[33-8] ^ W[33-14] ^ W[33-16];W[33] = ROTL(W[33],1);
W[34] = W[34-3] ^ W[34-8] ^ W[34-14] ^ W[34-16];W[34] = ROTL(W[34],1);
W[35] = W[35-3] ^ W[35-8] ^ W[35-14] ^ W[35-16];W[35] = ROTL(W[35],1);
W[36] = W[36-3] ^ W[36-8] ^ W[36-14] ^ W[36-16];W[36] = ROTL(W[36],1);
W[37] = W[37-3] ^ W[37-8] ^ W[37-14] ^ W[37-16];W[37] = ROTL(W[37],1);
W[38] = W[38-3] ^ W[38-8] ^ W[38-14] ^ W[38-16];W[38] = ROTL(W[38],1);
W[39] = W[39-3] ^ W[39-8] ^ W[39-14] ^ W[39-16];W[39] = ROTL(W[39],1);
W[40] = W[40-3] ^ W[40-8] ^ W[40-14] ^ W[40-16];W[40] = ROTL(W[40],1);
W[41] = W[41-3] ^ W[41-8] ^ W[41-14] ^ W[41-16];W[41] = ROTL(W[41],1);
W[42] = W[42-3] ^ W[42-8] ^ W[42-14] ^ W[42-16];W[42] = ROTL(W[42],1);
W[43] = W[43-3] ^ W[43-8] ^ W[43-14] ^ W[43-16];W[43] = ROTL(W[43],1);
W[44] = W[44-3] ^ W[44-8] ^ W[44-14] ^ W[44-16];W[44] = ROTL(W[44],1);
W[45] = W[45-3] ^ W[45-8] ^ W[45-14] ^ W[45-16];W[45] = ROTL(W[45],1);
W[46] = W[46-3] ^ W[46-8] ^ W[46-14] ^ W[46-16];W[46] = ROTL(W[46],1);
W[47] = W[47-3] ^ W[47-8] ^ W[47-14] ^ W[47-16];W[47] = ROTL(W[47],1);
W[48] = W[48-3] ^ W[48-8] ^ W[48-14] ^ W[48-16];W[48] = ROTL(W[48],1);
W[49] = W[49-3] ^ W[49-8] ^ W[49-14] ^ W[49-16];W[49] = ROTL(W[49],1);
W[50] = W[50-3] ^ W[50-8] ^ W[50-14] ^ W[50-16];W[50] = ROTL(W[50],1);
W[51] = W[51-3] ^ W[51-8] ^ W[51-14] ^ W[51-16];W[51] = ROTL(W[51],1);
W[52] = W[52-3] ^ W[52-8] ^ W[52-14] ^ W[52-16];W[52] = ROTL(W[52],1);
W[53] = W[53-3] ^ W[53-8] ^ W[53-14] ^ W[53-16];W[53] = ROTL(W[53],1);
W[54] = W[54-3] ^ W[54-8] ^ W[54-14] ^ W[54-16];W[54] = ROTL(W[54],1);
W[55] = W[55-3] ^ W[55-8] ^ W[55-14] ^ W[55-16];W[55] = ROTL(W[55],1);
W[56] = W[56-3] ^ W[56-8] ^ W[56-14] ^ W[56-16];W[56] = ROTL(W[56],1);
W[57] = W[57-3] ^ W[57-8] ^ W[57-14] ^ W[57-16];W[57] = ROTL(W[57],1);
W[58] = W[58-3] ^ W[58-8] ^ W[58-14] ^ W[58-16];W[58] = ROTL(W[58],1);
W[59] = W[59-3] ^ W[59-8] ^ W[59-14] ^ W[59-16];W[59] = ROTL(W[59],1);
W[60] = W[60-3] ^ W[60-8] ^ W[60-14] ^ W[60-16];W[60] = ROTL(W[60],1);
W[61] = W[61-3] ^ W[61-8] ^ W[61-14] ^ W[61-16];W[61] = ROTL(W[61],1);
W[62] = W[62-3] ^ W[62-8] ^ W[62-14] ^ W[62-16];W[62] = ROTL(W[62],1);
W[63] = W[63-3] ^ W[63-8] ^ W[63-14] ^ W[63-16];W[63] = ROTL(W[63],1);
W[64] = W[64-3] ^ W[64-8] ^ W[64-14] ^ W[64-16];W[64] = ROTL(W[64],1);
W[65] = W[65-3] ^ W[65-8] ^ W[65-14] ^ W[65-16];W[65] = ROTL(W[65],1);
W[66] = W[66-3] ^ W[66-8] ^ W[66-14] ^ W[66-16];W[66] = ROTL(W[66],1);
W[67] = W[67-3] ^ W[67-8] ^ W[67-14] ^ W[67-16];W[67] = ROTL(W[67],1);
W[68] = W[68-3] ^ W[68-8] ^ W[68-14] ^ W[68-16];W[68] = ROTL(W[68],1);
W[69] = W[69-3] ^ W[69-8] ^ W[69-14] ^ W[69-16];W[69] = ROTL(W[69],1);
W[70] = W[70-3] ^ W[70-8] ^ W[70-14] ^ W[70-16];W[70] = ROTL(W[70],1);
W[71] = W[71-3] ^ W[71-8] ^ W[71-14] ^ W[71-16];W[71] = ROTL(W[71],1);
W[72] = W[72-3] ^ W[72-8] ^ W[72-14] ^ W[72-16];W[72] = ROTL(W[72],1);
W[73] = W[73-3] ^ W[73-8] ^ W[73-14] ^ W[73-16];W[73] = ROTL(W[73],1);
W[74] = W[74-3] ^ W[74-8] ^ W[74-14] ^ W[74-16];W[74] = ROTL(W[74],1);
W[75] = W[75-3] ^ W[75-8] ^ W[75-14] ^ W[75-16];W[75] = ROTL(W[75],1);
W[76] = W[76-3] ^ W[76-8] ^ W[76-14] ^ W[76-16];W[76] = ROTL(W[76],1);
W[77] = W[77-3] ^ W[77-8] ^ W[77-14] ^ W[77-16];W[77] = ROTL(W[77],1);
W[78] = W[78-3] ^ W[78-8] ^ W[78-14] ^ W[78-16];W[78] = ROTL(W[78],1);
W[79] = W[79-3] ^ W[79-8] ^ W[79-14] ^ W[79-16];W[79] = ROTL(W[79],1);

  A = hash[0];
  B = hash[1];
  C = hash[2];
  D = hash[3];
  E = hash[4];
  
  
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[0] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[1] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[2] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[3] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[4] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[5] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[6] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[7] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[8] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[9] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[10] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[11] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[12] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[13] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[14] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[15] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[16] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[17] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[18] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[19] + K[0];E = D;D = C;C = ROTL(B, 30);B = A;A = T;


T = ROTL(A,5) + (B^C^D) + E + W[20] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[21] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[22] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[23] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[24] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[25] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[26] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[27] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[28] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[29] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[30] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[31] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[32] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[33] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[34] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[35] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[36] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[37] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[38] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B^C^D) + E + W[39] + K[1];E = D;D = C;C = ROTL(B, 30);B = A;A = T;


T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[40] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[41] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[42] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[43] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[44] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[45] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[46] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[47] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[48] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[49] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[50] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[51] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[52] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[53] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[54] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[55] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[56] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[57] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[58] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[59] + K[2];E = D;D = C;C = ROTL(B, 30);B = A;A = T;


T = ROTL(A,5) + (B ^ C ^ D) + E + W[60] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[61] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[62] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[63] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[64] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[65] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[66] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[67] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[68] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[69] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[70] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[71] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;                                                                        
T = ROTL(A,5) + (B ^ C ^ D) + E + W[72] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[73] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[74] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[75] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[76] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[77] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[78] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;
T = ROTL(A,5) + (B ^ C ^ D) + E + W[79] + K[3];E = D;D = C;C = ROTL(B, 30);B = A;A = T;

  hash[0] +=  A;
  hash[1] +=  B;
  hash[2] +=  C;
  hash[3] +=  D;
  hash[4] +=  E;

  return;
}

void sha256_md(unsigned char message[], int size, unsigned int hash[8]) {
  unsigned int bitlen = 8*size;
  hash[0] = 0x6A09E667;  
  hash[1] = 0xBB67AE85;
  hash[2] = 0x3C6EF372;  
  hash[3] = 0xA54FF53A;  
  hash[4] = 0x510E527F;
  hash[5] = 0x9B05688C;
  hash[6] = 0x1F83D9AB;
  hash[7] = 0x5BE0CD19;
  
  unsigned char msgTBH[64]; /* 64 BYTE msg to be hashed */
  unsigned char paddedMessage[64]; /* last msg block to be hashed*/
  int i;
  int Q= size/64;
  int R= size%64;
  unsigned char msg[R];
  memcpy(msg, &message[64*Q], R * sizeof(unsigned char));
  
  for (i=0; i<Q; i++) {
    memcpy(msgTBH, &message[64*i], 64 * sizeof(unsigned char));
    sha256_process(hash, msgTBH);
  }
  if (R>55) {
    memcpy(msgTBH, msg, R * sizeof(unsigned char));
    msgTBH[R]=0x80;
    for (i=R+1; i<64; i++) {
      msgTBH[i]=0x00;
    }
    sha256_process(hash, msgTBH);
    sha_msg_pad0(bitlen,paddedMessage);
  } else {
    sha_msg_pad(msg, R, bitlen, paddedMessage);
  }
 
  sha256_process(hash, paddedMessage);
  return;
}

void sha256_process(unsigned int hash[], unsigned char msg[]) {
  const unsigned int K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
  unsigned int W[64];
  int i;
  unsigned int A, B, C, D, E, F, G, H, T1, T2;

W[0] = (((unsigned) msg[0 * 4]) << 24) | (((unsigned) msg[0 * 4 + 1]) << 16) | (((unsigned) msg[0 * 4 + 2]) << 8) | (((unsigned) msg[0 * 4 + 3]));
W[1] = (((unsigned) msg[1 * 4]) << 24) | (((unsigned) msg[1 * 4 + 1]) << 16) | (((unsigned) msg[1 * 4 + 2]) << 8) | (((unsigned) msg[1 * 4 + 3]));
W[2] = (((unsigned) msg[2 * 4]) << 24) | (((unsigned) msg[2 * 4 + 1]) << 16) | (((unsigned) msg[2 * 4 + 2]) << 8) | (((unsigned) msg[2 * 4 + 3]));
W[3] = (((unsigned) msg[3 * 4]) << 24) | (((unsigned) msg[3 * 4 + 1]) << 16) | (((unsigned) msg[3 * 4 + 2]) << 8) | (((unsigned) msg[3 * 4 + 3]));
W[4] = (((unsigned) msg[4 * 4]) << 24) | (((unsigned) msg[4 * 4 + 1]) << 16) | (((unsigned) msg[4 * 4 + 2]) << 8) | (((unsigned) msg[4 * 4 + 3]));
W[5] = (((unsigned) msg[5 * 4]) << 24) | (((unsigned) msg[5 * 4 + 1]) << 16) | (((unsigned) msg[5 * 4 + 2]) << 8) | (((unsigned) msg[5 * 4 + 3]));
W[6] = (((unsigned) msg[6 * 4]) << 24) | (((unsigned) msg[6 * 4 + 1]) << 16) | (((unsigned) msg[6 * 4 + 2]) << 8) | (((unsigned) msg[6 * 4 + 3]));
W[7] = (((unsigned) msg[7 * 4]) << 24) | (((unsigned) msg[7 * 4 + 1]) << 16) | (((unsigned) msg[7 * 4 + 2]) << 8) | (((unsigned) msg[7 * 4 + 3]));
W[8] = (((unsigned) msg[8 * 4]) << 24) | (((unsigned) msg[8 * 4 + 1]) << 16) | (((unsigned) msg[8 * 4 + 2]) << 8) | (((unsigned) msg[8 * 4 + 3]));
W[9] = (((unsigned) msg[9 * 4]) << 24) | (((unsigned) msg[9 * 4 + 1]) << 16) | (((unsigned) msg[9 * 4 + 2]) << 8) | (((unsigned) msg[9 * 4 + 3]));
W[10] = (((unsigned) msg[10 * 4]) << 24) | (((unsigned) msg[10 * 4 + 1]) << 16) | (((unsigned) msg[10 * 4 + 2]) << 8) | (((unsigned) msg[10 * 4 + 3]));
W[11] = (((unsigned) msg[11 * 4]) << 24) | (((unsigned) msg[11 * 4 + 1]) << 16) | (((unsigned) msg[11 * 4 + 2]) << 8) | (((unsigned) msg[11 * 4 + 3]));
W[12] = (((unsigned) msg[12 * 4]) << 24) | (((unsigned) msg[12 * 4 + 1]) << 16) | (((unsigned) msg[12 * 4 + 2]) << 8) | (((unsigned) msg[12 * 4 + 3]));
W[13] = (((unsigned) msg[13 * 4]) << 24) | (((unsigned) msg[13 * 4 + 1]) << 16) | (((unsigned) msg[13 * 4 + 2]) << 8) | (((unsigned) msg[13 * 4 + 3]));
W[14] = (((unsigned) msg[14 * 4]) << 24) | (((unsigned) msg[14 * 4 + 1]) << 16) | (((unsigned) msg[14 * 4 + 2]) << 8) | (((unsigned) msg[14 * 4 + 3]));
W[15] = (((unsigned) msg[15 * 4]) << 24) | (((unsigned) msg[15 * 4 + 1]) << 16) | (((unsigned) msg[15 * 4 + 2]) << 8) | (((unsigned) msg[15 * 4 + 3]));

W[16] = sigma1(W[16-2])+W[16-7]+sigma0(W[16-15])+ W[16-16];
W[17] = sigma1(W[17-2])+W[17-7]+sigma0(W[17-15])+ W[17-16];
W[18] = sigma1(W[18-2])+W[18-7]+sigma0(W[18-15])+ W[18-16];
W[19] = sigma1(W[19-2])+W[19-7]+sigma0(W[19-15])+ W[19-16];
W[20] = sigma1(W[20-2])+W[20-7]+sigma0(W[20-15])+ W[20-16];
W[21] = sigma1(W[21-2])+W[21-7]+sigma0(W[21-15])+ W[21-16];
W[22] = sigma1(W[22-2])+W[22-7]+sigma0(W[22-15])+ W[22-16];
W[23] = sigma1(W[23-2])+W[23-7]+sigma0(W[23-15])+ W[23-16];
W[24] = sigma1(W[24-2])+W[24-7]+sigma0(W[24-15])+ W[24-16];
W[25] = sigma1(W[25-2])+W[25-7]+sigma0(W[25-15])+ W[25-16];
W[26] = sigma1(W[26-2])+W[26-7]+sigma0(W[26-15])+ W[26-16];
W[27] = sigma1(W[27-2])+W[27-7]+sigma0(W[27-15])+ W[27-16];
W[28] = sigma1(W[28-2])+W[28-7]+sigma0(W[28-15])+ W[28-16];
W[29] = sigma1(W[29-2])+W[29-7]+sigma0(W[29-15])+ W[29-16];
W[30] = sigma1(W[30-2])+W[30-7]+sigma0(W[30-15])+ W[30-16];
W[31] = sigma1(W[31-2])+W[31-7]+sigma0(W[31-15])+ W[31-16];
W[32] = sigma1(W[32-2])+W[32-7]+sigma0(W[32-15])+ W[32-16];
W[33] = sigma1(W[33-2])+W[33-7]+sigma0(W[33-15])+ W[33-16];
W[34] = sigma1(W[34-2])+W[34-7]+sigma0(W[34-15])+ W[34-16];
W[35] = sigma1(W[35-2])+W[35-7]+sigma0(W[35-15])+ W[35-16];
W[36] = sigma1(W[36-2])+W[36-7]+sigma0(W[36-15])+ W[36-16];
W[37] = sigma1(W[37-2])+W[37-7]+sigma0(W[37-15])+ W[37-16];
W[38] = sigma1(W[38-2])+W[38-7]+sigma0(W[38-15])+ W[38-16];
W[39] = sigma1(W[39-2])+W[39-7]+sigma0(W[39-15])+ W[39-16];
W[40] = sigma1(W[40-2])+W[40-7]+sigma0(W[40-15])+ W[40-16];
W[41] = sigma1(W[41-2])+W[41-7]+sigma0(W[41-15])+ W[41-16];
W[42] = sigma1(W[42-2])+W[42-7]+sigma0(W[42-15])+ W[42-16];
W[43] = sigma1(W[43-2])+W[43-7]+sigma0(W[43-15])+ W[43-16];
W[44] = sigma1(W[44-2])+W[44-7]+sigma0(W[44-15])+ W[44-16];
W[45] = sigma1(W[45-2])+W[45-7]+sigma0(W[45-15])+ W[45-16];
W[46] = sigma1(W[46-2])+W[46-7]+sigma0(W[46-15])+ W[46-16];
W[47] = sigma1(W[47-2])+W[47-7]+sigma0(W[47-15])+ W[47-16];
W[48] = sigma1(W[48-2])+W[48-7]+sigma0(W[48-15])+ W[48-16];
W[49] = sigma1(W[49-2])+W[49-7]+sigma0(W[49-15])+ W[49-16];
W[50] = sigma1(W[50-2])+W[50-7]+sigma0(W[50-15])+ W[50-16];
W[51] = sigma1(W[51-2])+W[51-7]+sigma0(W[51-15])+ W[51-16];
W[52] = sigma1(W[52-2])+W[52-7]+sigma0(W[52-15])+ W[52-16];
W[53] = sigma1(W[53-2])+W[53-7]+sigma0(W[53-15])+ W[53-16];
W[54] = sigma1(W[54-2])+W[54-7]+sigma0(W[54-15])+ W[54-16];
W[55] = sigma1(W[55-2])+W[55-7]+sigma0(W[55-15])+ W[55-16];
W[56] = sigma1(W[56-2])+W[56-7]+sigma0(W[56-15])+ W[56-16];
W[57] = sigma1(W[57-2])+W[57-7]+sigma0(W[57-15])+ W[57-16];
W[58] = sigma1(W[58-2])+W[58-7]+sigma0(W[58-15])+ W[58-16];
W[59] = sigma1(W[59-2])+W[59-7]+sigma0(W[59-15])+ W[59-16];
W[60] = sigma1(W[60-2])+W[60-7]+sigma0(W[60-15])+ W[60-16];
W[61] = sigma1(W[61-2])+W[61-7]+sigma0(W[61-15])+ W[61-16];
W[62] = sigma1(W[62-2])+W[62-7]+sigma0(W[62-15])+ W[62-16];
W[63] = sigma1(W[63-2])+W[63-7]+sigma0(W[63-15])+ W[63-16];

  A = hash[0];
  B = hash[1];
  C = hash[2];
  D = hash[3];
  E = hash[4];
  F = hash[5];
  G = hash[6];
  H = hash[7];


T1 = H + Sigma1(E) + CH(E,F,G) + K[0] + W[0];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[1] + W[1];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[2] + W[2];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[3] + W[3];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[4] + W[4];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[5] + W[5];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[6] + W[6];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[7] + W[7];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[8] + W[8];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[9] + W[9];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[10] + W[10];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[11] + W[11];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[12] + W[12];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[13] + W[13];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[14] + W[14];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[15] + W[15];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[16] + W[16];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[17] + W[17];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[18] + W[18];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[19] + W[19];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[20] + W[20];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[21] + W[21];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[22] + W[22];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[23] + W[23];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[24] + W[24];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[25] + W[25];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[26] + W[26];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[27] + W[27];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[28] + W[28];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[29] + W[29];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[30] + W[30];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[31] + W[31];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[32] + W[32];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[33] + W[33];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[34] + W[34];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[35] + W[35];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[36] + W[36];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[37] + W[37];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[38] + W[38];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[39] + W[39];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[40] + W[40];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[41] + W[41];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[42] + W[42];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[43] + W[43];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[44] + W[44];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[45] + W[45];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[46] + W[46];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[47] + W[47];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[48] + W[48];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[49] + W[49];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[50] + W[50];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[51] + W[51];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[52] + W[52];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[53] + W[53];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[54] + W[54];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[55] + W[55];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[56] + W[56];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[57] + W[57];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[58] + W[58];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[59] + W[59];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[60] + W[60];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[61] + W[61];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[62] + W[62];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma1(E) + CH(E,F,G) + K[63] + W[63];T2 = Sigma0(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
  
  hash[0] +=A;
  hash[1] +=B;
  hash[2] +=C;
  hash[3] +=D;
  hash[4] +=E;
  hash[5] +=F;
  hash[6] +=G;
  hash[7] +=H;
  return;
}


void sha512_msg_pad(unsigned char message[], int size, unsigned int bitlen, unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<size; i++) {
    paddedmsg[i]=message[i];
  }
  paddedmsg[size]= 0x80;
  for (i=size+1; i<124; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[127] = bitlen;
  paddedmsg[126] = bitlen >> 8;
  paddedmsg[125] = bitlen >> 16;
  paddedmsg[124] = bitlen >> 24;
  return;
}

void sha512_msg_pad0(unsigned int bitlen, unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<124; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[127] = bitlen;
  paddedmsg[126] = bitlen >> 8;
  paddedmsg[125] = bitlen >> 16;
  paddedmsg[124] = bitlen >> 24;
  return;
}


void sha512_md(unsigned char message[], int size, unsigned long hash[8]) {
  unsigned int bitlen = 8*size;
  hash[0] = 0x6a09e667f3bcc908;
  hash[1] = 0xbb67ae8584caa73b;
  hash[2] = 0x3c6ef372fe94f82b;
  hash[3] = 0xa54ff53a5f1d36f1;
  hash[4] = 0x510e527fade682d1;
  hash[5] = 0x9b05688c2b3e6c1f;
  hash[6] = 0x1f83d9abfb41bd6b;
  hash[7] = 0x5be0cd19137e2179;
  
  unsigned char msgTBH[128]; /* 128 BYTE msg to be hashed */
  unsigned char paddedMessage[128]; /* last msg block to be hashed*/
  
  int Q= size/128;
  int R= size%128;
  unsigned char msg[R];
  memcpy(msg, &message[128*Q], R * sizeof(unsigned char));
  int i;
  for (i=0; i<Q; i++) {
    memcpy(msgTBH, &message[128*i], 128 * sizeof(unsigned char));
    sha512_process(hash, msgTBH);
  }
  if (R>111) {
    memcpy(msgTBH, msg, R * sizeof(unsigned char));
    msgTBH[R]=0x80;
    for (i=R+1; i<128; i++) {
      msgTBH[i]=0x00;
    }
    sha512_process(hash, msgTBH);
    sha512_msg_pad0(bitlen,paddedMessage);
  } else {
    sha512_msg_pad(msg, R, bitlen, paddedMessage);
  }
 
  sha512_process(hash, paddedMessage);
  return;
}

void sha512_process(unsigned long hash[], unsigned char msg[]) {
  const unsigned long K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
  int i;
  unsigned long W[80];
  unsigned long A, B, C, D, E, F, G, H, T1, T2;

W[0] = (((unsigned long) msg[0 * 8])<< 56) | (((unsigned long) msg[0 * 8 + 1]) << 48) | (((unsigned long) msg[0 * 8 + 2]) << 40) | (((unsigned long) msg[0 * 8 + 3]) << 32) | (((unsigned long) msg[0 * 8 + 4]) << 24) | (((unsigned long) msg[0 * 8 + 5]) << 16) |  (((unsigned long) msg[0 * 8 + 6]) << 8)  | (((unsigned long) msg[0 * 8 + 7]));
W[1] = (((unsigned long) msg[1 * 8])<< 56) | (((unsigned long) msg[1 * 8 + 1]) << 48) | (((unsigned long) msg[1 * 8 + 2]) << 40) | (((unsigned long) msg[1 * 8 + 3]) << 32) | (((unsigned long) msg[1 * 8 + 4]) << 24) | (((unsigned long) msg[1 * 8 + 5]) << 16) |  (((unsigned long) msg[1 * 8 + 6]) << 8)  | (((unsigned long) msg[1 * 8 + 7]));
W[2] = (((unsigned long) msg[2 * 8])<< 56) | (((unsigned long) msg[2 * 8 + 1]) << 48) | (((unsigned long) msg[2 * 8 + 2]) << 40) | (((unsigned long) msg[2 * 8 + 3]) << 32) | (((unsigned long) msg[2 * 8 + 4]) << 24) | (((unsigned long) msg[2 * 8 + 5]) << 16) |  (((unsigned long) msg[2 * 8 + 6]) << 8)  | (((unsigned long) msg[2 * 8 + 7]));
W[3] = (((unsigned long) msg[3 * 8])<< 56) | (((unsigned long) msg[3 * 8 + 1]) << 48) | (((unsigned long) msg[3 * 8 + 2]) << 40) | (((unsigned long) msg[3 * 8 + 3]) << 32) | (((unsigned long) msg[3 * 8 + 4]) << 24) | (((unsigned long) msg[3 * 8 + 5]) << 16) |  (((unsigned long) msg[3 * 8 + 6]) << 8)  | (((unsigned long) msg[3 * 8 + 7]));
W[4] = (((unsigned long) msg[4 * 8])<< 56) | (((unsigned long) msg[4 * 8 + 1]) << 48) | (((unsigned long) msg[4 * 8 + 2]) << 40) | (((unsigned long) msg[4 * 8 + 3]) << 32) | (((unsigned long) msg[4 * 8 + 4]) << 24) | (((unsigned long) msg[4 * 8 + 5]) << 16) |  (((unsigned long) msg[4 * 8 + 6]) << 8)  | (((unsigned long) msg[4 * 8 + 7]));
W[5] = (((unsigned long) msg[5 * 8])<< 56) | (((unsigned long) msg[5 * 8 + 1]) << 48) | (((unsigned long) msg[5 * 8 + 2]) << 40) | (((unsigned long) msg[5 * 8 + 3]) << 32) | (((unsigned long) msg[5 * 8 + 4]) << 24) | (((unsigned long) msg[5 * 8 + 5]) << 16) |  (((unsigned long) msg[5 * 8 + 6]) << 8)  | (((unsigned long) msg[5 * 8 + 7]));
W[6] = (((unsigned long) msg[6 * 8])<< 56) | (((unsigned long) msg[6 * 8 + 1]) << 48) | (((unsigned long) msg[6 * 8 + 2]) << 40) | (((unsigned long) msg[6 * 8 + 3]) << 32) | (((unsigned long) msg[6 * 8 + 4]) << 24) | (((unsigned long) msg[6 * 8 + 5]) << 16) |  (((unsigned long) msg[6 * 8 + 6]) << 8)  | (((unsigned long) msg[6 * 8 + 7]));
W[7] = (((unsigned long) msg[7 * 8])<< 56) | (((unsigned long) msg[7 * 8 + 1]) << 48) | (((unsigned long) msg[7 * 8 + 2]) << 40) | (((unsigned long) msg[7 * 8 + 3]) << 32) | (((unsigned long) msg[7 * 8 + 4]) << 24) | (((unsigned long) msg[7 * 8 + 5]) << 16) |  (((unsigned long) msg[7 * 8 + 6]) << 8)  | (((unsigned long) msg[7 * 8 + 7]));
W[8] = (((unsigned long) msg[8 * 8])<< 56) | (((unsigned long) msg[8 * 8 + 1]) << 48) | (((unsigned long) msg[8 * 8 + 2]) << 40) | (((unsigned long) msg[8 * 8 + 3]) << 32) | (((unsigned long) msg[8 * 8 + 4]) << 24) | (((unsigned long) msg[8 * 8 + 5]) << 16) |  (((unsigned long) msg[8 * 8 + 6]) << 8)  | (((unsigned long) msg[8 * 8 + 7]));
W[9] = (((unsigned long) msg[9 * 8])<< 56) | (((unsigned long) msg[9 * 8 + 1]) << 48) | (((unsigned long) msg[9 * 8 + 2]) << 40) | (((unsigned long) msg[9 * 8 + 3]) << 32) | (((unsigned long) msg[9 * 8 + 4]) << 24) | (((unsigned long) msg[9 * 8 + 5]) << 16) |  (((unsigned long) msg[9 * 8 + 6]) << 8)  | (((unsigned long) msg[9 * 8 + 7]));
W[10] = (((unsigned long) msg[10 * 8])<< 56) | (((unsigned long) msg[10 * 8 + 1]) << 48) | (((unsigned long) msg[10 * 8 + 2]) << 40) | (((unsigned long) msg[10 * 8 + 3]) << 32) | (((unsigned long) msg[10 * 8 + 4]) << 24) | (((unsigned long) msg[10 * 8 + 5]) << 16) |  (((unsigned long) msg[10 * 8 + 6]) << 8)  | (((unsigned long) msg[10 * 8 + 7]));
W[11] = (((unsigned long) msg[11 * 8])<< 56) | (((unsigned long) msg[11 * 8 + 1]) << 48) | (((unsigned long) msg[11 * 8 + 2]) << 40) | (((unsigned long) msg[11 * 8 + 3]) << 32) | (((unsigned long) msg[11 * 8 + 4]) << 24) | (((unsigned long) msg[11 * 8 + 5]) << 16) |  (((unsigned long) msg[11 * 8 + 6]) << 8)  | (((unsigned long) msg[11 * 8 + 7]));
W[12] = (((unsigned long) msg[12 * 8])<< 56) | (((unsigned long) msg[12 * 8 + 1]) << 48) | (((unsigned long) msg[12 * 8 + 2]) << 40) | (((unsigned long) msg[12 * 8 + 3]) << 32) | (((unsigned long) msg[12 * 8 + 4]) << 24) | (((unsigned long) msg[12 * 8 + 5]) << 16) |  (((unsigned long) msg[12 * 8 + 6]) << 8)  | (((unsigned long) msg[12 * 8 + 7]));
W[13] = (((unsigned long) msg[13 * 8])<< 56) | (((unsigned long) msg[13 * 8 + 1]) << 48) | (((unsigned long) msg[13 * 8 + 2]) << 40) | (((unsigned long) msg[13 * 8 + 3]) << 32) | (((unsigned long) msg[13 * 8 + 4]) << 24) | (((unsigned long) msg[13 * 8 + 5]) << 16) |  (((unsigned long) msg[13 * 8 + 6]) << 8)  | (((unsigned long) msg[13 * 8 + 7]));
W[14] = (((unsigned long) msg[14 * 8])<< 56) | (((unsigned long) msg[14 * 8 + 1]) << 48) | (((unsigned long) msg[14 * 8 + 2]) << 40) | (((unsigned long) msg[14 * 8 + 3]) << 32) | (((unsigned long) msg[14 * 8 + 4]) << 24) | (((unsigned long) msg[14 * 8 + 5]) << 16) |  (((unsigned long) msg[14 * 8 + 6]) << 8)  | (((unsigned long) msg[14 * 8 + 7]));
W[15] = (((unsigned long) msg[15 * 8])<< 56) | (((unsigned long) msg[15 * 8 + 1]) << 48) | (((unsigned long) msg[15 * 8 + 2]) << 40) | (((unsigned long) msg[15 * 8 + 3]) << 32) | (((unsigned long) msg[15 * 8 + 4]) << 24) | (((unsigned long) msg[15 * 8 + 5]) << 16) |  (((unsigned long) msg[15 * 8 + 6]) << 8)  | (((unsigned long) msg[15 * 8 + 7]));

W[16] = sigma5121(W[16-2])+W[16-7]+sigma5120(W[16-15])+ W[16-16];
W[17] = sigma5121(W[17-2])+W[17-7]+sigma5120(W[17-15])+ W[17-16];
W[18] = sigma5121(W[18-2])+W[18-7]+sigma5120(W[18-15])+ W[18-16];
W[19] = sigma5121(W[19-2])+W[19-7]+sigma5120(W[19-15])+ W[19-16];
W[20] = sigma5121(W[20-2])+W[20-7]+sigma5120(W[20-15])+ W[20-16];
W[21] = sigma5121(W[21-2])+W[21-7]+sigma5120(W[21-15])+ W[21-16];
W[22] = sigma5121(W[22-2])+W[22-7]+sigma5120(W[22-15])+ W[22-16];
W[23] = sigma5121(W[23-2])+W[23-7]+sigma5120(W[23-15])+ W[23-16];
W[24] = sigma5121(W[24-2])+W[24-7]+sigma5120(W[24-15])+ W[24-16];
W[25] = sigma5121(W[25-2])+W[25-7]+sigma5120(W[25-15])+ W[25-16];
W[26] = sigma5121(W[26-2])+W[26-7]+sigma5120(W[26-15])+ W[26-16];
W[27] = sigma5121(W[27-2])+W[27-7]+sigma5120(W[27-15])+ W[27-16];
W[28] = sigma5121(W[28-2])+W[28-7]+sigma5120(W[28-15])+ W[28-16];
W[29] = sigma5121(W[29-2])+W[29-7]+sigma5120(W[29-15])+ W[29-16];
W[30] = sigma5121(W[30-2])+W[30-7]+sigma5120(W[30-15])+ W[30-16];
W[31] = sigma5121(W[31-2])+W[31-7]+sigma5120(W[31-15])+ W[31-16];
W[32] = sigma5121(W[32-2])+W[32-7]+sigma5120(W[32-15])+ W[32-16];
W[33] = sigma5121(W[33-2])+W[33-7]+sigma5120(W[33-15])+ W[33-16];
W[34] = sigma5121(W[34-2])+W[34-7]+sigma5120(W[34-15])+ W[34-16];
W[35] = sigma5121(W[35-2])+W[35-7]+sigma5120(W[35-15])+ W[35-16];
W[36] = sigma5121(W[36-2])+W[36-7]+sigma5120(W[36-15])+ W[36-16];
W[37] = sigma5121(W[37-2])+W[37-7]+sigma5120(W[37-15])+ W[37-16];
W[38] = sigma5121(W[38-2])+W[38-7]+sigma5120(W[38-15])+ W[38-16];
W[39] = sigma5121(W[39-2])+W[39-7]+sigma5120(W[39-15])+ W[39-16];
W[40] = sigma5121(W[40-2])+W[40-7]+sigma5120(W[40-15])+ W[40-16];
W[41] = sigma5121(W[41-2])+W[41-7]+sigma5120(W[41-15])+ W[41-16];
W[42] = sigma5121(W[42-2])+W[42-7]+sigma5120(W[42-15])+ W[42-16];
W[43] = sigma5121(W[43-2])+W[43-7]+sigma5120(W[43-15])+ W[43-16];
W[44] = sigma5121(W[44-2])+W[44-7]+sigma5120(W[44-15])+ W[44-16];
W[45] = sigma5121(W[45-2])+W[45-7]+sigma5120(W[45-15])+ W[45-16];
W[46] = sigma5121(W[46-2])+W[46-7]+sigma5120(W[46-15])+ W[46-16];
W[47] = sigma5121(W[47-2])+W[47-7]+sigma5120(W[47-15])+ W[47-16];
W[48] = sigma5121(W[48-2])+W[48-7]+sigma5120(W[48-15])+ W[48-16];
W[49] = sigma5121(W[49-2])+W[49-7]+sigma5120(W[49-15])+ W[49-16];
W[50] = sigma5121(W[50-2])+W[50-7]+sigma5120(W[50-15])+ W[50-16];
W[51] = sigma5121(W[51-2])+W[51-7]+sigma5120(W[51-15])+ W[51-16];
W[52] = sigma5121(W[52-2])+W[52-7]+sigma5120(W[52-15])+ W[52-16];
W[53] = sigma5121(W[53-2])+W[53-7]+sigma5120(W[53-15])+ W[53-16];
W[54] = sigma5121(W[54-2])+W[54-7]+sigma5120(W[54-15])+ W[54-16];
W[55] = sigma5121(W[55-2])+W[55-7]+sigma5120(W[55-15])+ W[55-16];
W[56] = sigma5121(W[56-2])+W[56-7]+sigma5120(W[56-15])+ W[56-16];
W[57] = sigma5121(W[57-2])+W[57-7]+sigma5120(W[57-15])+ W[57-16];
W[58] = sigma5121(W[58-2])+W[58-7]+sigma5120(W[58-15])+ W[58-16];
W[59] = sigma5121(W[59-2])+W[59-7]+sigma5120(W[59-15])+ W[59-16];
W[60] = sigma5121(W[60-2])+W[60-7]+sigma5120(W[60-15])+ W[60-16];
W[61] = sigma5121(W[61-2])+W[61-7]+sigma5120(W[61-15])+ W[61-16];
W[62] = sigma5121(W[62-2])+W[62-7]+sigma5120(W[62-15])+ W[62-16];
W[63] = sigma5121(W[63-2])+W[63-7]+sigma5120(W[63-15])+ W[63-16];
W[64] = sigma5121(W[64-2])+W[64-7]+sigma5120(W[64-15])+ W[64-16];
W[65] = sigma5121(W[65-2])+W[65-7]+sigma5120(W[65-15])+ W[65-16];
W[66] = sigma5121(W[66-2])+W[66-7]+sigma5120(W[66-15])+ W[66-16];
W[67] = sigma5121(W[67-2])+W[67-7]+sigma5120(W[67-15])+ W[67-16];
W[68] = sigma5121(W[68-2])+W[68-7]+sigma5120(W[68-15])+ W[68-16];
W[69] = sigma5121(W[69-2])+W[69-7]+sigma5120(W[69-15])+ W[69-16];
W[70] = sigma5121(W[70-2])+W[70-7]+sigma5120(W[70-15])+ W[70-16];
W[71] = sigma5121(W[71-2])+W[71-7]+sigma5120(W[71-15])+ W[71-16];
W[72] = sigma5121(W[72-2])+W[72-7]+sigma5120(W[72-15])+ W[72-16];
W[73] = sigma5121(W[73-2])+W[73-7]+sigma5120(W[73-15])+ W[73-16];
W[74] = sigma5121(W[74-2])+W[74-7]+sigma5120(W[74-15])+ W[74-16];
W[75] = sigma5121(W[75-2])+W[75-7]+sigma5120(W[75-15])+ W[75-16];
W[76] = sigma5121(W[76-2])+W[76-7]+sigma5120(W[76-15])+ W[76-16];
W[77] = sigma5121(W[77-2])+W[77-7]+sigma5120(W[77-15])+ W[77-16];
W[78] = sigma5121(W[78-2])+W[78-7]+sigma5120(W[78-15])+ W[78-16];
W[79] = sigma5121(W[79-2])+W[79-7]+sigma5120(W[79-15])+ W[79-16];


  A = hash[0];
  B = hash[1];
  C = hash[2];
  D = hash[3];
  E = hash[4];
  F = hash[5];
  G = hash[6];
  H = hash[7];
  
T1 = H + Sigma5121(E) + CH(E,F,G) + K[0] + W[0];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[1] + W[1];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[2] + W[2];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[3] + W[3];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[4] + W[4];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[5] + W[5];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[6] + W[6];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[7] + W[7];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[8] + W[8];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[9] + W[9];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[10] + W[10];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[11] + W[11];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[12] + W[12];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[13] + W[13];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[14] + W[14];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[15] + W[15];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[16] + W[16];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[17] + W[17];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[18] + W[18];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[19] + W[19];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[20] + W[20];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[21] + W[21];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[22] + W[22];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[23] + W[23];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[24] + W[24];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[25] + W[25];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[26] + W[26];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[27] + W[27];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[28] + W[28];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[29] + W[29];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[30] + W[30];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[31] + W[31];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[32] + W[32];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[33] + W[33];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[34] + W[34];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[35] + W[35];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[36] + W[36];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[37] + W[37];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[38] + W[38];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[39] + W[39];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[40] + W[40];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[41] + W[41];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[42] + W[42];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[43] + W[43];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[44] + W[44];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[45] + W[45];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[46] + W[46];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[47] + W[47];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[48] + W[48];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[49] + W[49];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[50] + W[50];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[51] + W[51];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[52] + W[52];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[53] + W[53];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[54] + W[54];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[55] + W[55];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[56] + W[56];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[57] + W[57];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[58] + W[58];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[59] + W[59];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[60] + W[60];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[61] + W[61];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[62] + W[62];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[63] + W[63];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[64] + W[64];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[65] + W[65];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[66] + W[66];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[67] + W[67];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[68] + W[68];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[69] + W[69];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[70] + W[70];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[71] + W[71];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[72] + W[72];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[73] + W[73];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[74] + W[74];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[75] + W[75];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[76] + W[76];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[77] + W[77];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[78] + W[78];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
T1 = H + Sigma5121(E) + CH(E,F,G) + K[79] + W[79];T2 = Sigma5120(A) + MAJ(A,B,C);H = G;G = F;F = E;E = D + T1;D = C;C = B;B = A;A = T1 + T2;
  
  hash[0] +=A;
  hash[1] +=B;
  hash[2] +=C;
  hash[3] +=D;
  hash[4] +=E;
  hash[5] +=F;
  hash[6] +=G;
  hash[7] +=H;
  return;
}


int testSHA(int shatype, int numT){
  unsigned int hash1[5];
  unsigned int hash2[8];
  unsigned long hash3[8];
  int size=3, i;
  clock_t start, finish;
  double seconds;
  static unsigned char msg4[1000000];
  for (i=0; i<1000000; i++)  msg4[i]='a';
  size=1000000;
  
  if (shatype==1) {
    sha1_md(msg4, size, hash1);
    if ((hash1[0] !=0x34aa973c)||(hash1[1]!=0xd4c4daa4)||(hash1[2]!=0xf61eeb2b)
	||(hash1[3]!=0xdbad2731)||(hash1[4]!=0x6534016f)) {
      printf("SHA-1 failed\n");
      return 1;
    } else {
      start = clock();
      for (i=0;i<numT;i++) sha1_md(msg4, size, hash1);
      finish = clock();
      seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
      printf("%f seconds for %d times of SHA-1\n",seconds,numT);
    }
  }
  
  if (shatype==2) {
    sha256_md(msg4, size,hash2);
    if ((hash2[0] != 0xcdc76e5c)||(hash2[1]!=0x9914fb92)||(hash2[2]!=0x81a1c7e2)
      ||(hash2[3]!=0x84d73e67)||(hash2[4]!=0xf1809a48)||(hash2[5]!=0xa497200e)
	||(hash2[6]!=0x046d39cc)||(hash2[7]!=0xc7112cd0)) {
      printf("SHA-1 failed\n");
      return 1;
    } else {
      start = clock();
      for (i=0;i<numT;i++) sha256_md(msg4, size,hash2);
      finish = clock();
      seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
      printf("%f seconds for %d times of SHA-256\n",seconds,numT);
    }
  }
  
  if (shatype==3) {
    sha512_md(msg4, size,hash3);
    if ((hash3[0] != 0xe718483d0ce76964)||(hash3[1]!=0x4e2e42c7bc15b463)||(hash3[2]!=0x8e1f98b13b204428)
      ||(hash3[3]!=0x5632a803afa973eb)||(hash3[4]!=0xde0ff244877ea60a)||(hash3[5]!=0x4cb0432ce577c31b)
	||(hash3[6]!=0xeb009c5c2c49aa2e)||(hash3[7]!=0x4eadb217ad8cc09b)) {
      printf("SHA-1 failed\n");
      return 1;
    } else {
      start = clock();
      for (i=0;i<numT;i++) sha512_md(msg4, size,hash3);
      finish = clock();
      seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
      printf("%f seconds for %d times of SHA-512\n",seconds,numT);
    }
  }
  return 0;
}
