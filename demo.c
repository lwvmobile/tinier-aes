/*-------------------------------------------------------------------------------
 * demo.c         Tinier AES
 * Quick Work Flow Demonstation AES CTR Mode
 *
 * buid with gcc demo.c aes.c -o demo.o -Wall -Wextra -Wpedantic
 *-----------------------------------------------------------------------------*/

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include "aes.h"

int main ()
{

  time_t ts = time(NULL);
  srand(ts); //randomize seed based on current time
  int i = 0;

  uint8_t key[32];
  for (i = 0; i < 32; i++)
    key[i] = rand() & 0xFF;

  uint8_t iv[16];
  for (i = 0; i < 16; i++)
    iv[i] = rand() & 0xFF;

  uint8_t payload_bits[128];
  uint8_t payload_bytes[16];

  memset (payload_bits, 0, 128*sizeof(uint8_t));
  memset (payload_bytes, 0, 16*sizeof(uint8_t));
  
  //print key
  fprintf (stderr, "\nKey:");
  for (i = 0; i < 32; i++)
      fprintf (stderr, " %02X", key[i]);

  //print iv
  fprintf (stderr, "\nIV: ");
  for (i = 0; i < 16; i++)
      fprintf (stderr, " %02X", iv[i]);

  //print input
  fprintf (stderr, "\nInput: ");
  for (i = 0; i < 16; i++)
      fprintf (stderr, " %02X", payload_bytes[i]);

  //execute aes_ctr with a 256-bit key (type 2)
  aes_ctr_bytewise_payload_crypt (iv, key, payload_bytes, 2);

  //or execute aes_ctr with a bit-wise payload a 256-bit key (type 2)
  // aes_ctr_bitwise_payload_crypt (iv, key, payload_bits, 3);
  // pack_bit_array_into_byte_array(payload_bits, payload_bytes, 16); //packing optional, for display only

  //debug output
  fprintf (stderr, "\nOutput:");
  for (i = 0; i < 16; i++)
      fprintf (stderr, " %02X", payload_bytes[i]);

  return 0;
}