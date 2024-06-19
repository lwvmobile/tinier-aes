/*-------------------------------------------------------------------------------
 * aes.h         Tinier AES
 * Header File for externally available prototype functions
 *
 * Modified Tiny AES code for more variable nk/nr/nb values, all in one file
 * https://github.com/kokke/tiny-AES-c
 *-----------------------------------------------------------------------------*/

//bit and byte utility prototyes
uint64_t convert_bits_into_output(uint8_t * input, int len);
void pack_bit_array_into_byte_array (uint8_t * input, uint8_t * output, int len);
void unpack_byte_array_into_bit_array (uint8_t * input, uint8_t * output, int len);

//taylor made aes function prototypes
void aes_ctr_bitwise_payload_crypt (uint8_t * iv, uint8_t * key, uint8_t * payload, int type);
void aes_ctr_bytewise_payload_crypt (uint8_t * iv, uint8_t * key, uint8_t * payload, int type);
void aes_ofb_keystream_output (uint8_t * iv, uint8_t * key, uint8_t * output, int type, int nblocks);