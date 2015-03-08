/*******************ADVANCED SECURITY PRACTICAL ASSIGNMENT 2 - INFORMATION HIDING******************/
/*************************HILARY TERM 2015******************GaragePythons.c************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jpeglib.h>
#include <jerror.h>
#include <openssl/sha.h>
#include <stdint.h>

#define EMBED   1	// constants for the embed/extract mode
#define EXTRACT 2

/*****Helper methods that will be useful later*****************************************************/

/*****TASK 1: bit stream creation and manipulation*************************************************/
typedef struct {
char* data;     /* payload data */
int data_size;   /* strlen(data) */
int last_bit_offset; /* last bit in data stream */

int current_data_offset; /* which character we're at */
int current_bit_offset;  /* bit in character we're at */
} BitStream;

BitStream *createBitstream(char *payload, int payload_length) //will be helpful
{
  BitStream *bs = malloc(sizeof(BitStream));
  bs->data = payload;  bs->data_size = payload_length;
  bs->last_bit_offset = bs->data[bs->data_size] & 1;

  bs->current_data_offset = 0;  bs->current_bit_offset = 7;
  return bs;
}

unsigned char nextBit(BitStream *bs) //iterator over bit stream
{                                              /**endianness accounted for; treat as little endian*/
    unsigned char bit = 0x00;
    bit = (bs->data[bs->current_data_offset] >> bs->current_bit_offset) & 0x01;

    bs->current_bit_offset--;  /* move to next character */

    if (bs->current_bit_offset < 0)
    {
        bs->current_bit_offset = 7;
        bs->current_data_offset++;
    }
    return bit;
}
/**************************************************************************************************/

/****TASK 2: Knuth shuffle for random permutations*************************************************/

void shuffle(int *list, size_t len)
{
	int j; int *tmp;
	while(len)
	{
		j = irand(len);
		if (j != len - 1)
		{	tmp = list[j];		list[j] = list[len - 1];	list[len - 1] = tmp;		}
		len--;
	}
}

int irand(int n)
{
	int r, rand_max = RAND_MAX - (RAND_MAX % n);  // reroll until r falls in a range that can be evenly
	while ((r = rand()) >= rand_max); // distributed in n bins.  Unless n is comparable to RAND_MAX.
	return r / (rand_max / n);
}
void main(int argc, char **argv)
{
  int mode;	// determines whether we are embedding or extracting

  struct jpeg_decompress_struct cinfo_in;                   // types for libjpeg input object
  struct jpeg_error_mgr jpegerr_in;
  jpeg_component_info *component;
  jvirt_barray_ptr *DCT_blocks;
  struct jpeg_compress_struct cinfo_out;                    // types for libjpeg output object
  struct jpeg_error_mgr jpegerr_out;

  FILE *file_in;	                                                    // file handles
  FILE *file_out;     // only used for embedding
  FILE *file_payload; // only used for embedding

  uint32_t payload_length; 	         /** to store the payload; changed for fixed 32 bit size*/
  unsigned char *payload_bytes;
  unsigned long BUFFSIZE=1024*1024; //1MB hardcoded max payload size, plenty

  char *key; unsigned char *keyhash;                     // the key string, and its SHA-1 hash
  int* order;                                            // order to visit JPEG DCT coefficients

  unsigned long blocks_high, blocks_wide;                    // useful properties of the image
  int block_y, block_x, u, v;					  // for the example code

  if(argc==4 && strcmp(argv[1],"embed")==0)	// parse parameters
  {    mode=EMBED;    key=argv[3];    }
  else if(argc==3 && strcmp(argv[1],"extract")==0)
  {    mode=EXTRACT;    key=argv[2];  }
       else
       {
         fprintf(stderr, "Usage: GaragePythons embed cover.jpg key <payload >stego.jpg\n");
         fprintf(stderr, "Or     GaragePythons extract key <stego.jpg\n");         exit(1);
       }

  if(mode==EMBED)
  {
    if((payload_bytes=malloc(BUFFSIZE))==NULL)		     // read ALL (up to eof, or max buffer
    {							     // size) of the payload into the buffer
      fprintf(stderr, "Memory allocation failed!\n");  exit(1);
    }
    file_payload=stdin;
    payload_length=fread(payload_bytes, 1, BUFFSIZE, file_payload);
    fprintf(stderr, "Embedding payload of length %ld bytes...\n", payload_length);

/**************************************************************************************************/

/****TASK 1****convert payload into bit stream (or ternary alphabet if you prefer) and unambiguously
/**************encode its length*******************************************************************/

    char* payload;
    if((payload=malloc(payload_length * sizeof(char) + sizeof(payload_length)))==NULL)
    {
      fprintf(stderr, "Memory allocation failed!\n");   exit(1);      //fail.
    }
    //otherwise...
    memcpy(payload, &payload_length, sizeof(payload_length)); //make payload begin with length
    memcpy(payload+sizeof(payload_length), payload_bytes, strlen(payload_bytes));

    BitStream* payloadStream =
                createBitstream(payload, sizeof(payload_length)+strlen(payload_bytes));

    #ifdef DEBUG /**debug code; prints first eight bytes of payload, including payload length */
    int i;
    for(i=0; i<64; i++) //print eight bytes
    {
        fprintf(stderr, "%d", nextBit(payloadStream));
        if (i%8==7 && i!=0) fprintf(stderr, "\n");
    }
    #endif
  }
/**************************************************************************************************/
  if(mode==EMBED)   // open the input file
  {
    if((file_in=fopen(argv[2],"rb"))==NULL)
    {
      fprintf(stderr, "Unable to open cover file %s\n", argv[2]);      exit(1);
    }
  }
  else if(mode==EXTRACT)  {    file_in=stdin;  }

  cinfo_in.err = jpeg_std_error(&jpegerr_in); // libjpeg -- create decompression object for reading
  jpeg_create_decompress(&cinfo_in);          //   the input file, using the standard error handler
  jpeg_stdio_src(&cinfo_in, file_in); // libjpeg -- feed cover file handle to libjpeg decompressor
  jpeg_read_header(&cinfo_in, TRUE);  	// libjpeg -- read the compression parameters and
  component=cinfo_in.comp_info;	     	// first (luma) component information

  blocks_wide=component->width_in_blocks; //very useful (they apply to luma component only)
  blocks_high=component->height_in_blocks;
  // these might also be useful: component->quant_table->quantval[i] gives the quantization factor
  // 					for code i (i=0..63, scanning the 8x8 modes in row order)

  // libjpeg -- read all the DCT coefficients into a memory structure
  DCT_blocks=jpeg_read_coefficients(&cinfo_in); //(memory handling is done by library)

  // if embedding, set up the output file (we had to read the input first so
  //                       that libjpeg can set up an output file with the exact same parameters)
  if(mode==EMBED)
  {
    cinfo_out.err = jpeg_std_error(&jpegerr_out); // libjpeg -- create compression
    jpeg_create_compress(&cinfo_out);             // object with default error handler

    // libjpeg -- copy all parameters from input to output object
    jpeg_copy_critical_parameters(&cinfo_in, &cinfo_out);

    file_out=stdout;				  // libjpeg -- feed the stego file handle to
    jpeg_stdio_dest(&cinfo_out, file_out);	  // the libjpeg compressor
  }

  // At this point the input has been read, and an output is ready (if embedding)
  // We can modify the DCT_blocks if we are embedding, or just print the payload if extracting

/***TASK 2****use the key to create a pseudorandom order to visit the coefficients*****************/

  if((keyhash=malloc(20))==NULL) // enough space for a 160-bit hash
  {    fprintf(stderr, "Memory allocation failed!\n");    exit(1);  }
  SHA1(key, strlen(key), keyhash); // hash the key and then initialize the random
  srand(*(unsigned int *)keyhash); // number generator's state with the first 32 key bits

  if((order=malloc(payload_length*8))==NULL) //times 8 since we need to visit for each bit, not byte
  {    fprintf(stderr, "Memory allocation failed!\n");    exit(1);  }

  int j; for (j=0; j<payload_length*8; j++) order[j]=j; //initialize visiting order.
  /** at this point, to run the Knuth shuffle on a list/array/something, call shuffle(arr, size); */
  shuffle(order,payload_length);                        //now the order is pseudorandomly permuted.


/**************************************************************************************************/

/***TASK 3****embed the payload********************************************************************/
/*
  if(mode==EMBED)
  {


    jpeg_write_coefficients(&cinfo_out, DCT_blocks); // libjpeg -- write the coefficient block
    jpeg_finish_compress(&cinfo_out);
  }
*/
/**************************************************************************************************/

/***TASK 4****extact the payload symbols and reconstruct the original bytes************************/
/*
  else if(mode==EXTRACT)
  {    // use something like printf("%s", payload_bytes);

  }
*/
/**************************************************************************************************/
/*
  // example code: prints out all the DCT blocks to stderr, scanned in row order, but does not
  // change them (if "embedding", the cover jpeg was also sent unchanged to stdout)

  for (block_y=0; block_y<component->height_in_blocks; block_y++)
  {
    for (block_x=0; block_x< component->width_in_blocks; block_x++)
    {
      // this is the magic code which accesses block (block_x,block_y) from luma component of image
      JCOEFPTR block=(cinfo_in.mem->access_virt_barray)((j_common_ptr)&cinfo_in, DCT_blocks[0],
							block_y, (JDIMENSION)1, FALSE)[0][block_x];
	//JCOEFPTR can just be used as an array of 64 ints
      for (u=0; u<8; u++)
      {
	for(v=0; v<8; v++)
        {
	  fprintf(stderr, "%3d ", block[u*8+v]);
	}
	fprintf(stderr, "\n");
      }
      fprintf(stderr, "\n");
    }
  }

  jpeg_finish_decompress(&cinfo_in);  // libjpeg -- finish with the input file
  jpeg_destroy_decompress(&cinfo_in); //            and clean up
*/
  free(keyhash);		// free memory blocks (not actually needed, the OS will do it)
  free(payload_bytes);
}
