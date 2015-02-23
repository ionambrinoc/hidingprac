#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jpeglib.h>
#include <jerror.h>
#include <openssl/sha.h>

// constants for the embed/extract mode
#define EMBED   1
#define EXTRACT 2

void main(int argc, char **argv)
{
  // determines whether twe are embedding or extracting
  int mode;

  // types for the libjpeg input object
  struct jpeg_decompress_struct cinfo_in;
  struct jpeg_error_mgr jpegerr_in;
  jpeg_component_info *component;
  jvirt_barray_ptr *DCT_blocks;

  // types for the libjpeg output objet
  struct jpeg_compress_struct cinfo_out;
  struct jpeg_error_mgr jpegerr_out;

  // file handles
  FILE *file_in;
  FILE *file_out;     // only used for embedding
  FILE *file_payload; // only used for embedding
  
  // to store the payload
  unsigned long payload_length; 
  unsigned char *payload_bytes;
  unsigned long BUFFSIZE=1024*1024; //1MB hardcoded max payload size, plenty

  // the key string, and its SHA-1 hash
  char *key;
  unsigned char *keyhash;

  // useful properties of the image
  unsigned long blocks_high, blocks_wide;
  
  // for the example code
  int block_y, block_x, u, v;

  // parse parameters
  if(argc==4 && strcmp(argv[1],"embed")==0)
  {
    mode=EMBED;
    key=argv[3];
  }
  else if(argc==3 && strcmp(argv[1],"extract")==0)
  {
    mode=EXTRACT;
    key=argv[2];
  }
  else
  {
    fprintf(stderr, "Usage: GaragePythons embed cover.jpg key <payload >stego.jpg\n");
    fprintf(stderr, "Or     GaragePythons extract key <stego.jpg\n");
    exit(1);
  }

  if(mode==EMBED)
  {
    // read ALL (up to eof, or max buffer size) of the payload into the buffer
    if((payload_bytes=malloc(BUFFSIZE))==NULL)
    {
      fprintf(stderr, "Memory allocation failed!\n");
      exit(1);
    }
    file_payload=stdin;
    payload_length=fread(payload_bytes, 1, BUFFSIZE, file_payload);
    fprintf(stderr, "Embedding payload of length %ld bytes...\n", payload_length);

    // TASK 1: convert payload into bit stream (or ternary alphabet if you prefer) and unambiguously encode its length

  }  

  // open the input file
  if(mode==EMBED)
  {
    if((file_in=fopen(argv[2],"rb"))==NULL)
    {
      fprintf(stderr, "Unable to open cover file %s\n", argv[2]);
      exit(1);
    }
  }
  else if(mode==EXTRACT)
  {
    file_in=stdin;
  }

  // libjpeg -- create decompression object for reading the input file, using the standard error handler
  cinfo_in.err = jpeg_std_error(&jpegerr_in);
  jpeg_create_decompress(&cinfo_in);

  // libjpeg -- feed the cover file handle to the libjpeg decompressor
  jpeg_stdio_src(&cinfo_in, file_in);

  // libjpeg -- read the compression parameters and first (luma) component information
  jpeg_read_header(&cinfo_in, TRUE);
  component=cinfo_in.comp_info;

  // these are very useful (they apply to luma component only)
  blocks_wide=component->width_in_blocks;
  blocks_high=component->height_in_blocks;
  // these might also be useful:
  // component->quant_table->quantval[i] gives you the quantization factor for code i (i=0..63, scanning the 8x8 modes in row order)

  // libjpeg -- read all the DCT coefficients into a memory structure (memory handling is done by the library)
  DCT_blocks=jpeg_read_coefficients(&cinfo_in);

  // if embedding, set up the output file
  // (we had to read the input first so that libjpeg can set up an output file with the exact same parameters)
  if(mode==EMBED)
  {
    // libjpeg -- create compression object with default error handler
    cinfo_out.err = jpeg_std_error(&jpegerr_out);
    jpeg_create_compress(&cinfo_out);

    // libjpeg -- copy all parameters from the input to output object
    jpeg_copy_critical_parameters(&cinfo_in, &cinfo_out);

    // libjpeg -- feed the stego file handle to the libjpeg compressor
    file_out=stdout;
    jpeg_stdio_dest(&cinfo_out, file_out);
  }


  // At this point the input has been read, and an output is ready (if embedding)
  // We can modify the DCT_blocks if we are embedding, or just print the payload if extracting

  if((keyhash=malloc(20))==NULL) // enough space for a 160-bit hash
  {
    fprintf(stderr, "Memory allocation failed!\n");
    exit(1);
  }
  SHA1(key, strlen(key), keyhash);

  // TASK 2: use the key to create a pseudorandom order to visit the coefficients

  if(mode==EMBED)
  {
    // TASK 3: embed the payload

    // libjpeg -- write the coefficient block
    jpeg_write_coefficients(&cinfo_out, DCT_blocks);
    jpeg_finish_compress(&cinfo_out);
  }
  else if(mode==EXTRACT)
  {
    // TASK 4: extact the payload symbols and reconstruct the original bytes

    // use something like:
    // printf("%s", payload_bytes);
  }


  // example code: prints out all the DCT blocks to stderr, scanned in row order, but does not change them
  // (if "embedding", the cover jpeg was also sent unchanged  to stdout)
 
  for (block_y=0; block_y<component->height_in_blocks; block_y++)
  {
    for (block_x=0; block_x< component->width_in_blocks; block_x++)
    {
      // this is the magic code which accesses block (block_x,block_y) from the luma component of the image
      JCOEFPTR block=(cinfo_in.mem->access_virt_barray)((j_common_ptr)&cinfo_in, DCT_blocks[0], block_y, (JDIMENSION)1, FALSE)[0][block_x];
      // JCOEFPTR can just be used as an array of 64 ints
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
  
  // libjpeg -- finish with the input file and clean up
  jpeg_finish_decompress(&cinfo_in);
  jpeg_destroy_decompress(&cinfo_in);

  // free memory blocks (not actually needed, the OS will do it)
  free(keyhash);
  free(payload_bytes);
}
