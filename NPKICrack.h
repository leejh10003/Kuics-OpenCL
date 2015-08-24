#ifndef NPKICRACK_H_INCLUDED
#define NPKICRACK_H_INCLUDED

#include <stdint.h>

#define MAX_PASSWORD	32
#define MAX_PW_CHARSET	64
#define PRINT_INTERVAL	5000
#define WORK_DIM 1

#ifndef __OPENCL_CL_H
    #ifdef __APPLE__
        #include <OpenCL/opencl.h>
    #else
        #include <CL/cl.h>
    #endif
    #define __OPENCL_CL_H
#endif
struct npki_private_key
{
	uint8_t *rawkey;
	long rawkey_len;
	uint8_t salt[8]; // dkey, div, buf is temporary
    uint16_t itercount;
    uint8_t *crypto;
    long crypto_len;
    uint8_t *plain;
};
typedef struct npki_private_key NPKIPrivateKey;

struct npki_brute_force
{
	char* pkey_path;		// Private Key Path
	char* pw_charset_path;	// Password Charset
	char* pw_init;			// Initial Password
	char password[MAX_PASSWORD];		// Password
    char pw_charset[MAX_PW_CHARSET];	// Password Charset
	uint32_t pw_min_len;	// Password Minimum Length
    uint32_t pw_max_len;	// Password Maximum Length
    uint32_t pw_now_len;	// Now, which n len pw is to iterate?
    uint64_t pw_cursor;	// Now, which n'th pw is to iterate?
    time_t	starttime;
};
typedef struct npki_brute_force NPKIBruteForce;

int BruteForceIterator (NPKIPrivateKey *pkey, NPKIBruteForce *bforce);
char* PasswordGenerator (NPKIBruteForce *bforce);
void NPKIDecrypt (NPKIPrivateKey *pkey, const char* password);

void InitNPKIPrivateKey (NPKIPrivateKey *pkey);
int ReadRawNPKIPrivateKey (NPKIPrivateKey *pkey, const char* PrivateKeyPath);
void ParseNPKIPrivateKey (NPKIPrivateKey *pkey);
void FreeNPKIPrivateKey (NPKIPrivateKey *pkey);

void InitNPKIBruteForce (NPKIBruteForce *bforce);
int ReadPasswordCharset (NPKIBruteForce *bforce);
int ValidateInitialPW	(NPKIBruteForce *bforce);
uint64_t SetCursorFromInitialPW (NPKIBruteForce *bforce);
uint32_t GetSerialFromCharset(NPKIBruteForce *bforce, const char tofind);
void ReadyNPKIBruteForce (NPKIBruteForce *bforce);

void GetMaxCursor(NPKIBruteForce *bforce);
void SetStartTime(NPKIBruteForce *bforce);
void PrintBruteForceEnvInfo(NPKIBruteForce *bforce);
void NPKIDecryptOpenCL (NPKIPrivateKey *pkey, const char* password, cl_kernel kernel, cl_context context, cl_command_queue commandQueue);
int BruteForceIteratorOpenCL(NPKIPrivateKey *pkey, NPKIBruteForce *bforce, cl_kernel kernel, cl_context context, cl_command_queue commandQueue);
void memBufPrintErr(int errNum);
#endif // NPKICRACK_H_INCLUDED
