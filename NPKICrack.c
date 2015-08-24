#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include "Seed.h"
#include "Hash.h"
#include "BasicIO.h"
#include "ErrorHandle.h"
#include "NPKICrack.h"

cl_mem inBuf = NULL;
cl_mem outBuf = NULL;
cl_mem roundKeyBuf = NULL;
cl_mem ivBuf = NULL;
// http://fly32.net/447

// �� static ������������ �ѹ� ���� ���� ������� �ʴ´�.
static uint8_t charset_dic[0x100] = {0};
static uint32_t charset_len;
static uint64_t max_cursor[MAX_PASSWORD+1] = {0};

int BruteForceIterator (NPKIPrivateKey *pkey, NPKIBruteForce *bforce)
{
	uint64_t full_cursor = 0, base_cursor = 0;
	for (int i = bforce->pw_min_len; i < bforce->pw_now_len; i++)
		full_cursor += max_cursor[i];
	full_cursor += bforce->pw_cursor;
	base_cursor = full_cursor;

	while (TRUE)
	{
		PasswordGenerator(bforce);

		NPKIDecrypt(pkey, bforce->password);

		// PRINT_INTERVAL�� �� ������ ��Ȳ ���
		if (!(bforce->pw_cursor % PRINT_INTERVAL))
		{ // PRIu64 �� ���� ���� -> uint64_t�� �����쿡�� %I64u, ���������� %llu�� ���� �ٸ�
			time_t elasped = time(NULL) - bforce->starttime + 1; // 1 �� ���̸� DIV/0 �߻�
			long remains = (max_cursor[MAX_PASSWORD] - base_cursor) / ((full_cursor-base_cursor) / elasped + 1) - elasped;
			printf(	"Now Calculating Password \'%s\', %"PRId64"key/sec\n"
					"  Len%02u   : %3"PRIu64".%02"PRIu64"%%\n"
					"  All     : %3"PRIu64".%02"PRIu64"%%\n"
					"  Elapsed : %02ldh %02ldm %02lds\n"
					"  Remain  : %02ldh %02ldm %02lds\n",
					bforce->password, (full_cursor-base_cursor) / elasped, bforce->pw_now_len,
					bforce->pw_cursor * 100 / max_cursor[bforce->pw_now_len],
					(bforce->pw_cursor * 10000 / max_cursor[bforce->pw_now_len]) % 100,
					full_cursor * 100 / max_cursor[MAX_PASSWORD],
					(full_cursor * 10000 / max_cursor[MAX_PASSWORD]) % 100,
					sec2hour(elasped), sec2min(elasped), sec2sec(elasped),
					sec2hour(remains), sec2min(remains), sec2sec(remains));
		}

		// ����� ���ڵ��Ǿ��ٸ�
		if(IsPKCS5PaddingOK(pkey->plain, pkey->crypto_len))
			return TRUE;

		uint8_t isfull = TRUE;
		for (uint32_t i = 0; i < bforce->pw_now_len; i++)
		{
			if (bforce->password[i] != bforce->pw_charset[charset_len-1])
			{
				isfull = FALSE;
				break;
			}
		}

		bforce->pw_cursor++;
		full_cursor++;

		if (isfull)
		{
			bforce->pw_cursor = 0;
			bforce->pw_now_len++;

			if (bforce->pw_max_len < bforce->pw_now_len)
				break; // ���� �� ���Ҵ�.
		}
	}

    return FALSE;
}

char* PasswordGenerator (NPKIBruteForce *bforce)
{
	uint32_t i = 0;
	for (i = 0; i < bforce->pw_now_len; i++)
//		bforce->password[i] = bforce->pw_charset[bforce->pw_cursor / ipow(charset_len, i) % charset_len];
		bforce->password[i] = bforce->pw_charset[(bforce->pw_cursor % ipow(charset_len, i+1)) / ipow(charset_len, i)];
	bforce->password[i] = '\0';
	return bforce->password;
}

void NPKIDecrypt (NPKIPrivateKey *pkey, const char* password)
{
// ���� ���� �� �ʱ�ȭ
    uint8_t dkey[20] = {0}, div[20] = {0}, buf[20] = {0}, iv[16] = {0}, seedkey[20] = {0}; // dkey, div, buf is temporary
	uint32_t roundkey[32] = {0};

// Get SEED Key
	// ��й�ȣ ���̴� �ִ� 64�ڸ����� ���ѵǾ� �ִ�.
    JV_PBKDF1(dkey, (uint8_t*)password, strlen(password), pkey->salt, sizeof(pkey->salt), pkey->itercount);
    memcpy(seedkey, dkey, 16);
// Get SEED IV
    memcpy(buf, dkey+16, 4);
    JV_SHA1(div, buf, 4);
    memcpy(iv, div, 16);

#ifdef _DEBUG_DEEP
	puts("\n== SEED Key ==");
	DumpBinary(seedkey, 16);
	puts("\n== IV ==");
    DumpBinary(iv, 16);
#endif

	JV_SeedRoundKey(roundkey, seedkey);

	//--  ����ȭ�� �κ� Start --//
	// CPU��� OpenMP
	// GPU��� OpenCL
	for (uint32_t i = 0; i < pkey->crypto_len; i += SeedBlockSize)
	{
		if (i == 0) // �� ó���̸� IV�� �־��ְ�
			JV_SEED_CBC128_Decrypt_OneBlock(pkey->crypto, pkey->plain, roundkey, iv);
		else // �װ� �ƴϸ� ���� Crypto Block�� �־��ش�
			JV_SEED_CBC128_Decrypt_OneBlock(pkey->crypto + i, pkey->plain + i, roundkey, pkey->crypto + (i-SeedBlockSize));
	}
	//--  ����ȭ�� �κ� End --//
}



void InitNPKIPrivateKey (NPKIPrivateKey *pkey)
{
	pkey->rawkey = NULL;
	pkey->rawkey_len = 0;
	for (int i = 0; i < 8; i++)
		pkey->salt[i] = 0;
	pkey->itercount = 0;
    pkey->crypto = NULL;
    pkey->crypto_len = 0;
    pkey->plain = NULL;
}

int ReadRawNPKIPrivateKey (NPKIPrivateKey *pkey, const char* PrivateKeyPath)
{
	FILE *fp = fopen(PrivateKeyPath, "rb");
	pkey->rawkey_len = ReadFileSize(PrivateKeyPath);
    pkey->rawkey = (uint8_t *)malloc(pkey->rawkey_len * sizeof(uint8_t));
	fread((void*) (pkey->rawkey), 1, pkey->rawkey_len, fp);

#ifdef _DEBUG
	puts("== Private Key ==");
	DumpBinary(pkey->rawkey, pkey->rawkey_len);
#endif

    return 0;
}

void ParseNPKIPrivateKey (NPKIPrivateKey *pkey)
{
// salt <- PrivateKeyBuf, rawkey[20]-[27] // 21-28����Ʈ
	memcpy((void*) (pkey->salt), (void*) (pkey->rawkey+20), 8);
// itercount <- rawkey[30]-[31] // 31-32����Ʈ
	pkey->itercount = (pkey->rawkey[30] << 8) + pkey->rawkey[31];

#ifdef _DEBUG
	puts("\n== Salt ==");
	DumpBinary(pkey->salt, 8);
	printf(	"\n== Itercount : %d ==\n", pkey->itercount);
#endif

// crypted <- rawkey[36]-[End] // 37����Ʈ����
	pkey->crypto_len = pkey->rawkey_len - 36;
	pkey->crypto = (uint8_t *)malloc(pkey->crypto_len * sizeof(uint8_t));
	pkey->plain = (uint8_t *)malloc(pkey->crypto_len * sizeof(uint8_t));
	memcpy((void*) pkey->crypto, (void*) (pkey->rawkey + 36), pkey->crypto_len);

#ifdef _DEBUG
	puts("\n== Encrypted Data ==");
	DumpBinary(pkey->crypto, pkey->crypto_len);
#endif
}

void FreeNPKIPrivateKey (NPKIPrivateKey *pkey)
{
	free(pkey->rawkey);
	free(pkey->crypto);
	free(pkey->plain);
}


void InitNPKIBruteForce (NPKIBruteForce *bforce)
{
	for (int i = 0; i < MAX_PASSWORD; i++)
		bforce->password[i] = 0;
	for (int i = 0; i < MAX_PW_CHARSET; i++)
		bforce->pw_charset[i] = 0;
	bforce->pkey_path = NULL;
	bforce->pw_charset_path = NULL;// Password Charset
	bforce->pw_init = NULL;
	bforce->pw_min_len = 0;		// Password Minimum Length
    bforce->pw_max_len = 0;		// Password Maximum Length
    bforce->pw_now_len = 0;		// Now, n len pw is to iterate?
    bforce->pw_cursor = 0;		// Now, n'th pw is to iterate?
    bforce->starttime = 0;
}

int ReadPasswordCharset (NPKIBruteForce *bforce)
{
    FILE *fp = NULL;
	long cslen = 0;

// ���� ����
	cslen = ReadFileSize(bforce->pw_charset_path);
	if (MAX_PW_CHARSET < cslen) // �״�� �θ� Overflow �߻� -> Abort
		JVErrorHandle(JVERR_PW_CHARSET_TOO_LONG);

// ������ �д´�.
    fp = fopen(bforce->pw_charset_path, "rt");
	for (long i = 0; i < cslen; i++)
		bforce->pw_charset[i] = fgetc(fp);
	fclose(fp);

// �ߺ��Ǵ� ���ڰ� ������ �˻�
	for (long i = 0; i < cslen; i++)
	{
//		printf("");
		charset_dic[(uint8_t) bforce->pw_charset[i]]++;
	}

	for (long i = 0; i < cslen; i++)
	{
		if (2 <= charset_dic[i])
			return FALSE; // ���� ����
	}
// ���� ����
	charset_len = strlen(bforce->pw_charset);

	return TRUE;
}

//
int ValidateInitialPW (NPKIBruteForce *bforce)
{
    for (size_t i = 0; i < strlen(bforce->pw_init); i++)
	{
        if (charset_dic[(uint8_t) bforce->pw_init[i]] == 0) // charset�� ���°� pw_init�� �ִ�
			return FALSE;
	}

    return TRUE;
}

uint64_t SetCursorFromInitialPW (NPKIBruteForce *bforce)
{
    bforce->pw_now_len = strlen(bforce->pw_init);
    bforce->pw_cursor = 0;
    for (uint32_t i = 0; i < bforce->pw_now_len; i++)
		bforce->pw_cursor += (GetSerialFromCharset(bforce, bforce->pw_init[i]) * ipow(charset_len, i));

    strncpy(bforce->password, bforce->pw_init, MAX_PASSWORD);
	bforce->password[MAX_PASSWORD-1] = '\0';

	return bforce->pw_cursor;
}

uint32_t GetSerialFromCharset(NPKIBruteForce *bforce, const char tofind)
{
    char* address = strchr(bforce->pw_charset, tofind);
    return (uint32_t) (address - bforce->pw_charset);
}

void ReadyNPKIBruteForce (NPKIBruteForce *bforce)
{
    bforce->pw_now_len = bforce->pw_min_len;
    bforce->pw_cursor = 0;

/* �� �κ��� PasswordGenerator�� ó���Ѵ�.
	uint32_t i = 0;
    for (i = 0; i < bforce->pw_now_len; i++)
		bforce->password[i] = bforce->pw_charset[0];
	bforce->password[i] = '\0';
*/
}

void GetMaxCursor(NPKIBruteForce *bforce)
{
	for (uint32_t i = bforce->pw_min_len; i <= bforce->pw_max_len; i++)
	{ // i�� �������
		max_cursor[i] = 1;
		for (uint32_t d = 0; d < i; d++) // d�� �ڸ���
			max_cursor[i] += GetSerialFromCharset(bforce, bforce->pw_charset[charset_len-1]) * ipow(charset_len, d);
		// ����� ��ü�� Ŀ�� ����
		max_cursor[MAX_PASSWORD] += max_cursor[i];
#ifdef _DEBUG
		printf("max_cursor for len %2u : %"PRIu64"\n", i, max_cursor[i]);
#endif
	}

    return;
}

void SetStartTime(NPKIBruteForce *bforce)
{
	bforce->starttime = time(NULL);
}

void PrintBruteForceEnvInfo(NPKIBruteForce *bforce)
{
	PasswordGenerator(bforce);
	printf(	"= BruteForce Environment Info = \n"
			"Password Minimum Length     : %u\n"
			"Password Maximum Length     : %u\n"
			"Number of keys to calculate : %"PRIu64"\n"
			"Initial Password to try     : \'%s\'\n"
			"Password Charsets to try\n  ",
			bforce->pw_min_len, bforce->pw_max_len, max_cursor[MAX_PASSWORD], bforce->password);
	for (uint32_t i = 0; i < charset_len; i++)
		putchar(bforce->pw_charset[i]);
	putchar('\n');
}
int BruteForceIteratorOpenCL(NPKIPrivateKey *pkey,
							NPKIBruteForce *bforce,
							cl_kernel kernel,
							cl_context context,
							cl_command_queue commandQueue)
{
	uint64_t full_cursor = 0, base_cursor = 0;
	for (int i = bforce->pw_min_len; i < bforce->pw_now_len; i++)
		full_cursor += max_cursor[i];
	full_cursor += bforce->pw_cursor;
	base_cursor = full_cursor;

	while (TRUE)
	{
		PasswordGenerator(bforce);

		NPKIDecryptOpenCL(pkey, bforce->password, kernel, context, commandQueue);

		// PRINT_INTERVAL�� �� ������ ��Ȳ ���
		if (!(bforce->pw_cursor % PRINT_INTERVAL))
		{ // PRIu64 �� ���� ���� -> uint64_t�� �����쿡�� %I64u, ���������� %llu�� ���� �ٸ�
			time_t elasped = time(NULL) - bforce->starttime + 1; // 1 �� ���̸� DIV/0 �߻�
			long remains = (max_cursor[MAX_PASSWORD] - base_cursor) / ((full_cursor-base_cursor) / elasped + 1) - elasped;
			printf(	"Now Calculating Password \'%s\', %"PRId64"key/sec\n"
					"  Len%02u   : %3"PRIu64".%02"PRIu64"%%\n"
					"  All     : %3"PRIu64".%02"PRIu64"%%\n"
					"  Elapsed : %02ldh %02ldm %02lds\n"
					"  Remain  : %02ldh %02ldm %02lds\n",
					bforce->password, (full_cursor-base_cursor) / elasped, bforce->pw_now_len,
					bforce->pw_cursor * 100 / max_cursor[bforce->pw_now_len],
					(bforce->pw_cursor * 10000 / max_cursor[bforce->pw_now_len]) % 100,
					full_cursor * 100 / max_cursor[MAX_PASSWORD],
					(full_cursor * 10000 / max_cursor[MAX_PASSWORD]) % 100,
					sec2hour(elasped), sec2min(elasped), sec2sec(elasped),
					sec2hour(remains), sec2min(remains), sec2sec(remains));
		}

		// ����� ���ڵ��Ǿ��ٸ�
		if(IsPKCS5PaddingOK(pkey->plain, pkey->crypto_len))
			return TRUE;

		uint8_t isfull = TRUE;
		for (uint32_t i = 0; i < bforce->pw_now_len; i++)
		{
			if (bforce->password[i] != bforce->pw_charset[charset_len-1])
			{
				isfull = FALSE;
				break;
			}
		}

		bforce->pw_cursor++;
		full_cursor++;

		if (isfull)
		{
			bforce->pw_cursor = 0;
			bforce->pw_now_len++;

			if (bforce->pw_max_len < bforce->pw_now_len)
				break; // ���� �� ���Ҵ�.
		}
	}

    return FALSE;
}
void NPKIDecryptOpenCL (NPKIPrivateKey *pkey,
						const char* password,
						cl_kernel kernel,
						cl_context context,
						cl_command_queue commandQueue)
{
// ���� ���� �� �ʱ�ȭ
    uint8_t dkey[20] = {0}, div[20] = {0}, buf[20] = {0}, iv[16] = {0}, seedkey[20] = {0}; // dkey, div, buf is temporary
	uint32_t roundkey[32] = {0};
	cl_int errNum;

// Get SEED Key
	// ��й�ȣ ���̴� �ִ� 64�ڸ����� ���ѵǾ� �ִ�.
    JV_PBKDF1(dkey, (uint8_t*)password, strlen(password), pkey->salt, sizeof(pkey->salt), pkey->itercount);
    memcpy(seedkey, dkey, 16);
// Get SEED IV
    memcpy(buf, dkey+16, 4);
    JV_SHA1(div, buf, 4);
    memcpy(iv, div, 16);

#ifdef _DEBUG_DEEP
	puts("\n== SEED Key ==");
	DumpBinary(seedkey, 16);
	puts("\n== IV ==");
    DumpBinary(iv, 16);
#endif

	JV_SeedRoundKey(roundkey, seedkey);







	//Creating OpenCL Memory buffers.
	if(inBuf == NULL){
		inBuf = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, pkey->crypto_len * sizeof(uint8_t), pkey->crypto, &errNum);
		if(errNum != CL_SUCCESS){
			printf("Failed to create inBuf cl_mem buffer.\n\n");
			memBufPrintErr(errNum);
			exit(1);
		}
		else{
			printf("Successed to create inBuf cl_mem buffer.\n\n");
		}
	}
	if(outBuf == NULL){
		outBuf = clCreateBuffer(context, CL_MEM_WRITE_ONLY, pkey->crypto_len * sizeof(uint8_t), NULL, &errNum);
		if(errNum != CL_SUCCESS){
			printf("Failed to create outBuf cl_mem buffer.\n\n");
			memBufPrintErr(errNum);
			exit(1);
		}
		else{
			printf("Successed to create outBuf cl_mem buffer.\n\n");
		}
	}
	if(roundKeyBuf == NULL){
		roundKeyBuf = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(roundkey), roundkey, &errNum);
		if(errNum != CL_SUCCESS){
			printf("Failed to create roundKeyBuf cl_mem buffer.\n\n");
			memBufPrintErr(errNum);
			exit(1);
		}
		else{
			printf("Successed to create roundKeyBuf cl_mem buffer.\n\n");
		}
	}
	if(ivBuf == NULL){
		ivBuf = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(iv), iv, &errNum);
		if(errNum != CL_SUCCESS){
			printf("Failed to create ivBuf cl_mem buffer.\n\n");
			memBufPrintErr(errNum);
			exit(1);
		}
		else{
			printf("Successed to create ivBuf cl_mem buffer.\n\n");
		}
	}






	//Setting OpenCL kernel's arguments
	errNum = clSetKernelArg(kernel, 0, sizeof(cl_mem), &inBuf);
	errNum |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &outBuf);
	errNum |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &roundKeyBuf);
	errNum |= clSetKernelArg(kernel, 3, sizeof(cl_mem), &ivBuf);
	if(errNum != CL_SUCCESS){
		printf("Failed to set OpenCL kernel arguments.");
		exit(1);
	}






	//Setting OpenCL kernel's run dimension and size
	size_t globalWorkSize[WORK_DIM];
	size_t localWorkSize[WORK_DIM];
	globalWorkSize[0] = pkey->crypto_len / SeedBlockSize;
	localWorkSize[0] = 1;






	//Running OpenCL kernel
	errNum = clEnqueueNDRangeKernel(commandQueue, kernel, WORK_DIM, NULL, globalWorkSize, localWorkSize, 0, NULL, NULL);
	if(errNum != CL_SUCCESS){
		printf("Failed to run OpenCL kernel.");
		switch(errNum){
			case CL_INVALID_PROGRAM_EXECUTABLE: printf("CL_INVALID_PROGRAM_EXECUTABLE \n"); break;
			case CL_INVALID_COMMAND_QUEUE: printf("CL_INVALID_COMMAND_QUEUE \n"); break;
			case CL_INVALID_KERNEL: printf("CL_INVALID_KERNEL \n"); break;
			case CL_INVALID_CONTEXT: printf("CL_INVALID_CONTEXT \n"); break;
			case CL_INVALID_KERNEL_ARGS: printf("CL_INVALID_KERNEL_ARGS \n"); break;
			case CL_INVALID_WORK_DIMENSION: printf("CL_INVALID_WORK_DIMENSION \n"); break;
			case CL_INVALID_WORK_GROUP_SIZE: printf("CL_INVALID_WORK_GROUP_SIZE \n"); break;
			case CL_INVALID_WORK_ITEM_SIZE: printf("CL_INVALID_WORK_ITEM_SIZE \n"); break;
			case CL_INVALID_GLOBAL_OFFSET: printf("CL_INVALID_GLOBAL_OFFSET \n"); break;
			case CL_OUT_OF_RESOURCES: printf("CL_OUT_OF_RESOURCES \n"); break;
			case CL_MEM_OBJECT_ALLOCATION_FAILURE: printf("CL_MEM_OBJECT_ALLOCATION_FAILURE \n"); break;
			case CL_INVALID_EVENT_WAIT_LIST: printf("CL_INVALID_EVENT_WAIT_LIST \n"); break;
			case CL_OUT_OF_HOST_MEMORY: printf("CL_OUT_OF_HOST_MEMORY \n"); break;
			default: break;
		}
		exit(1);
	}





	//Reading plain text from OpenCL device
	/*errNum = clEnqueueReadBuffer(commandQueue, outBuf, CL_TRUE, 0, pkey->crypto_len * sizeof(uint8_t), pkey->plain, 0, NULL, NULL);
	if(errNum != CL_SUCCESS){
		printf("Failed to copy plain string from OpenCL device to OpenCL host.");
		exit(1);
	}*/
	printf("iter\n");
}
void memBufPrintErr(int errNum)
{
	switch(errNum){
		case CL_INVALID_CONTEXT: printf("context is not a valid context.."); break;
		case CL_INVALID_VALUE: printf("values specified in flags are not valid."); break;
		case CL_INVALID_BUFFER_SIZE: printf("size is 0 or is greater than CL_DEVICE_MAX_MEM_ALLOC_SIZE value specified in table of OpenCL Device Queries for clGetDeviceInfo for all devices in context."); break;
		case CL_INVALID_HOST_PTR: printf("host_ptr is NULL and CL_MEM_USE_HOST_PTR or CL_MEM_COPY_HOST_PTR are set in flags or if host_ptr is not NULL but CL_MEM_COPY_HOST_PTR or CL_MEM_USE_HOST_PTR are not set in flags."); break;
		case CL_MEM_OBJECT_ALLOCATION_FAILURE: printf("if there is a failure to allocate memory for buffer object."); break;
		case CL_OUT_OF_HOST_MEMORY: printf("there is a failure to allocate resources required by the OpenCL implementation on the host."); break;
		default: break;
	}
}