#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <iostream>
#include <fstream>
#include <sstream>
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif
#include "jjOpenCLBasic.hpp"
#include "ErrorHandle.h"
#include "BasicIO.h"
#include "Hash.h"
#include "Seed.h"
#include "NPKICrack.h"

using namespace std;

int main(int argc, char ** argv)
{
	//OpenCL 초기화
	cl_context context = 0;
	cl_command_queue commandQueue = 0;
	cl_device_id device;
	cl_program program = 0;
	cl_int errNum = 0;
	cl_int retNum = 0;
	cl_kernel kernel = 0;


	context = createContext();
	commandQueue = createCommandqueue(context, &device);
	program = CreateProgram(context, device, "kernel.cl");
	kernel = CreateKernel(program, "JV_SEED_CBC128_Decrypt_OneBlock");
	//OpenCL 초기화 종료



// This file is saved with PKCS#8 file format, and the key is encrypted with PKCS#5's PBKDF1
// 변수 선언 및 초기화
    NPKIPrivateKey pkey; 	// NPKI Private Key Struct
    NPKIBruteForce bforce;	// NPKI Brute Force Struct
	// 찾았다면 TRUE로 SET
	int arg_file	= FALSE;
	int arg_min		= FALSE;
	int arg_max 	= FALSE;
	int arg_charset	= FALSE;
	int arg_initial	= FALSE;

    InitNPKIBruteForce(&bforce);

// Welcome Print
	printf(	"Joveler and joonji's NPKI Craker for Inc0gntio 2015\n"
			"(%dbit Build, Compile Date %04d.%02d.%02d)\n\n",
			WhatBitOS(), CompileYear(), CompileMonth(), CompileDate());

// ./NPKICracker -f [PrivateKeyFile] -m [MinPWLen] -M [MaxPWLen] -c [PWCharset] -i [StartFrom]
	if (argc == 1)
	{
		JVWarnHandle(JVWARN_NOT_ENOUGH_ARGV);
		JV_Help();
		exit(JVWARN_NOT_ENOUGH_ARGV);
	}

	// Search for arguments
	for (int i = 1; i < argc; i++)
	{ // 이 루프를 돌며 -f, -m, -M, -c, -i를 찾는다.
		if (strcmp(argv[i], "-f") == 0)
		{  // -f signPri.key, 파일 존재
			if (i+1 != argc && scanfile(argv[i+1]))
			{
				arg_file = TRUE;
				bforce.pkey_path = argv[i+1];
			}
			else
				JVErrorHandle(JVERR_PRIVATE_KEY_NOT_EXIST);
		}
		else if (strcmp(argv[i], "-m") == 0)
		{ // -m 10
			if (i+1 != argc && 0 < atoi(argv[i+1]))
			{
				arg_min = TRUE;
				bforce.pw_min_len = atoi(argv[i+1]);
			}
			else
				JVErrorHandle(JVERR_PW_MIN_LENGTH_NOT_EXIST);
		}
		else if (strcmp(argv[i], "-M") == 0)
		{ // -m 15
			if (i+1 != argc && 0 < atoi(argv[i+1]))
			{
				arg_max = TRUE;
				bforce.pw_max_len = atoi(argv[i+1]);
			}
			else
				JVErrorHandle(JVERR_PW_MAX_LENGTH_NOT_EXIST);
		}
		else if (strcmp(argv[i], "-c") == 0)
		{ // -c Charset.txt
			if (i+1 != argc && scanfile(argv[i+1]))
			{
				arg_charset = TRUE;
				bforce.pw_charset_path = argv[i+1];
			}
			else
				JVErrorHandle(JVERR_PW_CHARSET_NOT_EXIST);
		}
		else if (strcmp(argv[i], "-i") == 0)
		{ // -i pwpigeon
			if (i+1 != argc)
			{
				arg_initial = TRUE;
				bforce.pw_init = argv[i+1];
			}
			else
				JVErrorHandle(JVERR_PW_INITIAL_NOT_EXIST);
		}
	}

	if (!arg_file) // PrivateKeyFile이 없다면
		JVErrorHandle(JVERR_PRIVATE_KEY_NOT_EXIST);
	if (!arg_min) // Default
		bforce.pw_min_len = 8;
	if (!arg_max) // Default
		bforce.pw_max_len = 16;
	if (!arg_charset)
		JVErrorHandle(JVERR_PW_CHARSET_NOT_EXIST);


// Read and Parse NPKI Private Key Struct
	InitNPKIPrivateKey(&pkey);
	ReadRawNPKIPrivateKey(&pkey, bforce.pkey_path);
	ParseNPKIPrivateKey(&pkey);
	printf("= Reading NPKI Private Key File Complete =\n");

// Read and Parse Password Charset
	if (ReadPasswordCharset(&bforce) == FALSE)
		JVErrorHandle(JVERR_PW_CHARSET_DUPLICATE);
	printf("= Reading Password Charset File Complete =\n");


// Validate Initial Password
	if (arg_initial)
	{
		if (ValidateInitialPW(&bforce) == FALSE)
			JVErrorHandle(JVERR_PW_INITIAL_NOT_VALID);
		SetCursorFromInitialPW(&bforce);
		printf("= Reading Initial Password Complete =\n");
	}
	else
	{
		ReadyNPKIBruteForce(&bforce);
	}

// Calculate MAX Cursor -> Used for calculating percent realtime
	GetMaxCursor(&bforce);
	SetStartTime(&bforce);

// Print Session Info
    PrintBruteForceEnvInfo(&bforce);
    putchar('\n');
	putchar('\n');

// Now, do BruteForce!
	printf("= Press Enter to start BruteForce... =\n");
	getchar();
	putchar('\n');
	if (BruteForceIteratorOpenCL(&pkey, &bforce, kernel, context, commandQueue)) // Found it. If there is no Problem, convert this line to int BruteForceIteratorOpenCL(&pkey, &bforce, kernel, context, commandQueue)
	{
		printf(	"\n= Decrypt Success =\n"
				"Password is \'%s\'\n\n", bforce.password);

#ifdef _DEBUG_RESULT
		puts("\n== Decrypted Data ==");
		DumpBinary(pkey.plain, pkey.crypto_len);
#endif
		return TRUE;
	}
	else
	{
		printf(	"\n= Decrypt Failed =\n"
				"Please change password range or charset and run again.\n\n");
	}


// Free NPKI Private Key Struct
	FreeNPKIPrivateKey(&pkey);
	return 0;
}