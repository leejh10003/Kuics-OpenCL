#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "BasicIO.h"

int scanfile (const char name[]) // ������ ���� ���� �˻�
{
	FILE *fp;
	int is_file_exist = TRUE;

    fp = fopen(name, "r");
	if (fp == NULL)
		is_file_exist = FALSE;
	else
		fclose(fp);
	return is_file_exist;
}

char* scanstr (int strlong, char *str) // ���ڿ��� �����÷ο���� �ʴ� scanf ��� �Լ�
{ // ������ �ԷµǴ� ���ڿ� ���̴� strlong - 2. \n�� NULL ���� �����̴�.
	size_t lentmp;
	fgets(str, strlong, stdin);
	lentmp = strlen(str);
	str[lentmp - 1] = '\0';
	return str;
}

int WhatBitOS() // ���Ʈ �������ΰ� �˾Ƴ���
{
	if (sizeof(int*) == 4)
		return 32;
	else if (sizeof(int*) == 8)
		return 64;
	else
		return (sizeof(int*) * 8);
}

uint8_t BytePrefix(uint64_t sizelen)
{
	uint8_t whatbyte;

    if (sizelen < BIN_KILOBYTE) // Byte
		whatbyte = ENUM_BYTE;
	else if (sizelen < BIN_MEGABYTE) // KB
		whatbyte = ENUM_KILOBYTE;
	else if (sizelen < BIN_GIGABYTE) // MB
		whatbyte = ENUM_MEGABYTE;
	else // GB
		whatbyte = ENUM_GIGABYTE;

	return whatbyte;
}

int CompileYear () // �������� �⵵
{
	const char macro[16] = __DATE__;
	char stmp[8] = {0}; // ��ü 0���� �ʱ�ȭ

	stmp[0] = macro[7];
	stmp[1] = macro[8];
	stmp[2] = macro[9];
	stmp[3] = macro[10];
	stmp[4] = '\0';

	return atoi(stmp);
}

int CompileMonth ()
{ // �������� �� ǥ��
	const char macro[16] = __DATE__;
	const char smonth[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	int i = 0;

// �� ����
	for (i = 0; i < 12; i++)
	{
		if (strstr(macro, smonth[i]) != NULL)
			return i + 1;
	}

// -1�� ��ȯ�Ǵ� ���� �� �ν� �Ұ�
	return -1;
}

int CompileDate ()
{ // �������� �� ǥ��
	const char macro[16] = __DATE__;
	char stmp[4] = {0}; // ��ü 0���� �ʱ�ȭ

// �� ����
	stmp[0] = macro[4];
	stmp[1] = macro[5];
	stmp[2] = '\0';
	return atoi(stmp);
}

long ReadFileSize(const char* filename)
{
	FILE *fp = NULL;
	long filesize;

	if (!(scanfile(filename)))
	{ // ������ �������� �ʴٸ�
		fprintf(stderr, "Error in ReadFileSize()\n%s not exists!\n", filename);
		return -1;
	}

	fp = fopen(filename, "r"); // fp���� ������ �� ��
	fseek(fp, 0, SEEK_END); // �����͸� �� �ڷ� �̵�
	filesize = ftell(fp); // ũ�⸦ sizelen�� �ִ´�.
	fclose(fp); // ���� �ݱ�
	return filesize;
}

void DumpBinary(const uint8_t buf[], const uint32_t bufsize)
{
	uint32_t base = 0;
	uint32_t interval = 16;
	while (base < bufsize)
	{
		if (base + 16 < bufsize)
			interval = 16;
		else
			interval = bufsize - base;

		printf("0x%04x:   ", base);
		for (uint32_t i = base; i < base + 16; i++) // i for dump
		{
			if (i < base + interval)
				printf("%02x", buf[i]);
			else
			{
				putchar(' ');
				putchar(' ');
			}

			if ((i+1) % 2 == 0)
				putchar(' ');
			if ((i+1) % 8 == 0)
				putchar(' ');
		}
		putchar(' ');
		putchar(' ');
		for (uint32_t i = base; i < base + 16; i++) // i for dump
		{
			if (i < base + interval)
			{
				if (0x20 <= buf[i] && buf[i] <= 0x7E)
					printf("%c", buf[i]);
				else
					putchar('.');
			}
			else
			{
				putchar(' ');
				putchar(' ');
			}

			if ((i+1) % 8 == 0)
				putchar(' ');
		}
		putchar('\n');


		if (base + 16 < bufsize)
			base += 16;
		else
			base = bufsize;
	}

	return;
}

// Padding Compile�δ� ����. ���� 3082������ �˻�
int IsPKCS5PaddingOK(const uint8_t* buf, const uint32_t buflen)
{
	if (buf[0] != 0x30 || buf[1] != 0x82)
		return FALSE;

	for (int i = 1; i < buf[buflen-1]; i++)
	{
		if (buf[buflen-1-i] != buf[buflen-1])
			return FALSE;
	}

	if (buf[buflen-1] == 0)
		return FALSE;

	return TRUE;
}

uint64_t ipow (uint32_t low, uint32_t upper)
{
	uint64_t result = 1;
	for (uint32_t i = 0; i < upper; i++)
		result *= low;
	return result;
}
