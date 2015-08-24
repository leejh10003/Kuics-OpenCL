#include <stdio.h>
#include <stdlib.h>

#include "ErrorHandle.h"

void JVErrorHandle(int code)
{
	char *msg = NULL;
	switch (code)
	{
	case JVERR_PRIVATE_KEY_NOT_EXIST:
		msg =	"ErrorMessage : JVERR_PRIVATE_KEY_NOT_EXIST\n"
				"NPKI private key argument doesn't exist!\n";
		break;
	case JVERR_PW_MIN_LENGTH_NOT_EXIST:
		msg = 	"ErrorMessage : JVERR_PW_MIN_LENGTH_NOT_EXIST\n"
				"Please specify password's minimum length.\n";
		break;
	case JVERR_PW_MAX_LENGTH_NOT_EXIST:
		msg = 	"ErrorMessage : JVERR_PW_MAX_LENGTH_NOT_EXIST\n"
				"Please specify password's maximum length.\n";
		break;
	case JVERR_PW_CHARSET_NOT_EXIST:
		msg = 	"ErrorMessage : JVERR_PW_CHARSET_NOT_EXIST\n"
				"Please specift valid charset file's path.\n";
		break;
	case JVERR_PW_CHARSET_TOO_LONG:
		msg = 	"ErrorMessage : JVERR_PW_CHARSET_TOO_LONG\n"
				"Password Charset is too long. Cannot be over MAX_PW_CHARSET\n";
		break;
	case JVERR_PW_INITIAL_NOT_EXIST:
		msg = 	"ErrorMessage : JVERR_PW_INITIAL_NOT_EXIST\n"
				"Initial password argument doesn't exist!\n";
		break;
	case JVERR_PW_INITIAL_NOT_VALID:
		msg = 	"ErrorMessage : JVERR_PW_INITIAL_NOT_VALID\n"
				"Initial password is not valid with charset\n";
		break;
	case JVERR_PW_CHARSET_DUPLICATE:
		msg = 	"ErrorMessage : JVERR_PW_CHARSET_DUPLICATE\n"
				"There are duplicated character in charset.\n";
		break;
	default:
		msg = 	"ErrorMessage : UNDEFINDED ERROR\n"
				"Undefined Error\n";
		break;
	}
    printf("ErrorCode : %d\n%s", code, msg);
    exit(code);
}

void JVWarnHandle(int code)
{
	char *msg = NULL;
	switch (code)
	{
	case JVWARN_NOT_ENOUGH_ARGV:
		msg = "WarnMessage : JVWARN_NOT_ENOUGH_ARGV\nNot enough argv\n";
		break;
	case JVWARN_NOT_VALID_ARGV:
		msg = "WarnMessage : JVWARN_NOT_VALID_ARGV\nNot valid argv\n";
		break;
	default:
		msg = "WarnMessage : UNDEFINDED WARNING\nUndefined Warning\n";
		break;
	}
    printf("WarnCode : %d\n%s", code, msg);
}
void JV_Help ()
{
	printf(	"Usage\n"
			"./NPKICracker -f [PrivateKeyFile] -m [MinPWLen] -M [MaxPWLen] -c [PWCharsetFile] -s [StartFrom]\n"
			"\n"
			"-f : Must Provide NPKI's private key file path\n"
			"-m : Minimum length of attacking password (default is 8)\n"
			"-M : Maximum length of attacking password (default is 12)\n"
			"-c : Charset pool of attacking password\n"
			"-s : Start from this password\n"
			"Password must not be longer than 32.");
}