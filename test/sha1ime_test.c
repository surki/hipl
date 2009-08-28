/*
 * Original from:
 * http://www1.ietf.org/mail-archive/web/cfrg/current/msg01157.html
 */

/*
 *  sha1ime_test.c
 *
 *  Description:
 *      This file will exercise the SHA-1 code performing the three
 *      tests documented in FIPS PUB 180-1 plus one which calls
 *      SHA1Input with an exact multiple of 512 bits, plus a few
 *      error test checks.
 *
 *  Portability Issues:
 *      None.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sha1ime.h"

/*
 *  Define patterns for testing
 */
#define TEST1   "abc"
#define TEST2a  "abcdbcdecdefdefgefghfghighijhi"

#define TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define TEST2   TEST2a TEST2b
#define TEST3   "a"
#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
    /* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b
char *testarray[4] =
{
    TEST1,
    TEST2,
    TEST3,
    TEST4
};
long int repeatcount[4] = { 1, 1, 1000000, 10 };
char *resultarray[4] = {
    "3E AE 19 1E 55 5C 3D 4C 31 4B FC D7 09 87 5B 6E 51 80 03 F5", 
    "E4 B0 EC E7 05 2E 65 ED 6F 52 B6 6B B2 3D 9F 3D 1D CC 17 7A",
    "3C 00 62 58 34 0D B1 0B A3 68 27 70 A4 CB 6F 30 EF BC 26 5C",
    "11 FD 36 AA 29 F6 9C 4C 90 4D 92 2C A3 7B FB C2 AA 63 5E 27"
};

int main()
{
    SHA1IMEContext sha;
    int i, j, err;
    uint8_t Message_Digest[20];

    /*
     *  Perform SHA1-IME tests
     */
    for(j = 0; j < 4; ++j)
    {
        printf( "\nTest %d: %d, '%s'\n",
                j+1,
                repeatcount[j],
                testarray[j]);

        err = SHA1IMEReset(&sha);
        if (err)
        {
            fprintf(stderr, "SHA1IMEReset Error %d.\n", err );
            break;    /* out of for j loop */
        }

        for(i = 0; i < repeatcount[j]; ++i)
        {

            err = SHA1IMEInput(&sha,
                  (const unsigned char *) testarray[j],
                  strlen(testarray[j]));
            if (err)
            {
                fprintf(stderr, "SHA1IMEInput Error %d.\n", err );
                break;    /* out of for i loop */
            }
        }

        err = SHA1IMEResult(&sha, Message_Digest);
        if (err)
        {
            fprintf(stderr,
            "SHA1IMEResult Error %d, could not compute message digest.\n",
            err );
        }
        else
        {
            printf("\t");
            for(i = 0; i < 20 ; ++i)
            {
                printf("%02X ", Message_Digest[i]);
            }
            printf("\n");
        }
        printf("Should match:\n");
        printf("\t%s\n", resultarray[j]);
    }

    /* Test some error returns */
    err = SHA1IMEInput(&sha,(const unsigned char *) testarray[1], 1);
    printf ("\nError %d. Should be %d.\n", err, shaStateError );
    err = SHA1IMEReset(0);
    printf ("\nError %d. Should be %d.\n", err, shaNull );
    return 0;
}
