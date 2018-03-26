#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#define BUF_SIZE 256
#define sha "objcopy -j.sha "
#define restore "objcopy -R.sha "
#define ver1 "openssl dgst -sha256 -verify " 
#define ver2 " -signature digest "
#define digest "digest" 
#define safe "safe"
#define ok "OK"
#define failure "Failure"
int main(int argc, char **argv)
{
    FILE *binary;
    FILE *public_key;
    bool legit = false;
	char path[100];
    if(argc < 3)
    {
        fprintf(stderr, "Usage: loader <secured binary> <public key>\n");
        exit(1);
    }
    else if(argc == 3)
    {
        //Open binary
        binary = fopen(argv[1], "rb");
        if (!binary)
        {
            fprintf(stderr, "Unable to open binary %s\n", argv[1]);
            return 1;
        }
        fclose(binary);
        
        //Open key
        public_key = fopen(argv[2], "rb");
        if (!public_key)
        {
            fprintf(stderr, "Unable to open public_key %s\n", argv[2]);
            return 1;
        }
        fclose(public_key);
	
        FILE *fp;
        char extract_sign[80] = sha;
        strcat(extract_sign, argv[1]);
        strcat(strcat(extract_sign, " "), digest);
        char verify[80] = ver1;
        strcat(strcat(verify, argv[2]), ver2);
        strcat(verify, argv[1]);
        char exec[80] = restore;
        strcat(strcat(exec, argv[1]), safe);
        
        fp = popen(extract_sign, "r");
        if (fp == NULL) 
        {
            fprintf(stderr, "Failed to run command : %s\n", extract_sign);
            perror("Error with popen");
            exit(1);
        }
        /* close */
        pclose(fp);
        printf("%s\n\n", verify);
        fp = popen(verify, "r");
        if (fp == NULL) 
        {
            fprintf(stderr, "Failed to run command : %s\n", verify);
            perror("Error with popen");
            exit(1);
        }
        /* Read the output a line at a time - output it. */
        while (fgets(path, sizeof(path)-1, fp) != NULL) 
        {
            if(strstr(path, ok) != NULL)
            {
                legit = true;
                break;
            }
            else if(strstr(path, failure) != NULL)
            {
                fprintf(stderr, "Failed while verificating the digest\n");
                exit(1);
            }
        }
        /* close */
        pclose(fp);
        
        if(legit)
        {
            fp = popen(exec, "r");
            if (fp == NULL) 
            {
                fprintf(stderr, "Failed to run command : %s\n", exec);
                perror("Error with popen");
                exit(1);
            }
            /* close */
            pclose(fp);
            system(safe);
        }
    }
    else
    {
        fprintf(stderr, "Usage: loader <secured binary> <public key>\n");
        exit(1);
    }        
    
    return 0;
}