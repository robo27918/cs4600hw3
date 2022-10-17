/*
    message = 4c61756e63682061206d697373696c652e  ->"Launch a missle."
    S = 643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F
    e = 010001 (this hex value equals to decimal 65537)
    n = AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115
*/
#include <stdio.h>
#include <openssl/bn.h>

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *S =BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *message = BN_new();
    BIGNUM *calc_message = BN_new();
  
    
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    printBN("n: ", n);

    BN_hex2bn(&e, "010001");
    printBN("e: ",e);
    BN_hex2bn(&S,"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    printBN("Signature from message:  ", S); 
    
    BN_hex2bn(&message, "4c61756e63682061206d697373696c652e");
    printBN("actual Message should be equal to: ",message);
    
    //calculate C = m^d mod n
    BN_mod_exp(calc_message, S, e, n, ctx);
    printBN("calculate value of message :  ", message);

    return 0;
}
void printBN(char *msg, BIGNUM * a)
{
    //convert the BIGNUM to number string
    char * num_str = BN_bn2hex(a);
    //print out num_str
    printf("%s %s\n",msg,num_str);
    //free dynamically allocated memory
    OPENSSL_free(num_str);
}