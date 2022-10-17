/*
The public/private keys used in this task are the same as the ones used in Task 2. Please decrypt the following
ciphertext C, and convert it back to a plain ASCII string

C = 8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F
n = DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5
e = 010001 (this hex value equals to decimal 65537)
d = 74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D
*/

#include <stdio.h>
#include <openssl/bn.h>

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *e =BN_new();
    BIGNUM *message = BN_new();
    BIGNUM *Ciphertxt = BN_new();
    
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    printBN("n: ", n);

    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    printBN("d: ",d);

    BN_hex2bn(&Ciphertxt, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
    printBN("Ciphertext before decyrption: ",message);
    
    //calculate C = m^d mod n
    BN_mod_exp(message, Ciphertxt, d, n, ctx);
    printBN("Message in hex after decryption ",message);
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