/*
Let (e, n) be the public key. Please encrypt the message "A top secret!" (the quotations are not
included). We need to convert this ASCII string to a hex string, and then convert the hex string to a BIGNUM
using the hex-to-bn API BN hex2bn(). The following python command can be used to convert a plain
ASCII string to a hex string.


n = DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5
e = 010001 (this hex value equals to decimal 65537)
M = A top secret! --> 4120746f702073656372657421
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

    BN_hex2bn(&e, "010001");
    printBN("e: ",e);
    BN_hex2bn(&message, "4120746f702073656372657421");
    printBN("message: ",message);
    
    //calculate C = m^e mod n
    BN_mod_exp(Ciphertxt, message, e, n, ctx);
    printBN("Cipher text after encryption is: ",Ciphertxt);
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