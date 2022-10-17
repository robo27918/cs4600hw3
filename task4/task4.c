/*
The public/private keys used in this task are the same as the ones used in Task 2. Please generate a signature
for the following message (please directly sign this message, instead of signing its hash value):
M = I owe you $2000.
Please make a slight change to the message M, such as changing $2000 to $3000, and sign the modified
message. Compare both signatures and describe what you obser

e = 010001 (this hex value equals to decimal 65537)
d = 74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D
M =49206f776520796f752024323030302e
M_diff = 49206f776520796f752024353035302e
*/
#include <stdio.h>
#include <openssl/bn.h>

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d =BN_new();
    BIGNUM *message = BN_new();
    //message_diff used for comparison of how a small change affects signature.
    BIGNUM *message_diff = BN_new();
    BIGNUM *Sig = BN_new();
    
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    printBN("n: ", n);

    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    printBN("d: ",d);

    BN_hex2bn(&message, "49206f776520796f752024323030302e");
    //printBN("Ciphertext before decyrption: ",message);
    
    //calculate C = m^d mod n
    BN_mod_exp(Sig, message, d, n, ctx);
    printBN("Signature from message:  ", Sig);

    //create signature for message_dif = "I owe you $5050."
     BN_hex2bn(&message_diff, "49206f776520796f752024353035302e");
     BN_mod_exp(Sig, message_diff, d, n, ctx);
    printBN("Signature from message_diff:  ", Sig);
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