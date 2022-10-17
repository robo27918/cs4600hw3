/*
Author: Roberto S. Toribio
CS4600: HW3-TASK1

Problem stmt:
Let p, q, and e be three prime numbers. Let n = p*q. We will use (e, n) as the public key. Please
calculate the private key d. The hexadecimal values of p, q, and e are listed in the following. It should be
noted that although p and q used in this task are quite large numbers, they are not large enough to be secure.
We intentionally make them small for the sake of simplicity. In practice, these numbers should be at least
512 bits long (the one used here are only 128 bits).

p = F7E75FDC469067FFDC4E847C51F452DF
q = E85CED54AF57E53E092113E62F436F4F
e = 0D88C3
*/

//declare p,q,and e as BIGNUM data types
#include <stdio.h>
#include <openssl/bn.h>

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p =BN_new();
    BIGNUM *q =BN_new();
    BIGNUM *e =BN_new();
    BIGNUM *n =BN_new();
    BIGNUM *phi_n = BN_new();
    BIGNUM *p_sub_1  = BN_new();
    BIGNUM *q_sub_1 = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM * one = BN_new();
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");
    BN_dec2bn(&one ,"1");
    printBN("p: ", p);
    printBN("q: ",q);
    printBN("e: ",e);
    printBN("ONE in hex is: ",one);
    
    //step1: calculate n
    BN_mul(n,p,q,ctx);
    printBN("the value of n is: ",n);
    //step2 :initialize phi_n = (p-1)(q-1)
    BN_sub(p_sub_1,p,one);
    printBN("the value of p_sub_1 ",p_sub_1 );
    BN_sub(q_sub_1,q,one);
    printBN("the value of q_sub_1 ",q_sub_1 );
    BN_mul (phi_n,p_sub_1,q_sub_1,ctx);
    printBN("the value of phi_n",phi_n);

    
   
    
    

    //step 3: solve for d:private key (decyrption key)
    // e * d = 1 mod phi(n)
    BN_mod_inverse(d,e,phi_n,ctx);
    printBN("The value of d: ", d);
    
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