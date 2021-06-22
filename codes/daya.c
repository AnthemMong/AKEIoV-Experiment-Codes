//2020 11-22
//compile: gcc daya.c -lgmp -lpbc -lcrypto -o daya
// Provably Secure and Lightweight ID-2PAKA Protocol For IIoT Environment
# include<pbc/pbc.h>
# include<pbc/pbc_test.h>
# include<openssl/sha.h>
# include<openssl/aes.h>
# include<string.h>
# include<stdlib.h>
# include<stdio.h>
# include<time.h>

# define HASH_LEN 20
# define MAXLEN 4096
# define MAX_PARAM 6

void h1(unsigned char* result, element_t *e1);
void h2(unsigned char* result, unsigned char* estr, int len);
void combine(unsigned char* result,  element_t* es[], int size);

int main(int argc, char* argv[])
{
    pairing_t pairing;
    double time1, time2, time3, time4;
    int byte1, byte2;
    int len1, len2, len3, maxlen;
    int comm_traffic;


    element_t P, P0, Psi1, Psi2, Pr1, Pr2, Sigma1, Sigma2, X1, X2, G1temp1, G1temp2;
    element_t s, ID1, ID2, q1, q2, q12, q21, r1, r2, sk1, sk2, Zntemp1, Zntemp2, Zntemp3;
    element_t GTtemp1, GTtemp2;

    unsigned char hash_result[HASH_LEN];
    unsigned char temp1[MAXLEN];
    unsigned char temp2[MAXLEN];
    unsigned char temp3[MAXLEN];

    element_t* params[MAX_PARAM];

    pbc_demo_pairing_init(pairing, argc, argv);

    if (!pairing_is_symmetric(pairing))
    {
        fprintf(stderr, "only works with symmetric pairing\n");
        exit(1);
    }
    element_init_G1(P, pairing);
    element_init_G1(P0, pairing);
    element_init_G1(Psi1, pairing);
    element_init_G1(Psi2, pairing);
    element_init_G1(Pr1, pairing);
    element_init_G1(Pr2, pairing);
    element_init_G1(Sigma1, pairing);
    element_init_G1(Sigma2, pairing);
    element_init_G1(X1, pairing);
    element_init_G1(X2, pairing);
    element_init_G1(G1temp1, pairing);
    element_init_G1(G1temp2, pairing);

    element_init_Zr(s, pairing);
    element_init_Zr(ID1, pairing);
    element_init_Zr(ID2, pairing);
    element_init_Zr(q1, pairing);
    element_init_Zr(q2, pairing);
    element_init_Zr(q12, pairing);
    element_init_Zr(q21, pairing);
    element_init_Zr(r1, pairing);
    element_init_Zr(r2, pairing);
    element_init_Zr(sk1, pairing);
    element_init_Zr(sk2, pairing);
    element_init_Zr(Zntemp1, pairing);
    element_init_Zr(Zntemp2, pairing);
    element_init_Zr(Zntemp3, pairing);

    element_init_GT(GTtemp1, pairing);
    element_init_GT(GTtemp2, pairing);

    time1 = pbc_get_time();
    element_random(s);
    element_random(P);
    element_mul_zn(P0, P, s);

    time2 = pbc_get_time();
    printf("PKG init: %fs\n", time2 - time1);

    printf("Private Key Extracting......\n");
    time1 = pbc_get_time();

    // int i;
    // for (i = 0; i < 100; i++)
    // {
        element_random(ID1);
        element_random(ID2);

        h1(hash_result, &ID1);
        element_from_hash(q1, hash_result, HASH_LEN);
        element_add(Zntemp1, s, q1);
        element_invert(Zntemp2, Zntemp1);
        element_mul(Zntemp3, s, Zntemp2);
        element_mul_zn(Pr1, P, Zntemp3);

        h1(hash_result, &ID2);
        element_from_hash(q2, hash_result, HASH_LEN);
        element_add(Zntemp1, s, q2);
        element_invert(Zntemp2, Zntemp1);
        element_mul(Zntemp3, s, Zntemp2);
        element_mul_zn(Pr2, P, Zntemp3);
    //}

    

    time2 = pbc_get_time();
    printf("Key extracting time: %fs\n", time2 - time1);
    fprintf(stderr, "%0.2f, ", (time2 - time1) * 1000);

    printf("Key Agreement......\n");
    time1 = pbc_get_time();

    element_random(r1);
   
    element_mul_zn(Psi1, P, r1);
    element_mul_zn(Sigma1, Pr1, r1);
    
    element_random(r2);
    element_mul_zn(Psi2, P, r2);
    element_mul_zn(Sigma2, Pr2, r2);

    
    h1(hash_result, &ID2);
    element_from_hash(q12, hash_result, HASH_LEN);
    element_mul_zn(G1temp1, P, q12);
    element_add(G1temp2, P0, G1temp1);
    
    element_pairing(GTtemp1, Sigma2, G1temp2);
    
    element_pairing(GTtemp2, Psi2, P0);
    
    // if (element_cmp(GTtemp1, GTtemp2) == 0)
    //     printf("Accept!\n");
    // else 
    //     printf("Reject!\n");

    element_mul_zn(X1, Psi2, r1);
    
    h1(hash_result, &ID1);
    element_from_hash(q21, hash_result, HASH_LEN);
    element_mul_zn(G1temp1, P, q21);
    element_add(G1temp2, P0, G1temp1);
    element_pairing(GTtemp1, Sigma1, G1temp2);

    element_pairing(GTtemp2, Psi1, P0);

    
    // if (element_cmp(GTtemp1, GTtemp2) == 0)
    //     printf("Accept!\n");
    // else 
    //     printf("Reject!\n");
    element_mul_zn(X2, Psi1, r2);

 
    memset(temp1, 0, MAXLEN);
    len1 = element_length_in_bytes(ID1) + element_length_in_bytes(ID2) + element_length_in_bytes(Psi1) + element_length_in_bytes(Psi2) + element_length_in_bytes(X1);
    params[0] = &ID1;
    params[1] = &ID2;
    params[2] = &Psi1;
    params[3] = &Psi2;
    params[4] = &X1;
    combine(temp1, params, 5);
    h2(hash_result, temp1, len1);
    element_from_hash(sk1, hash_result, HASH_LEN);

    
    memset(temp2, 0, MAXLEN);
    len2 = element_length_in_bytes(ID1) + element_length_in_bytes(ID2) + element_length_in_bytes(Psi1) + element_length_in_bytes(Psi2) + element_length_in_bytes(X1);      
    params[0] = &ID1;
    params[1] = &ID2;
    params[2] = &Psi1;
    params[3] = &Psi2;
    params[4] = &X2;
    combine(temp2, params, 5);
    h2(hash_result, temp2, len1);
    element_from_hash(sk2, hash_result, HASH_LEN);

    time2 = pbc_get_time();
    element_printf("sk1: %B\n", sk1);
    element_printf("sk2: %B\n", sk2);


    printf("Key agreement time: %fs\n", time2 - time1);
    fprintf(stderr, "%0.2f\n", (time2 - time1) * 1000);
    comm_traffic = element_length_in_bytes(Psi1) + element_length_in_bytes(Psi2) + element_length_in_bytes(Sigma1) + element_length_in_bytes(Sigma2); 
    printf("Communication traffic: %d\n", comm_traffic);
    printf("Key memeory cost: %d\n", 2 * (element_length_in_bytes(Psi1) + element_length_in_bytes(q1)));
    
    return 0;
}

void h1(unsigned char* result, element_t *e1)
{
    int elelen;
    unsigned char* estr;
    elelen = element_length_in_bytes(*e1);

    estr = (unsigned char*)malloc(sizeof(unsigned char) * elelen);
    if (estr == NULL)
    {
        fprintf(stderr, "error!\n");
        exit(0);
    }
    element_snprintf(estr, elelen, "%B", *e1);
    SHA1((const unsigned char *)estr, strlen(estr),  result);
    free(estr);
}

void h2(unsigned char* result, unsigned char* estr, int len)
{
    SHA1((const unsigned char *)estr, len, result);
}

void combine(unsigned char* result,  element_t* es[], int size)
{
    int i, len;
    unsigned char* ptr;

    ptr = result;
    for (i = 0; i < size; i++)
    {
        len = element_length_in_bytes(*es[i]);
        element_to_bytes(ptr, *es[i]);
        ptr += len;
    }
}