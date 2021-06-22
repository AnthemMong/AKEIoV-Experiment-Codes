//2020-10-14
//compile: gcc odelu.c -lgmp -lpbc -lcrypto -o odelu
//provably secure authenticated key agreement scheme for smart grid
# include<pbc/pbc.h>
# include<pbc/pbc_test.h>
# include<openssl/sha.h>
# include<string.h>
# include<stdlib.h>
# include<stdio.h>

# define HASH_LEN 20
# define MAXLEN 4096
# define MAX_PARAM 6

void h5(unsigned char* result, element_t* e1);
void h1(unsigned char* result, element_t* e1);
void h2(unsigned char* result, element_t* e1);
void h3(unsigned char* result, unsigned char* estr, int len);
void h4(unsigned char* result, element_t* e1);
void print_hex(unsigned char* ustr, int len);
int element_xor(unsigned char* result, unsigned char* str1, int len1, unsigned char* str2, int len2);
void combine(unsigned char* result,  element_t* es[], int size);

int main(int argc, char* argv[])
{
    pairing_t pairing;
    double time1, time2;
    int byte1, byte2;
    int len1, len2, len3;
    element_t P, Ppub, Ri, Kj, SA, T1, G1temp1, G1temp2;
    element_t k, ri, MIDi, si, SIDj, kj, x1, n1, x2, sks, skm, Zntemp1, Zntemp2, Zntemp3;
    element_t g, gm1, gs1, gs2, XA12, XA, PA, TA, XB01, XB02, XB11, XB12, XB, PB, TB, KA11, KA12, KA14, KB11, KB12, KB14, GTtemp1, GTtemp2, SKA, SKB;

    unsigned char hash_result[HASH_LEN];

    unsigned char Am1[HASH_LEN];
    unsigned char As1[HASH_LEN];
    unsigned char Am2[HASH_LEN];
    unsigned char As2[HASH_LEN];
    unsigned char Am3[HASH_LEN];
    unsigned char As3[HASH_LEN];

    unsigned char temp1[MAXLEN];
    unsigned char temp2[MAXLEN];
    unsigned char temp3[MAXLEN];

    unsigned char C1[MAXLEN];
    element_t* params[MAX_PARAM];

    pbc_demo_pairing_init(pairing, argc, argv);

    if (!pairing_is_symmetric(pairing))
    {
        fprintf(stderr, "only works with symmetric pairing\n");
        exit(1);
    }

    element_init_G1(P, pairing);
    element_init_G1(Ppub, pairing);
    element_init_G1(Ri, pairing);
    element_init_G1(Kj, pairing);
    element_init_G1(SA, pairing);
    element_init_G1(T1, pairing);
    element_init_G1(G1temp1, pairing);
    element_init_G1(G1temp2, pairing);

    element_init_Zr(k, pairing);
    element_init_Zr(ri, pairing);
    element_init_Zr(MIDi, pairing);
    element_init_Zr(si, pairing);
    element_init_Zr(SIDj, pairing);
    element_init_Zr(kj, pairing);
    element_init_Zr(x1, pairing);
    element_init_Zr(n1, pairing);
    element_init_Zr(x2, pairing);
    element_init_Zr(sks, pairing);
    element_init_Zr(skm, pairing);
    element_init_Zr(Zntemp1, pairing);
    element_init_Zr(Zntemp2, pairing);
    element_init_Zr(Zntemp3, pairing);

    element_init_GT(g, pairing);
    element_init_GT(gm1, pairing);
    element_init_GT(gs1, pairing);
    element_init_GT(gs2, pairing);
    element_init_GT(GTtemp1, pairing);
    element_init_GT(GTtemp2, pairing);

    printf("PKG Setup......\n");
    time1 = pbc_get_time();
    element_random(P);
    element_random(k);
    element_pairing(g, P, P);
    
    element_mul_zn(Ppub, P, k);

    time2 = pbc_get_time();
    fprintf(stdout, "PKG init: %fs\n", time2 - time1);

    printf("Extract......\n");
    time1 = pbc_get_time();

    // int i;
    // for (i = 0; i < 100; i++)
    // {
        element_random(ri);
        element_random(MIDi);
        element_mul_zn(Ri, P, ri);
        element_mul_zn(G1temp1, Ri, MIDi);
        h5(hash_result, &G1temp1);
        element_from_hash(Zntemp1, hash_result, HASH_LEN);
        element_mul(Zntemp2, Zntemp1, k);
        element_add(si, Zntemp2, ri);

        element_random(SIDj);
        h1(hash_result, &SIDj);
        element_from_hash(Zntemp1, hash_result, HASH_LEN);

        element_add(Zntemp2, k, Zntemp1);
        element_invert(Zntemp3, Zntemp2);

        element_mul_zn(Kj, P, Zntemp3);
        element_mul_zn(G1temp1, Kj, SIDj);
        h5(hash_result, &G1temp1);
        element_from_hash(kj, hash_result, HASH_LEN);
    //}

    
    time2 = pbc_get_time();
    fprintf(stdout, "Extract: %fs\n", time2 - time1);
    fprintf(stderr, "%0.2f, ", (time2 - time1) * 1000);

    printf("Kay agreement......\n");
    time1 = pbc_get_time();

    element_random(x1);
    element_random(n1);
    
    h1(hash_result, &SIDj);
    element_from_hash(Zntemp2, hash_result, HASH_LEN);

    element_mul_zn(G1temp1, P, Zntemp2);
    element_add(G1temp2, G1temp1, Ppub);
    element_add(Zntemp1, x1, si);
    element_mul_zn(T1, G1temp2, Zntemp1);
    element_add(Zntemp1, x1, si);
    element_pow_zn(gm1, g, Zntemp1);


    element_mul_zn(GTtemp1, gm1, SIDj);
    h2(hash_result, &GTtemp1);
    len1 = element_length_in_bytes(MIDi) + element_length_in_bytes(Ri) + element_length_in_bytes(n1);
    memset(temp1, 0, MAXLEN);
    params[0] = &MIDi;
    params[1] = &Ri;
    params[2] = &n1;
    combine(temp1, params, 3);
    //print_hex(temp1, len1);
    
    len2 = element_xor(C1, hash_result, HASH_LEN, temp1, len1);
    len3 = len2;

    len1 = element_length_in_bytes(T1) +  element_length_in_bytes(MIDi) + element_length_in_bytes(Ri) + element_length_in_bytes(n1) + element_length_in_bytes(gm1);
    memset(temp1, 0, MAXLEN);
    params[0] = &T1;
    params[1] = &MIDi;
    params[2] = &Ri;
    params[3] = &n1;
    params[4] = &gm1;
    combine(temp1, params, 5);
    h3(Am1, temp1, len1);
    
    element_pairing(gs1, T1, Kj);
    element_mul_zn(GTtemp1, gs1, SIDj);
    h2(hash_result, &GTtemp1);

    memset(temp1, 0, MAXLEN);
    element_xor(temp1, C1, len2, hash_result, HASH_LEN);
    //print_hex(temp1, len3);

    len1 = element_length_in_bytes(T1) +  element_length_in_bytes(MIDi) + element_length_in_bytes(Ri) + element_length_in_bytes(n1) + element_length_in_bytes(gm1);
    memset(temp1, 0, MAXLEN);
    len2 = len1;
    params[0] = &T1;
    params[1] = &MIDi;
    params[2] = &Ri;
    params[3] = &n1;
    params[4] = &gs1;
    combine(temp1, params, 5);
    h3(As1, temp1, len1);

    // element_printf("gm1: %B\n", gm1);
    // element_printf("gs1: %B\n", gs1);

    // if (memcmp(As1, Am1, HASH_LEN) == 0)
    //     printf("Accept\n");
    // else 
    //     printf("Reject\n");


    element_random(x2);

    element_mul_zn(G1temp2, Ri, MIDi);
    h5(hash_result, &G1temp2);
    element_from_hash(Zntemp1, hash_result, HASH_LEN);
    element_mul_zn(G1temp1, Ppub, Zntemp1);
    element_add(G1temp2, G1temp1, Ri);

    element_add(Zntemp1, x2, kj);
    element_mul_zn(G1temp1, P, Zntemp1);
    element_pairing(gs2, G1temp1, G1temp2);
 

    element_add(Zntemp1, x2, kj);
    element_pow_zn(GTtemp1, gs1, Zntemp1);
    h4(hash_result, &GTtemp1);
    element_from_hash(sks, hash_result, HASH_LEN);

    
    len1 = element_length_in_bytes(sks) +  element_length_in_bytes(gs2) + element_length_in_bytes(SIDj) + element_length_in_bytes(MIDi) + element_length_in_bytes(n1) + element_length_in_bytes(gs1);
    memset(temp1, 0, MAXLEN);
    params[0] = &sks;
    params[1] = &gs2;
    params[2] = &SIDj;
    params[3] = &MIDi;
    params[4] = &n1;
    params[5] = &gs1;
    combine(temp1, params, 6);
    h3(As2, temp1, len1);

    element_add(Zntemp1, x1, si);
    element_invert(Zntemp2, si);
    element_mul(Zntemp3, Zntemp1, Zntemp2);
    element_pow_zn(GTtemp1, gs2, Zntemp3);
    h4(hash_result, &GTtemp1);
    element_from_hash(skm, hash_result, HASH_LEN);


    len1 = element_length_in_bytes(skm) +  element_length_in_bytes(gs2) + element_length_in_bytes(SIDj) + element_length_in_bytes(MIDi) + element_length_in_bytes(n1) + element_length_in_bytes(gm1);
    memset(temp1, 0, MAXLEN);
    params[0] = &skm;
    params[1] = &gs2;
    params[2] = &SIDj;
    params[3] = &MIDi;
    params[4] = &n1;
    params[5] = &gm1;
    combine(temp1, params, 6);

    time1 = pbc_get_time();
    h3(Am2, temp1, len1);
    time2 = pbc_get_time();
    printf("h: %f\n", time2-time1);

    // if (memcmp(As2, Am2, HASH_LEN) == 0)
    //     printf("Accept\n");
    // else 
    //     printf("Reject\n");

    len1 = element_length_in_bytes(skm) + element_length_in_bytes(MIDi) + element_length_in_bytes(n1) + element_length_in_bytes(gm1) + element_length_in_bytes(gs2) + element_length_in_bytes(SIDj);
    memset(temp1, 0, MAXLEN);
    params[0] = &skm;
    params[1] = &MIDi;
    params[2] = &n1;
    params[3] = &gm1;
    params[4] = &gs2;
    params[5] = &SIDj;
    combine(temp1, params, 6);
    h3(Am3, temp1, len1);

    len1 = element_length_in_bytes(skm) + element_length_in_bytes(MIDi) + element_length_in_bytes(n1) + element_length_in_bytes(gm1) + element_length_in_bytes(gs2) + element_length_in_bytes(SIDj);
    memset(temp1, 0, MAXLEN);
    params[0] = &sks;
    params[1] = &MIDi;
    params[2] = &n1;
    params[3] = &gs1;
    params[4] = &gs2;
    params[5] = &SIDj;
    combine(temp1, params, 6);
    h3(As3, temp1, len1);

    // if (memcmp(As3, Am3, HASH_LEN) == 0)
    //     printf("Accept\n");
    // else 
    //     printf("Reject\n");

    time2 = pbc_get_time();
    fprintf(stdout, "Key agreement: %fs\n", time2 - time1);
    fprintf(stderr, "%0.2f\n", (time2 - time1) * 1000);

    element_printf("sks: %B\n", sks);
    element_printf("skm: %B\n", skm);
    fprintf(stdout, "Communication traffic: %d\n", element_length_in_bytes(T1) + 2 * HASH_LEN + HASH_LEN + element_length_in_bytes(gs2) + HASH_LEN);
    fprintf(stdout, "Key memeory cost: %d\n", 2 * (element_length_in_bytes(kj) + element_length_in_bytes(Kj) + element_length_in_bytes(si) + element_length_in_bytes(Ri)));
    return 0;
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

int element_xor(unsigned char* result, unsigned char* str1, int len1, unsigned char* str2, int len2)
{
    int i, minlen, maxlen;
    unsigned char* pmax, *pmin;

    if (len1 > len2)
    {
        minlen = len2;
        maxlen = len1;
        pmax = str1;
        pmin = str2;
    }
        
    else
    {
        minlen = len1;
        maxlen = len2;
        pmax = str2;
        pmin = str1;
    }

    if (result == NULL)
    {
        fprintf(stderr, "error!\n");
        exit(0);
    }  

    for (i = 0; i < maxlen; i++)
    {
        if (i < minlen)
            result[i] = str1[i] ^ str2[i];
        else
            result[i] = pmax[i];
    }
    return maxlen;
}

void print_hex(unsigned char* ustr, int len)
{
    int i;
    for (i = 1; i < len; i++)
        printf("%02x", ustr[i]);
    printf("\n");
}

void h5(unsigned char* result, element_t *e1)
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
    element_to_bytes(estr, *e1);
    SHA1((const unsigned char *)estr, strlen(estr),  result);
    free(estr);
}

void h1(unsigned char* result, element_t* e1)
{
    h5(result, e1);
}

void h2(unsigned char* result, element_t* e1)
{
    h5(result, e1);
}

void h3(unsigned char* result, unsigned char* estr, int len)
{
    SHA1((const unsigned char *)estr, len, result);
}

void h4(unsigned char* result, element_t* e1)
{
    h5(result, e1);
}
