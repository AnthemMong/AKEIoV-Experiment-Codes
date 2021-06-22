//2019-6-02
//compaile: gcc ops_time.c -o ops_time -lpbc -lgmp
# include<stdio.h>
# include<stdlib.h>
# include<unistd.h>
# include<pbc/pbc.h>
# include<pbc/pbc_test.h>

# define MAXLINE 4096

int main(int argc, char* argv[])
{
    pairing_t pairing;
    double time1, time2, total;
    int times = 100;
    int i;
    element_t P, Q, a, b, c, x, y, temp1, temp2, G1temp1, GTtemp1, GTtemp2, GTtemp3, Ztemp1, Ztemp2;

    pbc_demo_pairing_init(pairing, argc, argv);

    element_init_G1(P, pairing);
    element_init_G1(Q, pairing);
    element_init_G1(G1temp1, pairing);
    element_init_GT(GTtemp1, pairing);
    element_init_GT(GTtemp2, pairing);
    element_init_GT(GTtemp3, pairing);
    element_init_Zr(a, pairing);
    element_init_Zr(b, pairing);
    element_init_Zr(c, pairing);
 
    element_random(P);
    element_random(Q);
    element_random(a);
    element_random(b);
    element_random(c);
    element_random(GTtemp1);
    element_random(GTtemp2);
    element_random(GTtemp3);

    time1 = pbc_get_time();
    for (i = 0; i < times; i++)
    {
        element_pow_zn(Q, P, a);
    }
    time2 = pbc_get_time();

    printf("G1 e: %lf\n", (time2 - time1)/times);

    time1 = pbc_get_time();
    for (i = 0; i < times; i++)
    {
        element_pow_zn(GTtemp2, GTtemp1, a);
    }
    time2 = pbc_get_time();

    printf("GT e: %lf\n", (time2 - time1)/times);

    time1 = pbc_get_time();
    for (i = 0; i < times; i++)
    {
        element_pairing(GTtemp2, P, Q);
    }
    time2 = pbc_get_time();

    printf("Pairing: %lf\n", (time2 - time1)/times);

    time1 = pbc_get_time();
    for (i = 0; i < times; i++)
    {
        element_mul(c, a, b);
    }
    time2 = pbc_get_time();
    printf("Zr Mul: %lf\n", (time2 - time1)/times);

    time1 = pbc_get_time();
    for (i = 0; i < times; i++)
    {
        element_mul(GTtemp3, GTtemp1, GTtemp2);
    }
    time2 = pbc_get_time();
    printf("GT Mul: %lf\n", (time2 - time1)/times);


    time1 = pbc_get_time();
    for (i = 0; i < times; i++)
    {
        element_mul_zn(G1temp1, P, a);
    }
    time2 = pbc_get_time();
    printf("G1 Mul_Zn: %lf\n", (time2 - time1)/times);

    time1 = pbc_get_time();
    for (i = 0; i < times; i++)
    {
        element_mul_zn(GTtemp2, GTtemp1, a);
    }
    time2 = pbc_get_time();
    printf("GT Mul_Zn: %lf\n", (time2 - time1)/times);

    time1 = pbc_get_time();
    for (i = 0; i < times; i++)
    {
        element_add(G1temp1, P, Q);
    }
    time2 = pbc_get_time();
    printf("G1 Add: %lf\n", (time2 - time1)/times);

    time1 = pbc_get_time();
    for (i = 0; i < times; i++)
    {
        element_add(GTtemp1, GTtemp2, GTtemp3);
    }
    time2 = pbc_get_time();
    printf("GT Add: %lf\n", (time2 - time1)/times);

    element_clear(P);
    element_clear(Q);
    element_clear(a);
    element_clear(b);
    element_clear(c);
    pairing_clear(pairing);
    return 0;
}