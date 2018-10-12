// HW library functions that all parties need to make connections, encrypt and decrypt and other stuff

#ifndef CRYPTO_MATH_H
#define CRYPTO_MATH_H
#include<stdlib.h>
typedef unsigned int u_int;

u_int gcd(u_int a, u_int b)
{
    if(a%b == 0)
        return b;
    return gcd(b, a%b);
}

u_int exp_mod(u_int base, u_int exp, u_int mod)
{
    long unsigned int sol = base;
    long unsigned int cur_exp = exp;
    while(cur_exp > 1)
    {
        if(cur_exp %2 == 0)
        {
            sol = (sol*sol) % mod;
            cur_exp = cur_exp/2;
        }
        else
        {
            u_int ender = exp_mod(sol, cur_exp-1, mod);
            return sol*ender % mod;
        }
    }
    return sol;
}

u_int check_prime(u_int candidate)
{
    //printf("CANDIDATE: %u\n", candidate);
    u_int exp = candidate - 1;
    u_int a; 
    u_int result;
    u_int r = 0;
    u_int i, j;
    while(exp%2 == 0)
    {
        r++;
        exp = exp/2;
        //printf("exp: %u\n", exp);
    }
    
    if(r == 0)
        return 0;
    //printf("r = %u\n", r);
    
    for(i = 0; i< 16; i++)
    {
        a = (rand() % (candidate-4)) + 2;
        //printf("CHECKING a = %u\n", a);
        //printf("MODDING: %u, %u, %u\n", a[i], exp, candidate);
        result = exp_mod(a, exp, candidate);
        //printf("result: %u\n", result);
        if(result == 1 || (result == candidate-1))
            continue;
        else
        {
            for(j = 0; j<r-1; j++)
            {
                result = exp_mod(result, 2, candidate);
                //printf("result: %u\n", result);
                if(result == candidate -1)
                {
                    break;
                }
            }
            if(result == candidate -1)
                continue;
            return 0;
        }
    }
    return 1;
}

u_int generate_prime(u_int max)
{
    u_int mod;
    if(max == 0)
        mod = RAND_MAX-1;
    else
        mod = max;
    // printf("GOT MODULUS: %u\n", mod);
    u_int holder = rand() % mod;
    // printf("GENERATED RAND MOD MAX\n");
    u_int check = holder << 1;
    check = check +1;
    // printf("GENERATED FIRST PRIME\n");
    while(!check_prime(holder))
    {
        holder = rand() % mod;
        u_int check = holder << 1;
        check = check +1;
        //printf("CHECKING %u\n", check);
    }
    return holder;
}

u_int find_prime_root(u_int p, int** result_facs, int * facs_size)
{
    u_int left = p-1;
    int found = 0;
    int num = 1;
    int* factors = malloc(sizeof(int)*1024);
    int check = 2;
    while(!check_prime(left))
    {
        if(left%check ==0)
        {
            factors[found] = check;
            found++;
            left = left/check;
        }
        else
        {
            check = check+1;
        }
    }
    *result_facs = malloc(sizeof(int)*found);
    int i;
    (*result_facs)[0] = factors[0];
    for(i = 1; i< found; i++)
    {
        if(factors[i] != (*result_facs)[num-1])
        {
            (*result_facs)[num] = factors[i];
            num++;
        }   
    }
    *facs_size = num;
    free(factors);
    factors = malloc(sizeof(int)*num);
    for(i =0; i<num; i++)
    {
        factors[i] = (p-1)/(*result_facs)[i];
    }
    
    int is_true = 0;
    u_int prim_root = 2;
    while(!is_true || prim_root == (p-1))
    {
        is_true = 1;
        for(i=0; i<num; i++)
        {
            if(exp_mod(prim_root, factors[i], p) == 1)
            {
                is_true = 0;
                
            }
        }
        if(is_true)
            return prim_root;
        prim_root++;
    }
    return 0;
}

#endif
