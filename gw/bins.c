#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    int i;
    char *chunks[8];
    for(i = 0; i < 8; ++i)
    {
        chunks[i] = malloc(0x30);
    }

    // lotando a tcache
    for (i = 0; i < 7; ++i) 
    {
        free(chunks[i]);
    }

    // free(chunks[7]) vai jogar esse chunk na unsorted bin
    free(chunks[7]);

    char *grande = malloc(0x500);
    char *top = malloc(0x10); // para evitar consolidacao com o topo

    char *grande2 = malloc(0x600);
    char *top2 = malloc(0x10);

    free(grande);
    free(grande2);

    char *chunk = malloc(0x1000);

    getchar();

    return EXIT_SUCCESS;
}
