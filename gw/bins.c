#include <stdio.h>
#include <stdlib.h>

static void pausa(const char *msg)
{
    puts("\n========================================");
    puts(msg);
    puts("========================================");
    getchar();
}

int main(void)
{
    setbuf(stdout, NULL);

    /*
     * 1. TCACHE
     *
     * malloc(0x30) -> chunk real de 0x40
     */
    char *tcache[4];

    for (int i = 0; i < 4; i++) {
        tcache[i] = malloc(0x30);
    }

    for (int i = 0; i < 4; i++) {
        free(tcache[i]);
    }

    pausa("[1] TCACHE: devem existir 4 chunks no bin 0x40");


    /*
     * 2. UNSORTED BIN
     *
     * Os chunks grandes são separados por "guards"
     * para evitar consolidação entre eles ou com o top chunk.
     */
    char *a = malloc(0x500);
    char *guard1 = malloc(0x20);

    char *b = malloc(0x600);
    char *guard2 = malloc(0x20);

    free(a);
    free(b);

    pausa("[2] UNSORTED BIN: os chunks 0x510 e 0x610 devem aparecer aqui");


    /*
     * 3. LARGE BINS
     *
     * Esse malloc é maior que a e b.
     *
     * Ao procurar um chunk adequado, malloc processa
     * a unsorted bin e classifica os chunks anteriores
     * nos large bins.
     */
    char *grande = malloc(0x1000);

    pausa("[3] LARGE BINS: unsorted deve ficar vazia e a/b devem estar nos largebins");


    /*
     * Evita warnings e mantém as alocações vivas até aqui.
     */
    (void)guard1;
    (void)guard2;
    (void)grande;

    return 0;
}
