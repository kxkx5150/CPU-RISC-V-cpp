#include "PC/PC.h"

int main(int argc, char **argv)
{
    PC *pc = new PC();
    pc->init();

    while (true) {
        pc->run();
    }
    return 0;
}
