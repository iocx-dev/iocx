#include "fixtures.h"
#include "pe_emit.h"

int main(void)
{
    build_all_fixtures();
    if (write_all_fixtures_pe("out") != 0) {
        return 1;
    }
    return 0;
}
