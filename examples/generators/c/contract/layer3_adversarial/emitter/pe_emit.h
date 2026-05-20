#ifndef PE_EMIT_H
#define PE_EMIT_H

#include "fixtures.h"

/* Write one fixture to a PE file path. Returns 0 on success, -1 on error. */
int write_fixture_pe(const FixtureSpec *f, const char *path);

/* Convenience: write all fixtures as fixture_<id>_<name>.exe */
int write_all_fixtures_pe(const char *dir);

#endif /* PE_EMIT_H */
