/* Copyright (c) 2026 MalX Labs and contributors
 * SPDX-License-Identifier: MPL-2.0
 *
 * Minimal carrier for clean_version_info.rc. The code is irrelevant - the point is
 * to produce a real PE with a real .rsrc section, so the RT_VERSION leaf
 * is located through the actual resource tree rather than a fake.
 */

int main(void)
{
    return 0;
}
