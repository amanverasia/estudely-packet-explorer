// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later

/** Maximum number of capture bytes passed to the in-memory Wiregasm session. */
export const MAX_ANALYSIS_BYTES = 1024 * 1024 * 1024;

/** Show a runtime warning before large captures reach the analysis limit. */
export const LARGE_CAPTURE_WARNING_BYTES = 250 * 1024 * 1024;
