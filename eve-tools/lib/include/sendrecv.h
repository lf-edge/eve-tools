// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef __sendrecv__
#define __sendrecv__

extern int
sendrecv(const char *data_to_send, int data_len, int *length, char **resp);

#endif // __sendrecv__
