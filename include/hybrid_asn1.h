#ifndef HYBRID_PQC_HYBRID_ASN1_H
#define HYBRID_PQC_HYBRID_ASN1_H

#include <stddef.h>

#include "hybrid_sign.h"

#define HYBRID_SIGNATURE_VERSION 1L

int hybrid_signature_encode_der(const HYBRID_SIGNATURE *signature,
                                unsigned char **der, size_t *der_len);

int hybrid_signature_decode_der(const unsigned char *der, size_t der_len,
                                HYBRID_SIGNATURE *signature);

#endif
