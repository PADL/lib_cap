#ifndef SC_H
#define SC_H

/*
The set of scalars is \Z/l
where l = 2^252 + 27742317777372353535851937790883648493.
*/

void sc_reduce(uint8_t *s);
void sc_muladd(uint8_t *s, const uint8_t *a, const uint8_t *b, const uint8_t *c);

#endif
