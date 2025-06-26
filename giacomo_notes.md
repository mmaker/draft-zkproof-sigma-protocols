1. Do we want the codec to return self or not? I kind of like not returning self since this makes it clear that this mutates the state.
2. We should mandate some sanity things for a codec: for example we should panic if we call prover_message twice in a row ecc.
3. Lemma 3.2 of the paper, should we have B in the second line?
