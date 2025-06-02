#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * reciprocal_scale - "scale" a value into range [0, ep_ro)
 * @val: value
 * @ep_ro: right open interval endpoint
 *
 * Perform a "reciprocal multiplication" in order to "scale" a value into
 * range [0, @ep_ro), where the upper interval endpoint is right-open.
 * This is useful, e.g. for accessing a index of an array containing
 * @ep_ro elements, for example. Think of it as sort of modulus, only that
 * the result isn't that of modulo. ;) Note that if initial input is a
 * small value, then result will return 0.
 *
 * Return: a result based on @val in interval [0, @ep_ro).
 */
static inline uint32_t reciprocal_scale(uint32_t val, uint32_t ep_ro) {
	return (uint32_t)(((uint64_t)val * ep_ro) >> 32);
}

#define GOLDEN_RATIO 2654435761UL

int main(int argc, char** argv) {
	int cpu;
	int queue = 96;
	if (argc > 1) {
		queue = atoi(argv[1]);
	}
	printf("Input queue:%d\n", queue);

	for (cpu = 0; cpu < 192; cpu++) {
		//uint32_t hash = cpu;
		// you can do some trick here to avoid vlan100 thing
		// uint32_t hash = cpu << 24;
		//uint32_t hash = (cpu << 24) * 13;
		uint32_t hash = cpu * GOLDEN_RATIO;
		uint32_t q = queue;
		uint32_t actual = reciprocal_scale(hash, q);
		printf("CPU[%d]: Hash:%u -> result: %u\n", cpu, hash, actual);
	}

	return 0;
}
