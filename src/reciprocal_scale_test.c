#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static inline uint32_t reciprocal_scale(uint32_t val, uint32_t ep_ro) {
	return (uint32_t)(((uint64_t)val * ep_ro) >> 32);
}

int main(int argc, char** argv) {
	int cpu;
	int queue = 96;
	if (argc > 1) {
		queue = atoi(argv[1]);
	}

	for (cpu = 0; cpu < 192; cpu++) {
		uint32_t hash = cpu;
		// you can do some trick here to avoid vlan100 thing
		uint32_t q = queue;
		uint32_t actual = reciprocal_scale(hash, q);
		printf("CPU[%d]: Hash:%u -> result: %u\n", cpu, hash, actual);
	}

	return 0;
}
