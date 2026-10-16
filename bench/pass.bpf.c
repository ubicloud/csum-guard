// Empty tc program: isolates the cost of the clsact hook + program dispatch.
#include "../vmlinux.h"	/* generated, see README */
#include <bpf/bpf_helpers.h>
SEC("tc") int pass(struct __sk_buff *ctx) { return 0; }
char LICENSE[] SEC("license") = "GPL";
