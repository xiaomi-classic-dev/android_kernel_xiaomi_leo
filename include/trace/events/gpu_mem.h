/* SPDX-License-Identifier: GPL-2.0 */
/* GPU memory trace points. Copyright (C) 2020 Google, Inc. */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM gpu_mem

#if !defined(_TRACE_GPU_MEM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_GPU_MEM_H

#include <linux/tracepoint.h>

/* Android ABI: GPU id and tgid at offsets 8/12, total bytes at offset 16.
 * pid 0 reports the global total; other values report a process total.
 */
TRACE_EVENT(gpu_mem_total,

	TP_PROTO(uint32_t gpu_id, uint32_t pid, uint64_t size),

	TP_ARGS(gpu_id, pid, size),

	TP_STRUCT__entry(
		__field(uint32_t, gpu_id)
		__field(uint32_t, pid)
		__field(uint64_t, size)
	),

	TP_fast_assign(
		__entry->gpu_id = gpu_id;
		__entry->pid = pid;
		__entry->size = size;
	),

	TP_printk("gpu_id=%u pid=%u size=%llu", __entry->gpu_id,
		__entry->pid, __entry->size)
);

#endif /* _TRACE_GPU_MEM_H */

#include <trace/define_trace.h>
