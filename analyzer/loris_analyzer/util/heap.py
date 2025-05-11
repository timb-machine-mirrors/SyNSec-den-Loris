import angr
import logging

from typing import List

from loris_analyzer.util import utils

log = logging.getLogger(__name__)


def init(
    state: angr.SimState,
    heap_data: List[dict]
):
    log.debug("heap_init")
    print_all_chunks(state)
    to_free_list = list()
    for chunk in heap_data:
        log.debug(
            f"heap_init:"
            f"chunk={chunk}"
        )
        size = chunk["size"] - 8  # 8 is the heap metadata size
        ptr = state.heap.malloc(size)
        if chunk["free"]:
            to_free_list.append(ptr)
        else:
            state.memory.store(ptr, chunk["data"], endness="Iend_BE")
    for ptr in to_free_list:
        state.heap.free(ptr)
    print_all_chunks(state)


def allocate(state: angr.SimState, size: int):
    print_all_chunks(state)
    buf = state.heap.malloc(size)
    if buf == 0:
        raise ValueError(f"could not alloc memory for size {size:#x}")
    log.debug(f"Allocated simulated buffer at {buf:#010x}(size={size:#x})")
    print_all_chunks(state)
    return buf


def free(state: angr.SimState, ptr):
    print_all_chunks(state)
    ptr_str = f"{ptr:#010x}" if isinstance(ptr, int) else str(ptr)
    log.debug(f"heap_free:ptr={ptr_str}")
    ptr = utils.try_eval_one(state, ptr)
    log.debug(f"heap_free:ptr={ptr}")
    if not isinstance(ptr, int):
        log.warning(f"Attempted to free a symbolic ptr {ptr_str}")
        return 1
    if ptr < state.heap.heap_base or state.heap.heap_base + state.heap.heap_size <= ptr:
        log.warning(f"Attempted to free out of heap ptr {ptr_str}")
        return 1
    state.heap.free(ptr)
    log.debug(f"Freed simulated buffer at {ptr:#010x}")
    print_all_chunks(state)
    return 0


def log_state(state: angr.SimState):
    log.debug("|------------------------------------------------|")
    _print_all_chunks(state)
    log.debug("|------------------ USED CHUNKS -----------------|")
    for ck in state.heap.allocated_chunks():
        size = utils.try_eval_one(state, ck.get_size())
        size_str = f"{size:#010x}" if isinstance(size, int) else str(size)
        log.debug(f"| {ck} (size={size_str}) |")
    log.debug("|------------------ FREE CHUNKS ------------------|")
    for ck in state.heap.free_chunks():
        size = utils.try_eval_one(state, ck.get_size())
        size_str = f"{size:#010x}" if isinstance(size, int) else str(size)
        log.debug(f"| {ck} (size={size_str}) |")
    log.debug("|------------------------------------------------|")


def print_all_chunks(state: angr.SimState):
    log.debug("|------------------------------------------------|")
    _print_all_chunks(state)
    log.debug("|------------------------------------------------|")


def _print_all_chunks(state: angr.SimState):
    log.debug("|------------------ HEAP CHUNKS -----------------|")
    for ck in state.heap.chunks():
        size = utils.try_eval_one(state, ck.get_size())
        size_str = f"{size:#010x}" if isinstance(size, int) else str(size)
        log.debug(f"| {ck} (size={size_str}) |")
