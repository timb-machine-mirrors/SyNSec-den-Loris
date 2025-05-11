import angr
import logging

from typing import Callable, List

log = logging.getLogger(__name__)


class MemoryTrimmer(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, src_stash: str, pickle_callback: Callable):
        super().__init__()
        self._src_stash = src_stash
        self._pickle_callback = pickle_callback

    def _pickle(self, states: List[angr.SimState]):
        for st in states:
            self._pickle_callback(st)

    def step(self, simgr, stash="active", **kwargs):
        simgr.step(stash=stash, **kwargs)

        states = simgr.stashes[self._src_stash]
        if len(states) == 0:
            return simgr
        self._pickle(states)
        simgr.move(from_stash=self._src_stash, to_stash=simgr.DROP)

        for _stash in simgr._auto_drop:
            if len(simgr.stashes[_stash]) == 0:
                continue
            del simgr.stashes[_stash][:]
        return simgr
