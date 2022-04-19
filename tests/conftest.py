# SPDX-License-Identifier: LGPL-2.1+

from typing import Any, Dict, List, Set

from tests.test_config_parser import MkosiConfig


class DictDiffer:
    def __init__(self, expected_dict: Dict[str, Any], current_dict: Dict[str, Any]) -> None:
        self.current_dict = current_dict
        self.expected_dict = expected_dict
        self.set_current, self.set_past = set(current_dict.keys()), set(expected_dict.keys())
        self.intersect = self.set_current.intersection(self.set_past)

    @property
    def unexpected(self) -> List[str]:
        return [f"{k}={self.current_dict[k]}" for k in self.set_current - self.intersect]

    @property
    def missing(self) -> List[str]:
        return [str(k) for k in self.set_past - self.intersect]

    @property
    def invalid(self) -> List[str]:
        inva = {o for o in self.intersect if self.expected_dict[o] != self.current_dict[o]}
        return [f"{k}={self.current_dict[k]} (exp: {self.expected_dict[k]})" for k in inva]

    @property
    def valid(self) -> Set[str]:
        return {o for o in self.intersect if self.expected_dict[o] == self.current_dict[o]}


def pytest_assertrepr_compare(op: str, left: MkosiConfig, right: Any) -> List[str]:
    if not isinstance(right, dict):
        return []
    for r in right.values():
        if not isinstance(vars(r), dict):
            return ["Invalid datatype"]
    if op == "==":

        def compare_job_args(job: str, l_a: Dict[str, Any], r_a: Dict[str, Any]) -> None:
            ddiff = DictDiffer(l_a, r_a)
            ret.append(f'Comparing parsed configuration {job} against expected configuration:')
            ret.append("unexpected:")
            ret.extend([f'- {i}' for i in ddiff.unexpected])
            ret.append("missing:")
            ret.extend([f'- {i}' for i in ddiff.missing])
            ret.append("invalid:")
            ret.extend([f'- {i}' for i in ddiff.invalid])

        verified_keys = []
        ret = ["MkosiConfig is not equal to parsed args"]
        for right_job, right_args in right.items():
            try:
                left_args = left.reference_config[right_job]
            except KeyError:
                ret.append(f'Unexpected job: {right_job}')
                continue
            r_v = vars(right_args)
            compare_job_args(right_job, left_args, r_v)
            verified_keys.append(right_job)
        for left_job in left.reference_config:
            if not left_job in verified_keys:
                ret.append(f'Missing job: {left_job}')
        return ret
    return []
