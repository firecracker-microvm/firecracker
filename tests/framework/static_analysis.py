# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module to perform a static analysis of a binary to determine all
actually invoked syscalls. Compares these against seccomp filters, and lists
redundant rules (e.g. those never triggered because the syscall they allow is not
actually used in the binary)."""

import functools
import json
import logging
import platform
import re
import subprocess
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, ClassVar, Generic, Tuple, TypeVar, get_args

import seccomp

logger = logging.getLogger(__name__)

# pylint: disable=c-extension-no-member,too-many-return-statements,too-few-public-methods


@dataclass
class Instruction(ABC):
    """ABC representing a single assembly instruction"""

    mnemonic: str
    args: list[str]

    comment_prefix: ClassVar[str]

    @property
    @abstractmethod
    def is_call(self):
        """Checks whether the given instruction is a subroutine call"""

    @property
    @abstractmethod
    def is_syscall(self):
        """Checks whether the given instruction is a syscall instruction"""

    @classmethod
    def from_str(cls, insn_str):
        """Parses the given string as a single assembly instruction, in the syntax that
        objdump uses by default on this architecture"""
        # remove comments
        insn_str = re.sub(rf"\s+{cls.comment_prefix}.*", "", insn_str)
        parts = insn_str.split(maxsplit=1)
        args = []
        if len(parts) > 1:
            # Strip each argument, in case objdump decides to put ,
            # spaces after commas (happens on ARM, doesn't happen on x86)
            args = [x.strip() for x in parts[1].split(",")]
        return cls(parts[0], args)

    @abstractmethod
    def backpropagate_register(
        self, reg: str
    ) -> str | int | Tuple[str, Callable[[int], int]]:
        """
        If this instruction loads an immediate into the given register, returns
        that immediate as an integer. If the instruction is a register to register transfer,
        returns the source register for this transfer. If this instruction doesn't change
        the given register, returns the given register. Returns None if we don't know
        how to backpropagate through this instruction.

        :param reg: the register to backpropagate through this instruction
        :return: An integer if the register is loaded with an immediate by this instruction, or a register
                 which needs to be backpropagated further (together with an optional forward-propagation
                 function).
        """

    def __str__(self):
        return f"{self.mnemonic} {','.join(self.args)}"


class InstructionX86_64(Instruction):  # pylint: disable=invalid-name
    """A x86_64 instruction"""

    comment_prefix = "#"

    @property
    def is_call(self):
        return self.mnemonic in ["call", "jmp"]

    @property
    def is_syscall(self):
        return self.mnemonic == "syscall"

    def backpropagate_register(
        self, reg: str
    ) -> str | int | Tuple[str, Callable[[int], int]]:
        # Simplifying assumption: an instruction will not modify a register
        # that it doesn't reference (generally wrong, but fine for our purposes)
        affected_registers = [
            match for (match, _) in re.findall(r"(%[a-z0-9]{2,4})(\W|)", str(self))
        ]
        if reg not in affected_registers:
            return reg

        match self.mnemonic:
            case "mov":
                if len(self.args) != 2:
                    raise UnsupportedInstructionError(self, reg)

                src, dst = self.args

                if dst == reg:
                    # an immediate load
                    if src.startswith("$"):
                        return int(src[3:], 16)
                    # We moved something into our target register. If it's a new register, we understand
                    # what's going on. Anything else, and tough luck
                    if re.match(r"^%\w{2,4}$", src):
                        return src
                    raise UnsupportedInstructionError(self, reg)
                return reg
            case "xor":
                src, dst = self.args

                if src == dst:
                    # we know that reg is part of the arguments, and we know that the arguments are identical
                    # Thus we have xor reg,reg, which is effectively zeroing reg
                    return 0
            case "push":
                # a push doesn't do anything
                return reg

        raise UnsupportedInstructionError(self, reg)


class InstructionAarch64(Instruction):
    """An aarch64 assembly instruction"""

    comment_prefix = "//"

    @property
    def is_call(self):
        return self.mnemonic in ["b", "bl"]

    @property
    def is_syscall(self):
        return self.mnemonic == "svc" and self.args == ["#0x0"]

    def backpropagate_register(
        self, reg: str
    ) -> str | int | Tuple[str, Callable[[int], int]]:
        affected_registers = [
            match
            for (_, match, _) in re.findall(r"(\s|,)([wx]\d{1,2})(\W|)", str(self))
        ]
        if reg not in affected_registers:
            return reg

        match self.mnemonic:
            case "mov":
                if len(self.args) != 2:
                    raise UnsupportedInstructionError(self, reg)

                dst, src = self.args

                if dst == reg:
                    # an immediate load
                    if src.startswith("#"):
                        return int(src[3:], 16)

                    if src in ["xzr", "wzr"]:
                        # See https://developer.arm.com/documentation/102374/0102/Registers-in-AArch64---other-registers
                        return 0

                    # We moved something into our target register. If it's a new register, we understand
                    # what's going on. Anything else, and tough luck
                    if re.match(r"^[xw]\d{1,2}$", src):
                        return src

                    raise UnsupportedInstructionError(self, reg)
                return reg
            case "movk":
                # https://developer.arm.com/documentation/dui0802/a/A64-General-Instructions/MOVK
                assert len(self.args) in [2, 3], str(self)

                immediate = int(self.args[1][3:], 16)
                shift = 0
                if len(self.args) == 3:
                    # shift has form "lsl #<shift>", so strip first 5 characters
                    shift = int(self.args[2][5:])

                mask = 0b1111_1111_1111_1111 << shift

                return reg, lambda x: (x & ~mask) | (immediate << shift)
            case "add" | "sub":
                if len(self.args) != 3:
                    raise UnsupportedInstructionError(self, reg)

                dst, src, imm = self.args

                if dst != reg:
                    return reg

                try:
                    # We can only handle additions of constants, because
                    # the backpropagation algorithm cannot follow multiple registers.
                    imm = int(imm[3:], 16)
                except ValueError as exc:
                    raise UnsupportedInstructionError(self, reg) from exc

                if self.mnemonic == "add":
                    return src, lambda x: x + imm
                # must have self.mnemonic == "sub" here by the case label above.
                return src, lambda x: x - imm

        raise UnsupportedInstructionError(self, reg)


TInstruction = TypeVar(  # pylint: disable=invalid-name
    "TInstruction", bound=Instruction
)


class Architecture(Generic[TInstruction]):
    """ABC representing an instruction set architecture, specifically containing information
    pertaining to syscall and subroutine call conventions"""

    # The symbolic name of the register used to pass the syscall number to the architectures
    # syscall instruction
    syscall_nr_register: ClassVar[str]

    # The list of registers (in order) used to pass arguments to the architectures syscall instruction
    syscall_argument_registers: ClassVar[list[str]]

    # The list of registers (in order) used to pass arguments to normal function calls
    fn_call_argument_registers: ClassVar[list[str]]

    # Convert to the correct variant of seccomp's Arch enum
    seccomp_arch: ClassVar[seccomp.Arch]

    t_instruction: type

    def __init_subclass__(cls) -> None:
        # Determine the generic parameter of a subclass, and store it in t_instruction. pylint doesnt understand it
        # pylint: disable=no-member
        cls.t_instruction = get_args(cls.__orig_bases__[0])[0]

    @staticmethod
    @abstractmethod
    def generalize_reg(reg: str) -> list[str]:
        """For a given register, return a list of registers that partially alias it.

        E.g. on x86, when given %rdi as input, return [%rdi, %edi, %di]"""

    @classmethod
    def determine_register_value(cls, instructions: list[TInstruction], register: str):
        """Determines the value of the given register at the end of the given instruction sequence
        via backpropagation"""
        looking_for = cls.generalize_reg(register)
        transforms = []

        for insn in reversed(instructions):
            for reg in looking_for:
                next_reg = insn.backpropagate_register(reg)

                if isinstance(next_reg, tuple):
                    next_reg, transform = next_reg

                    transforms.insert(0, transform)

                if isinstance(next_reg, int):
                    # Apply all transforms in reverse order of which we discovered them: We now forward propagate
                    # the actual value!
                    return functools.reduce(
                        lambda acc, fn: fn(acc), transforms, next_reg
                    )

                if next_reg != reg:
                    looking_for = cls.generalize_reg(next_reg)
                    break

        raise BackpropagationReachedStartOfFn(looking_for)


class ArchitectureX86_64(  # pylint: disable=invalid-name
    Architecture[InstructionX86_64]
):
    """The x86_64 ISA"""

    syscall_nr_register = "%eax"
    syscall_argument_registers = ["%rdi", "%rsi", "%rdx", "%r10", "%r8", "%r9"]
    fn_call_argument_registers = ["%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"]
    seccomp_arch = seccomp.Arch.X86_64

    @staticmethod
    def generalize_reg(reg: str) -> list[str]:
        suffixes = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"]
        prefixes = ["%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"]

        for suffix in suffixes:
            if reg.endswith(suffix):
                return [f"%r{suffix}", f"%e{suffix}", f"%{suffix}"]

        for prefix in prefixes:
            if reg.startswith(prefix):
                return [prefix, f"{prefix}d", f"{prefix}w"]

        return [reg]


class ArchitectureAarch64(Architecture[InstructionAarch64]):
    """The aarch64 ISA"""

    ALL_REGS = [f"x{i}" for i in range(0, 32)]

    syscall_nr_register = "x8"
    syscall_argument_registers = ALL_REGS[:8]
    fn_call_argument_registers = ALL_REGS[:8]
    seccomp_arch = seccomp.Arch.AARCH64

    @staticmethod
    def generalize_reg(reg: str) -> list[str]:
        mtch = re.match(r"^[xw](\d{1,2})$", reg)

        if mtch:
            nr = mtch.group(1)

            return [f"x{nr}", f"w{nr}"]

        return [reg]


SYSCALL_WRAPPERS = ["syscall", "__syscall_cp", "__syscall_cp_c"]
SPECIFIC_SYSCALL_WRAPPERS = {
    "ioctl": {"syscall": "ioctl", "nargs": 3},
    "__mmap": {"syscall": "mmap", "nargs": 6},
    "socket": {"syscall": "socket", "nargs": 3},
    "__madvise": {"syscall": "madvise", "nargs": 3},
    # special snowflake ioctl: https://github.com/kraj/musl/blob/ffb23aef7b5339b8c3234f4c6a93c488dc873919/src/termios/tcsetattr.c#L5
    "tcsetattr": {
        "syscall": "ioctl",
        "nargs": 3,
        "arg_transform": {1: lambda x: x + 0x5402},
    },
}


class Function:
    """Represents a single function in the binary (e.g. as determined from DWARF debug information)"""

    def __init__(self, name: str, arch: Architecture):
        self.name = name
        self.instructions = []
        self.arch = arch

    def resolve_registers_before_insn(self, i: int, registers: list[str]):
        """Tries to determine the values of the given registers when the i-th instruction
        executes."""
        resolved_registers = {}

        for reg in registers:
            try:
                resolved_registers[reg] = self.arch.determine_register_value(
                    self.instructions[:i], reg
                )
            except (
                UnsupportedInstructionError,
                BackpropagationReachedStartOfFn,
            ) as exc:
                resolved_registers[reg] = exc

        return resolved_registers


class UnsupportedInstructionError(Exception):
    """Exception indicating that an unsupported instruction was encountered during backpropagation, and this
    unsupported instruction refers to the register being backpropagated."""

    def __init__(self, insn: Instruction, reg: str):
        super().__init__(
            f"Encountered unsupported instruction during backpropagation which affects a register of interest ({reg}): {insn}"
        )

        self.instruction = insn


class BackpropagationReachedStartOfFn(Exception):
    """Exception indicating that the beginning of a function was reached during backpropagation, without any immediate
    value being loaded into the register whose value we were trying to determine"""

    def __init__(self, current_register):
        super().__init__(
            f"Backpropagation reached beginning of function definition while backpropagating {current_register}. Maybe it is a parameter itself?"
        )


def parse_objdump_output(output: str, arch: Architecture) -> list[Function]:
    """Parse the stdout from obj dump into a list of the contained functions"""
    lines = output.splitlines()

    # Skip the first line of the output, it's just the file format
    lines = lines[2:]

    functions = []
    current_function = None

    for line in lines:
        line = line.strip()

        # Skip empty lines and those just announcing the start of a new section
        if not line or line.startswith("Disassembly of section"):
            # all functions are separated by empty lines. This is a sanity check to ensure the regex below
            # catches all functions!
            current_function = None
            continue

        # Start of a new function?
        mtch = re.match(r"^<(.+)>:$", line)

        if mtch:
            # group 0 is always the full match (e.g. in our case the entire string because we have a regex with ^ and $)
            # to get the groups defined inside the regex, start at 1.
            current_function = Function(mtch.group(1), arch)
            functions.append(current_function)

            continue

        # otherwise, must be instruction
        if not current_function:
            logger.error(
                "Unexpectedly found data outside of function. Skipping line %s", line
            )
            continue

        current_function.instructions.append(arch.t_instruction.from_str(line))

    return functions


def find_syscalls_in_binary(binary_path: Path):  # pylint: disable=too-many-branches
    """Statically analyzes the given binary to find all syscalls.

    Uses objdump's '-d' option, parses the output, and then at the call site of each syscall instruction
    (and also of simple wrappers around it that weren't inlined during compilation), tries to determine the values
    of registers holding arguments to the syscall instruction."""
    if platform.processor() == "x86_64":
        arch = ArchitectureX86_64()
    else:
        arch = ArchitectureAarch64()

    disassembly = subprocess.check_output(
        f"objdump --demangle=rust -d {binary_path} --no-show-raw-insn --no-addresses".split()
    ).decode("utf-8")

    functions = parse_objdump_output(disassembly, arch)

    found_syscalls = {}

    for fn in functions:
        # We don't want to find syscall instruction inside functions that we treat as synthetic syscall instructions
        # themselves, because we will not be able to figure out any argument values here (since they are instead
        # determined by the arguments to the function itself). Not excluding these would mean the script recognizes
        # them as very broad syscall invocations (e.g. only the syscall number is known, but nothing else, meaning
        # all seccomp rules that refer to this syscall are more specific and thus cannot be ruled out).
        if fn.name in SYSCALL_WRAPPERS or fn.name in SPECIFIC_SYSCALL_WRAPPERS:
            continue

        for i, insn in enumerate(fn.instructions):
            if insn.is_syscall:
                resolved_registers = fn.resolve_registers_before_insn(
                    i,
                    [arch.syscall_nr_register] + arch.syscall_argument_registers,
                )

                syscall_nr = resolved_registers.pop(arch.syscall_nr_register)
                syscall_args = [
                    resolved_registers[reg] for reg in arch.syscall_argument_registers
                ]
            elif insn.is_call:
                # in objdump output, these look like 'call <syscall>', so strip the angle brackets
                called = insn.args[0][1:-1]

                if called in SYSCALL_WRAPPERS:
                    resolved_registers = fn.resolve_registers_before_insn(
                        i, arch.fn_call_argument_registers
                    )

                    # On x86_64, we are not able to recover the 6th argument passed, since it is passed on the stack
                    # This is because for the syscall wrapper, the syscall number itself is passed in one of the 6
                    # registers available for function arguments in the cdecl convention (instead of being passed in
                    # eax, which is not usually used for function arguments).
                    syscall_nr = resolved_registers.pop(
                        arch.fn_call_argument_registers[0]
                    )
                    syscall_args = [
                        resolved_registers[reg]
                        for reg in arch.fn_call_argument_registers[1:]
                    ]
                elif called in SPECIFIC_SYSCALL_WRAPPERS:
                    resolved_registers = fn.resolve_registers_before_insn(
                        i, arch.fn_call_argument_registers
                    )

                    syscall_nr = seccomp.resolve_syscall(
                        arch.seccomp_arch, SPECIFIC_SYSCALL_WRAPPERS[called]["syscall"]
                    )
                    syscall_nargs = SPECIFIC_SYSCALL_WRAPPERS[called]["nargs"]
                    syscall_args = [
                        resolved_registers[reg]
                        for reg in arch.fn_call_argument_registers[:syscall_nargs]
                    ]

                    if all(isinstance(arg, Exception) for arg in syscall_args):
                        logger.warning(
                            "Could not resolve any argument for syscall wrapper %s in function %s",
                            called,
                            fn.name,
                        )

                    # If the wrapper performs some transformation of an argument, apply it.
                    # It'd be cool to determine these automatically via back propagation or something,
                    # but that's a fairly complex task, and we only have a single syscall wrapper that needs this
                    for arg, modifier in (
                        SPECIFIC_SYSCALL_WRAPPERS[called]
                        .get("arg_transform", {})
                        .items()
                    ):
                        syscall_args[arg] = modifier(syscall_args[arg])
                else:
                    continue
            else:
                continue

            # This gets triggered in the __lockfile function on x86_64 (syscall number is loader before a branching instruction,
            # but if the branch is not taken, linear execution will eventually hit a ret. So during backpropagation we
            # would need to skip the section of assembly between "jmp" and "ret", but our script doesn't do anything
            # sophisticated like that and thus instead tries to analyse this branch where the syscall number register
            # gets clobbered, and it eventually hits a "pop" which it doesnt understand). The syscall in question is
            # "futex", and we call that one a million times elsewhere anyway.
            #
            # See: https://github.com/kraj/musl/blob/ffb23aef7b5339b8c3234f4c6a93c488dc873919/src/stdio/__lockfile.c#L4
            if isinstance(syscall_nr, Exception):
                logger.warning(
                    "Failed to resolve syscall number for instruction %s in function %s: %s",
                    insn,
                    fn.name,
                    syscall_nr,
                )
                continue

            syscall_name = seccomp.resolve_syscall(
                arch.seccomp_arch, syscall_nr
            ).decode("utf-8")
            if syscall_name not in found_syscalls:
                found_syscalls[syscall_name] = []

            found_syscalls[syscall_name].append(
                [None if isinstance(arg, Exception) else arg for arg in syscall_args]
            )

    return found_syscalls


def load_seccomp_rules(seccomp_path: Path):
    """Loads seccomp rules from the given file, and presents them as a dictionary
    mapping syscalls to a list of individual filters. Each individual filter
    describes some restriction of the arguments that are allowed to be passed
    to the syscall."""
    filters = json.loads(seccomp_path.read_text("utf-8"))

    all_filters = (
        filters["vcpu"]["filter"] + filters["vmm"]["filter"] + filters["api"]["filter"]
    )
    allowlist = defaultdict(list)

    for seccomp_filter in all_filters:
        syscall_name = seccomp_filter["syscall"]

        allowlist[syscall_name].append(
            {arg["index"]: arg["val"] for arg in seccomp_filter.get("args", [])}
        )

    return allowlist


KNOWN_SUPERFLUOUS_RULES = {
    # This syscall is inserted at runtime by the linux kernel, and thus not actually present in our binary.
    "restart_syscall": [{}]
}


def determine_unneeded_seccomp_rules(seccomp_rules, found_syscalls):
    """Based on the given list of syscall determined through static analysis, compute which of the
    given seccomp rules are redundant. By 'redundant' we here mean that no syscall that would match
    it is actually present in the given list of syscalls."""

    # TODO: We could also determine "too broad" rules here: If all actual invocations of a syscall specific a parameter,
    # but the rule does not restrict that parameter, we could recommend to strengthen the rule to specify the parameter!

    redundant_rules = []

    for syscall, rules in seccomp_rules.items():
        for allowed_arguments in rules:
            if (
                syscall in KNOWN_SUPERFLUOUS_RULES
                and allowed_arguments in KNOWN_SUPERFLUOUS_RULES[syscall]
            ):
                continue

            # A rule is not needed if for all actual invocation of the syscall the rule governs,
            # the rule does not match.
            # Here, we determine "does not match" as "the rule specifies some value for an argument of the syscall to be
            # allowed, but the invocation of the syscall never passes this specified value of the argument".
            # If there are no invocations of a syscall altogether, then the universal quantification will be vacuously
            # true, and any rules involving that syscall are reported as non-needed.
            rule_not_needed = all(
                any(
                    actual_invocations[arg_index] is not None
                    and actual_invocations[arg_index] != allowed_arg
                    for arg_index, allowed_arg in allowed_arguments.items()
                )
                for actual_invocations in found_syscalls.get(syscall, [])
            )

            if rule_not_needed:
                redundant_rules.append((syscall, allowed_arguments))

    return redundant_rules
