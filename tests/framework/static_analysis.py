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
from collections import namedtuple
from pathlib import Path

import seccomp

logger = logging.getLogger(__name__)

Instruction = namedtuple("Instruction", "mnemonic args")

# pylint: disable=c-extension-no-member,too-many-return-statements,too-few-public-methods


class Architecture(ABC):
    """Class defining the interface used by the static analysis algorithm"""

    @property
    @abstractmethod
    def syscall_nr_register(self):
        """The symbolic name of the register used to pass the syscall number to the architectures
        syscall instruction"""

    @property
    @abstractmethod
    def syscall_argument_registers(self):
        """The list of registers (in order) used to pass arguments to the architectures syscall instruction"""

    @property
    @abstractmethod
    def fn_call_argument_registers(self):
        """The list of registers (in order) used to pass arguments to normal function calls"""

    @property
    @abstractmethod
    def seccomp_arch(self) -> seccomp.Arch:
        """Convert to the correct variant of seccomp's Arch enum"""

    @abstractmethod
    def generalize_reg(self, reg: str) -> list[str]:
        """For a given register, return a list of registers that partially alias it.

        E.g. on x86, when given %rdi as input, return [%rdi, %edi, %di]"""

    @abstractmethod
    def is_call_instruction(self, insn: Instruction) -> bool:
        """Checks whether the given instruction is a subroutine call"""

    @abstractmethod
    def is_syscall_instruction(self, insn: Instruction) -> bool:
        """Checks whether the given instruction is a syscall instruction"""

    @abstractmethod
    def backpropagate_register(self, insn: Instruction, reg: str):
        """
        If this instruction loads an immediate into the given register, returns
        that immediate as an integer. If the instruction is a register to register transfer,
        returns the source register for this transfer. If this instruction doesn't change
        the given register, returns the given register. Returns None if we don't know
        how to backpropagate through this instruction.

        :param insn: The instruction to backpropagate through
        :param reg: the register to backpropagate through the given instruction
        :return:
        """

    @abstractmethod
    def instruction_from_str(self, insn_str: str) -> Instruction:
        """Parses the given string as a single assembly instruction, in the syntax that
        objdump uses by default on this architecture"""

    def determine_register_value(self, instructions: list[Instruction], register: str):
        """Determines the value of the given register at the end of the given instruction sequence
        via backpropagation"""
        looking_for = self.generalize_reg(register)
        transforms = []

        for insn in reversed(instructions):
            for reg in looking_for:
                next_reg = self.backpropagate_register(insn, reg)

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
                    looking_for = self.generalize_reg(next_reg)
                    break

        raise BackpropagationReachedStartOfFn(looking_for)


class X86_64(Architecture):  # pylint: disable=invalid-name
    """x86_64 architecture"""

    @property
    def syscall_nr_register(self):
        return "%eax"

    @property
    def syscall_argument_registers(self):
        return ["%rdi", "%rsi", "%rdx", "%r10", "%r8", "%r9"]

    @property
    def fn_call_argument_registers(self):
        return ["%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"]

    @property
    def seccomp_arch(self) -> seccomp.Arch:
        return seccomp.Arch.X86_64

    def generalize_reg(self, reg: str) -> list[str]:
        suffixes = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"]
        prefixes = ["%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"]

        for suffix in suffixes:
            if reg.endswith(suffix):
                return [f"%r{suffix}", f"%e{suffix}", f"%{suffix}"]

        for prefix in prefixes:
            if reg.startswith(prefix):
                return [prefix, f"{prefix}d", f"{prefix}w"]

        return [reg]

    def is_call_instruction(self, insn: Instruction):
        return insn.mnemonic in ["call", "jmp"]

    def is_syscall_instruction(self, insn: Instruction):
        return insn.mnemonic == "syscall"

    def backpropagate_register(self, insn: Instruction, reg: str):
        # Simplifying assumption: an instruction will not modify a register
        # that it doesn't reference (generally wrong, but fine for our purposes)
        affected_registers = [
            match for (match, _) in re.findall(r"(%[a-z0-9]{2,4})(\W|)", str(insn))
        ]
        if reg not in affected_registers:
            return reg

        match insn.mnemonic:
            case "mov":
                if len(insn.args) != 2:
                    raise UnsupportedInstructionException(insn, reg)

                src, dst = insn.args

                if dst == reg:
                    # an immediate load
                    if src.startswith("$"):
                        return int(src[3:], 16)
                    # We moved something into our target register. If it's a new register, we understand
                    # what's going on. Anything else, and tough luck
                    if re.match(r"^%\w{2,4}$", src):
                        return src
                    raise UnsupportedInstructionException(insn, reg)
                return reg
            case "xor":
                src, dst = insn.args

                if src == dst:
                    # we know that reg is part of the arguments, and we know that the arguments are identical
                    # Thus we have xor reg,reg, which is effectively zeroing reg
                    return 0
            case "push":
                # a push doesn't do anything
                return reg

        raise UnsupportedInstructionException(insn, reg)

    def instruction_from_str(self, insn_str: str) -> Instruction:
        parts = insn_str.split(maxsplit=1)

        args = []
        if len(parts) > 1:
            args = parts[1].split(",")

            # Strip each argument, in case objdump decides to put spaces after commas
            args = list(map(str.strip, args))
            # The last argument might have a comment after it. Strip that off
            args[-1] = args[-1].split("#")[0]

        return Instruction(parts[0], args)


class Aarch64(Architecture):
    """Aarch64 architecture"""

    ALL_REGS = [f"x{i}" for i in range(0, 32)]

    @property
    def syscall_nr_register(self):
        return "x8"

    @property
    def syscall_argument_registers(self):
        return Aarch64.ALL_REGS[:8]

    @property
    def fn_call_argument_registers(self):
        return Aarch64.ALL_REGS[:8]

    @property
    def seccomp_arch(self) -> seccomp.Arch:
        return seccomp.Arch.AARCH64

    def generalize_reg(self, reg: str) -> list[str]:
        mtch = re.match(r"^[xw](\d{1,2})$", reg)

        if mtch:
            nr = mtch.group(1)

            return [f"x{nr}", f"w{nr}"]

        return [reg]

    def is_call_instruction(self, insn: Instruction) -> bool:
        return insn.mnemonic in ["b", "bl"]

    def is_syscall_instruction(self, insn: Instruction) -> bool:
        return insn.mnemonic == "svc" and insn.args == ["#0x0"]

    def backpropagate_register(self, insn: "Instruction", reg: str):
        affected_registers = [
            match
            for (_, match, _) in re.findall(r"(\s|,)([wx]\d{1,2})(\W|)", str(insn))
        ]
        if reg not in affected_registers:
            return reg

        match insn.mnemonic:
            case "mov":
                if len(insn.args) != 2:
                    raise UnsupportedInstructionException(insn, reg)

                dst, src = insn.args

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

                    raise UnsupportedInstructionException(insn, reg)
                return reg
            case "movk":
                # https://developer.arm.com/documentation/dui0802/a/A64-General-Instructions/MOVK
                assert len(insn.args) in [2, 3], str(insn)

                immediate = int(insn.args[1][3:], 16)
                shift = 0
                if len(insn.args) == 3:
                    # shift has form "lsl #<shift>", so strip first 5 characters
                    shift = int(insn.args[2][5:])

                mask = 0b1111_1111_1111_1111 << shift

                return reg, lambda x: (x & ~mask) | (immediate << shift)
            case "add" | "sub":
                if len(insn.args) != 3:
                    raise UnsupportedInstructionException(insn, reg)

                dst, src, imm = insn.args

                if dst != reg:
                    return reg

                try:
                    # We can only handle additions of constants, because
                    # the backpropagation algorithm cannot follow multiple registers.
                    imm = int(imm[3:], 16)
                except ValueError as exc:
                    raise UnsupportedInstructionException(insn, reg) from exc

                if insn.mnemonic == "add":
                    return src, lambda x: x + imm
                return src, lambda x: x - imm

        raise UnsupportedInstructionException(insn, reg)

    def instruction_from_str(self, insn_str: str) -> "Instruction":
        parts = insn_str.split(maxsplit=1)

        args = []
        if len(parts) > 1:
            args = parts[1].split(",")

            # Strip each argument, in case objdump decides to put spaces after commas
            args = list(map(str.strip, args))
            # The last argument might have a comment after it. Strip that off
            args[-1] = args[-1].split("//")[0]

        return Instruction(parts[0], args)


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
                UnsupportedInstructionException,
                BackpropagationReachedStartOfFn,
            ) as exc:
                resolved_registers[reg] = exc

        return resolved_registers


class UnsupportedInstructionException(Exception):
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

        current_function.instructions.append(arch.instruction_from_str(line))

    return functions


def find_syscalls_in_binary(binary_path: Path):  # pylint: disable=too-many-branches
    """Statically analyzes the given binary to find all syscalls.

    Uses objdump's '-d' option, parses the output, and then at the call site of each syscall instruction
    (and also of simple wrappers around it that weren't inlined during compilation), tries to determine the values
    of registers holding arguments to the syscall instruction."""
    if platform.processor() == "x86_64":
        arch = X86_64()
    else:
        arch = Aarch64()

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
            if arch.is_syscall_instruction(insn):
                resolved_registers = fn.resolve_registers_before_insn(
                    i,
                    [arch.syscall_nr_register] + arch.syscall_argument_registers,
                )

                syscall_nr = resolved_registers.pop(arch.syscall_nr_register)
                syscall_args = [
                    resolved_registers[reg] for reg in arch.syscall_argument_registers
                ]
            elif arch.is_call_instruction(insn):
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
    allowlist = {}

    for seccomp_filter in all_filters:
        syscall_name = seccomp_filter["syscall"]

        if syscall_name not in allowlist:
            allowlist[syscall_name] = []

        allowlist[syscall_name].append(
            {arg["index"]: arg["val"] for arg in seccomp_filter.get("args", [])}
        )

    return allowlist


def determine_unneeded_seccomp_rules(seccomp_rules, found_syscalls):
    """Based on the given list of syscall determined through static analysis, compute which of the
    given seccomp rules are redundant. By 'redundant' we here mean that no syscall that would match
    it is actually present in the given list of syscalls."""

    # TODO: We could also determine "too broad" rules here: If all actual invocations of a syscall specific a parameter,
    # but the rule does not restrict that parameter, we could recommend the strengthen the rule to specify the parameter!

    redundant_rules = []

    for syscall, rules in seccomp_rules.items():
        for allowed_arguments in rules:
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
