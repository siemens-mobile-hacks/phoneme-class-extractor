#!/usr/bin/env python3
"""Recover classes from a phoneME source-ROM image.

This targets the CLDC HotSpot source ROMizer layout used by Siemens phones.
It emits valid class files and a Ghidra native-symbol file. By default it
rebuilds class-file constant pools and dequickens retained method bodies. JSON
metadata is available as an explicit option.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import struct
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Optional


FLASH_BASE = 0xA0000000

ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_SYNCHRONIZED = 0x0020
ACC_NATIVE = 0x0100
ACC_INTERFACE = 0x0200
ACC_ABSTRACT = 0x0400
ACC_STRICT = 0x0800
ACC_SYNTHETIC_ROM = 0x2000

ROM_PRELOADED = 0x10000000
ROM_ARRAY_CLASS = 0x04000000
ROM_NO_STACKMAPS = 0x1000
ROM_NO_EXCEPTIONS = 0x4000

PRIMITIVE_BY_BASIC_TYPE = {
    4: "Z", 5: "C", 6: "F", 7: "D", 8: "B", 9: "S", 10: "I", 11: "J"
}

CORE_ARRAY_BY_CLASS_ID = {
    0: "[Ljava/lang/Object;",
    3: "[Ljava/lang/String;",
    4: "[Z", 5: "[C", 6: "[F", 7: "[D",
    8: "[B", 9: "[S", 10: "[I", 11: "[J",
}


def align4(value: int) -> int:
    return (value + 3) & ~3


def parse_address(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        try:
            return int(value, 16)
        except ValueError as error:
            raise argparse.ArgumentTypeError(
                f"invalid address {value!r}") from error


@dataclass
class FieldInfo:
    access: int
    name: str
    descriptor: str
    initial_index: int
    offset: int
    synthetic_name: bool = False


@dataclass
class MethodInfo:
    address: int
    access_rom: int
    holder_id: int
    max_stack: int
    max_locals: int
    attributes: int
    name: str
    descriptor: str
    constants_pointer: int
    code: bytes
    exception_table_pointer: Optional[int]
    synthetic_name: bool = False


@dataclass
class ClassInfo:
    class_id: int
    info_physical: int
    info_pointer: int
    object_size: int
    vtable_length: int
    itable_length: int
    access_rom: int
    name_pointer: int
    name: Optional[str]
    methods_pointer: int
    fields_pointer: int
    interfaces_pointer: int
    constants_pointer: int
    vtable_pointer: int
    java_class_pointer: Optional[int] = None
    super_pointer: Optional[int] = None
    element_pointer: Optional[int] = None
    array_basic_type: Optional[int] = None
    methods: list[MethodInfo] = field(default_factory=list)
    fields: list[FieldInfo] = field(default_factory=list)
    interface_ids: list[int] = field(default_factory=list)


class Image:
    def __init__(self, path: Path, flash_base: int = FLASH_BASE):
        self.path = path
        self.data = path.read_bytes()
        self.flash_base = flash_base

    def off(self, address: int) -> int:
        offset = address - self.flash_base
        if not 0 <= offset < len(self.data):
            raise ValueError(f"address 0x{address:08x} is outside the image")
        return offset

    def u8o(self, offset: int) -> int:
        return self.data[offset]

    def u16o(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, offset)[0]

    def s16o(self, offset: int) -> int:
        return struct.unpack_from("<h", self.data, offset)[0]

    def u32o(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]

    def u16(self, address: int) -> int:
        return self.u16o(self.off(address))

    def u32(self, address: int) -> int:
        return self.u32o(self.off(address))

    def bytes(self, address: int, size: int) -> bytes:
        offset = self.off(address)
        return self.data[offset:offset + size]

    def symbol_bytes(self, pointer: int) -> bytes:
        # Source ROMizer removes OopDesc::_klass.  References retain the
        # logical object address, so SymbolDesc::_length is at pointer + 4.
        offset = self.off(pointer + 4)
        length = self.u16o(offset)
        if length > 0x4000 or offset + 2 + length > len(self.data):
            raise ValueError(f"invalid SymbolDesc at 0x{pointer:08x}")
        return self.data[offset + 2:offset + 2 + length]

    def symbol_text(self, pointer: int) -> Optional[str]:
        try:
            raw = self.symbol_bytes(pointer)
            if any(value < 0x20 or value >= 0x7f for value in raw):
                return None
            return raw.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            return None


class ROMExtractor:
    def __init__(self, image: Image, cp_pointer: Optional[int] = None,
                 structure_address: Optional[int] = None):
        self.image = image
        self.cp_pointer = cp_pointer
        self.structure_address = structure_address
        self.classes: dict[int, ClassInfo] = {}
        self.class_by_object: dict[int, ClassInfo] = {}

    def cp_entry(self, index: int) -> int:
        if self.cp_pointer is None:
            raise ValueError("system constant pool has not been located")
        return self.cp_entry_from(self.cp_pointer, index)

    def cp_entry_from(self, pointer: int, index: int) -> int:
        length = self.image.u16(pointer + 4)
        if not 0 <= index < length:
            raise ValueError(f"constant-pool index {index} >= {length}")
        return self.image.u32(pointer + 12 + index * 4)

    def cp_symbol(self, index: int) -> bytes:
        return self.image.symbol_bytes(self.cp_entry(index))

    def cp_symbol_from(self, pointer: int, index: int) -> bytes:
        return self.image.symbol_bytes(self.cp_entry_from(pointer, index))

    def _plausible_constant_pool(self, pointer: int) -> bool:
        try:
            offset = self.image.off(pointer)
            klass = self.image.u32o(offset)
            length = self.image.u16o(offset + 4)
            tags = self.image.u32o(offset + 8)
            return (16 <= length <= 65535 and
                    offset + 12 + length * 4 <= len(self.image.data) and
                    self.image.flash_base <= klass <
                    self.image.flash_base + len(self.image.data) and
                    self.image.flash_base <= tags <
                    self.image.flash_base + len(self.image.data))
        except (IndexError, ValueError, struct.error):
            return False

    def _class_candidate(self, offset: int) -> Optional[ClassInfo]:
        if offset < 0 or offset + 40 > len(self.image.data) or offset & 3:
            return None
        size_vtable = self.image.u32o(offset)
        object_size = size_vtable & 0xffff
        vtable_length = size_vtable >> 16
        itable_id = self.image.u32o(offset + 4)
        itable_length = itable_id & 0xffff
        class_id = itable_id >> 16
        access = self.image.u32o(offset + 12)
        if not (20 <= object_size <= 4096 and object_size % 4 == 0):
            return None
        if vtable_length >= 1024 or itable_length >= 4096 or class_id >= 4096:
            return None
        if not (access & ROM_PRELOADED):
            return None
        is_array = bool(access & ROM_ARRAY_CLASS)
        name_pointer = self.image.u32o(offset + 8)
        name = self.image.symbol_text(name_pointer)
        if not is_array:
            if name == ".unknown.":
                name = f"unknown/Class{class_id}"
            elif name is None or not ("/" in name or name in {"int", "void"}):
                return None
        elif access != 0x14000000:
            return None
        constants_pointer = 0
        interfaces_pointer = 0
        vtable_pointer = 0
        if not is_array:
            newer_constants = self.image.u32o(offset + 32)
            older_constants = self.image.u32o(offset + 28)
            if self._plausible_constant_pool(newer_constants):
                constants_pointer = newer_constants
                interfaces_pointer = self.image.u32o(offset + 28)
                vtable_pointer = self.image.flash_base + offset + 36
            elif self._plausible_constant_pool(older_constants):
                constants_pointer = older_constants
                interfaces_pointer = self.image.u32o(offset + 24)
                vtable_pointer = self.image.flash_base + offset + 32
            else:
                return None
        return ClassInfo(
            class_id=class_id,
            info_physical=self.image.flash_base + offset,
            info_pointer=self.image.flash_base + offset - 4,
            object_size=object_size,
            vtable_length=vtable_length,
            itable_length=itable_length,
            access_rom=access,
            name_pointer=name_pointer,
            name=name,
            methods_pointer=self.image.u32o(offset + 16) if not is_array else 0,
            fields_pointer=self.image.u32o(offset + 20) if not is_array else 0,
            interfaces_pointer=interfaces_pointer,
            constants_pointer=constants_pointer,
            vtable_pointer=vtable_pointer,
            array_basic_type=self.image.u32o(offset + 16) if is_array else None,
        )

    def locate_structure(self) -> int:
        """Locate java/lang/Object's ClassInfo using retained Symbol patterns."""
        if self.structure_address is not None:
            offsets = []
            try:
                requested = self.image.off(self.structure_address)
                offsets = [requested, requested + 4, requested - 4]
            except ValueError:
                pass
            for offset in offsets:
                candidate = self._class_candidate(offset)
                if candidate is not None:
                    self.structure_address = candidate.info_physical
                    return candidate.info_physical
            raise ValueError(
                f"0x{self.structure_address:08x} is not a valid ClassInfo address")

        marker = b"java/lang/Object"
        position = 0
        hits: list[int] = []
        while True:
            position = self.image.data.find(marker, position)
            if position < 0:
                break
            marker_position = position
            position += 1
            if marker_position < 2 or self.image.u16o(marker_position - 2) != len(marker):
                continue
            symbol_pointer = self.image.flash_base + marker_position - 6
            needle = struct.pack("<I", symbol_pointer)
            reference = 0
            while True:
                reference = self.image.data.find(needle, reference)
                if reference < 0:
                    break
                candidate = self._class_candidate(reference - 8)
                reference += 1
                if candidate is not None and candidate.name == "java/lang/Object":
                    hits.append(candidate.info_physical)
        hits = sorted(set(hits))
        if not hits:
            raise ValueError("java/lang/Object ClassInfo pattern was not found")
        if len(hits) > 1:
            # Prefer a candidate whose constant pool is itself structurally
            # valid; duplicate strings can occur in resources and update data.
            valid = []
            for address in hits:
                try:
                    candidate = self._class_candidate(self.image.off(address))
                    cp = candidate.constants_pointer if candidate else 0
                    length = self.image.u16(cp + 4)
                    if 16 <= length <= 65535:
                        valid.append(address)
                except ValueError:
                    pass
            if len(valid) == 1:
                hits = valid
        if len(hits) != 1:
            rendered = ", ".join(f"0x{address:08x}" for address in hits)
            raise ValueError(f"ambiguous ClassInfo pattern: {rendered}")
        self.structure_address = hits[0]
        return hits[0]

    def scan_classes(self) -> None:
        data = self.image.data
        anchor = self.locate_structure()
        if self.cp_pointer is None:
            anchor_info = self._class_candidate(self.image.off(anchor))
            if anchor_info is None:
                raise ValueError("located java/lang/Object ClassInfo became invalid")
            self.cp_pointer = anchor_info.constants_pointer
        start = 0
        end = len(data) - 40
        start = (start + 3) & ~3
        end = min(end, len(data) - 40)
        if start >= end:
            raise ValueError("empty ClassInfo scan range")
        candidates: dict[int, ClassInfo] = {}
        words = memoryview(data).cast("I")
        for offset in range(start, end, 4):
            if not words[offset // 4 + 3] & ROM_PRELOADED:
                continue
            info = self._class_candidate(offset)
            if info is None:
                continue
            class_id = info.class_id
            is_array = bool(info.access_rom & ROM_ARRAY_CLASS)
            # True ClassInfo objects have unique IDs. Prefer a decoded normal
            # class, but an exact array access flag is stronger than a random
            # normal-class-shaped hit in packed data.  Object-array IDs were
            # previously overwritten by such false positives (for example
            # class ID 3, the String[] class).
            old = candidates.get(class_id)
            old_is_array = bool(old and old.access_rom & ROM_ARRAY_CLASS)
            if (old is None or (is_array and not old_is_array) or
                    (not old_is_array and old.name is None and
                     info.name is not None)):
                candidates[class_id] = info
        self.classes = candidates
        self._locate_java_classes()
        self._name_array_classes()

    def _locate_java_classes(self) -> None:
        data = self.image.data
        by_info_pointer = {info.info_pointer: info
                           for info in self.classes.values()}
        words = memoryview(data).cast("I")
        for base in range(0, len(data) - 40, 4):
            info = by_info_pointer.get(words[base // 4 + 4])
            if info is None or info.java_class_pointer is not None:
                continue
            size_instance = words[base // 4 + 1]
            java_object_size = size_instance & 0xffff
            instance_size = struct.unpack_from("<h", data, base + 6)[0]
            if not (32 <= java_object_size <= 4096 and java_object_size % 4 == 0):
                continue
            if not (-8 <= instance_size <= 4096):
                continue
            klass = words[base // 4]
            if not (self.image.flash_base <= klass <
                    self.image.flash_base + len(data)):
                continue
            info.java_class_pointer = self.image.flash_base + base
            info.super_pointer = words[base // 4 + 8]
            info.element_pointer = words[base // 4 + 9]
            self.class_by_object[info.java_class_pointer] = info

    def _name_array_classes(self) -> None:
        resolving: set[int] = set()

        # Some builds keep the element JavaClass handle in a relocation
        # preamble immediately before ClassInfo. Build the reverse lookup once
        # instead of searching the complete fullflash separately for every
        # array class.
        relocated_elements: dict[int, tuple[int, ClassInfo]] = {}
        for candidate in self.classes.values():
            candidate_offset = self.image.off(candidate.info_physical)
            for distance in range(1, 65):
                offset = candidate_offset - distance
                if offset < 0:
                    break
                pointer = self.image.u32o(offset)
                old = relocated_elements.get(pointer)
                if old is None or distance < old[0]:
                    relocated_elements[pointer] = (distance, candidate)

        def relocated_element(pointer: int) -> Optional[ClassInfo]:
            """Resolve a relocated JavaClass handle via its ClassInfo preamble."""
            match = relocated_elements.get(pointer)
            return match[1] if match else None

        def descriptor(info: ClassInfo) -> str:
            core_name = CORE_ARRAY_BY_CLASS_ID.get(info.class_id)
            if core_name is not None:
                info.name = core_name
                return core_name
            if info.name is not None:
                return info.name if info.name.startswith("[") else f"L{info.name};"
            if info.class_id in resolving:
                return f"[Lunknown/Class{info.class_id};"
            resolving.add(info.class_id)
            basic = info.array_basic_type or 0
            if basic in PRIMITIVE_BY_BASIC_TYPE:
                result = "[" + PRIMITIVE_BY_BASIC_TYPE[basic]
            else:
                element_pointer = info.element_pointer or 0
                element = (self.class_by_object.get(element_pointer) or
                           relocated_element(element_pointer))
                result = "[" + (descriptor(element) if element else f"Lunknown/Class{info.class_id};")
            resolving.remove(info.class_id)
            info.name = result
            return result

        for info in self.classes.values():
            if info.access_rom & ROM_ARRAY_CLASS:
                descriptor(info)

    @staticmethod
    def _package_of(name: Optional[str]) -> Optional[str]:
        if not name or "/" not in name or name.startswith("unknown/"):
            return None
        return name.rsplit("/", 1)[0]

    def assign_unknown_packages(self) -> None:
        """Place ROMizer-renamed classes in the most likely package.

        Class IDs preserve suite/link order even though physical objects are
        later compacted.  Combine neighboring named classes with retained
        superclass, interface, field, and method signature references.  The
        basename remains the deterministic Class<ID> because the original
        basename is absent from product ROMs.
        """
        old_array_names = {
            item.class_id: item.name for item in self.classes.values()
            if item.access_rom & ROM_ARRAY_CLASS
        }
        ordinary = sorted((item for item in self.classes.values()
                           if item.name and not item.name.startswith("[")),
                          key=lambda item: item.class_id)
        positions = {item.class_id: index for index, item in enumerate(ordinary)}
        generic_supers = {
            "java/lang/Object", "java/lang/Thread", "java/lang/Exception",
            "java/util/TimerTask",
        }
        assignments: dict[str, str] = {}
        existing = {item.name for item in ordinary if item.name}
        unknown_by_name = {
            item.name: item for item in ordinary
            if item.name and item.name.startswith("unknown/Class")
        }
        base_scores: dict[str, collections.Counter[str]] = {}
        related_unknowns: dict[str, collections.Counter[str]] = {
            name: collections.Counter() for name in unknown_by_name
        }

        for info in ordinary:
            old_name = info.name
            if old_name is None or not old_name.startswith("unknown/Class"):
                continue
            scores: collections.Counter[str] = collections.Counter()
            position = positions[info.class_id]
            neighbors: list[tuple[str, int]] = []
            for sequence in (reversed(ordinary[:position]), ordinary[position + 1:]):
                for neighbor in sequence:
                    package = self._package_of(neighbor.name)
                    if package:
                        distance = abs(neighbor.class_id - info.class_id)
                        scores[package] += max(1, 12 - 2 * distance)
                        neighbors.append((package, distance))
                        break
            if len(neighbors) == 2 and neighbors[0][0] == neighbors[1][0]:
                scores[neighbors[0][0]] += 12

            super_info = self.superclass(info)
            super_name = super_info.name if super_info else None
            package = self._package_of(super_name)
            if package and super_name not in generic_supers:
                scores[package] += 5 if package.startswith("java/") else 10

            for interface_id in info.interface_ids:
                interface = self.classes.get(interface_id)
                package = self._package_of(interface.name if interface else None)
                if package:
                    scores[package] += 4 if package.startswith("java/") else 8

            references: collections.Counter[str] = collections.Counter()
            descriptors = ([field.descriptor for field in info.fields] +
                           [method.descriptor for method in info.methods])
            for descriptor in descriptors:
                for referenced_name in re.findall(r"L([^;]+);", descriptor):
                    package = self._package_of(referenced_name)
                    if package and package != "java/lang":
                        references[package] += 1
            for package, count in references.items():
                scores[package] += min(count, 6)

            for descriptor in descriptors:
                for referenced_name in re.findall(r"L([^;]+);", descriptor):
                    if referenced_name in unknown_by_name:
                        related_unknowns[old_name][referenced_name] += 4
                        related_unknowns[referenced_name][old_name] += 4
            if super_name in unknown_by_name:
                related_unknowns[old_name][super_name] += 8
                related_unknowns[super_name][old_name] += 8
            for interface_id in info.interface_ids:
                interface = self.classes.get(interface_id)
                if interface and interface.name in unknown_by_name:
                    related_unknowns[old_name][interface.name] += 8
                    related_unknowns[interface.name][old_name] += 8

            base_scores[old_name] = scores

        # A named class mentioning a ROMizer-hidden type is especially useful:
        # hidden types are commonly package-private helpers of that class.  This
        # reverse evidence also prevents generic interfaces such as Enumeration
        # from pulling an implementation into java/util.
        def bytecode_targets(source: ClassInfo
                             ) -> list[tuple[ClassInfo, int]]:
            result: list[tuple[ClassInfo, int]] = []
            for method in source.methods:
                bci = 0
                try:
                    while bci < len(method.code):
                        opcode = method.code[bci]
                        target: Optional[ClassInfo] = None
                        if opcode in {0xbb, 0xbd, 0xc0, 0xc1,
                                      0xe8, 0xe9, 0xea, 0xeb}:
                            cp_index = int.from_bytes(
                                method.code[bci + 1:bci + 3], "big")
                            class_id = self.cp_entry_from(
                                method.constants_pointer, cp_index)
                            target = self.classes.get(class_id)
                            weight = 40 if opcode in {0xbb, 0xe8} else 10
                        elif opcode in {0xce, 0xcf, 0xd0, 0xd1, 0xd2,
                                        0xf6, 0xf7, 0xf8, 0xf9, 0xfa}:
                            cp_index = int.from_bytes(
                                method.code[bci + 1:bci + 3], "big")
                            value = self.cp_entry_from(
                                method.constants_pointer, cp_index)
                            target = self.classes.get(value & 0xffff)
                            weight = 16
                        elif opcode in {0xe2, 0xe3, 0xe6, 0xe7}:
                            cp_index = int.from_bytes(
                                method.code[bci + 1:bci + 3], "big")
                            value = self.cp_entry_from(
                                method.constants_pointer, cp_index)
                            if opcode == 0xe3 or value >= self.image.flash_base:
                                target_method = self.parse_method(value)
                                target = self.classes.get(target_method.holder_id)
                            else:
                                target = self.classes.get(value >> 16)
                            weight = 16
                        else:
                            weight = 0
                        if target is not None:
                            result.append((target, weight))
                        bci += bytecode_length(method.code, bci)
                except (IndexError, ValueError):
                    pass
            return result

        for source in ordinary:
            source_package = self._package_of(source.name)
            if not source_package:
                continue
            descriptors = ([field.descriptor for field in source.fields] +
                           [method.descriptor for method in source.methods])
            referenced = collections.Counter(
                name for descriptor in descriptors
                for name in re.findall(r"L([^;]+);", descriptor)
                if name in unknown_by_name
            )
            for name, count in referenced.items():
                base_scores[name][source_package] += min(16, 8 * count)

            super_info = self.superclass(source)
            if super_info and super_info.name in unknown_by_name:
                base_scores[super_info.name][source_package] += 16
            for interface_id in source.interface_ids:
                interface = self.classes.get(interface_id)
                if interface and interface.name in unknown_by_name:
                    base_scores[interface.name][source_package] += 16

            # Quickened bytecode retains exact class IDs for allocations,
            # casts, static members and calls.  Those are stronger package
            # evidence than class-ID proximity, particularly for private
            # helper classes linked late by the ROMizer.
            for target, weight in bytecode_targets(source):
                if target.name in unknown_by_name:
                    base_scores[target.name][source_package] += weight

        inferred = {
            name: (scores.most_common(1)[0][0] if scores else "unknown")
            for name, scores in base_scores.items()
        }
        for _ in range(6):
            updated: dict[str, str] = {}
            for name, base in base_scores.items():
                scores = base.copy()
                for related_name, weight in related_unknowns[name].items():
                    package = inferred.get(related_name)
                    if package and package != "unknown":
                        scores[package] += min(weight, 16)
                updated[name] = (scores.most_common(1)[0][0]
                                 if scores else "unknown")
            if updated == inferred:
                break
            inferred = updated

        for old_name, info in unknown_by_name.items():
            package = inferred[old_name]
            new_name = f"{package}/Class{info.class_id}"
            if new_name in existing:
                new_name = f"{package}/RomClass{info.class_id}"
            existing.add(new_name)
            assignments[old_name] = new_name

        if not assignments:
            return
        for info in self.classes.values():
            if info.name in assignments:
                info.name = assignments[info.name]
            elif info.name:
                for old_name, new_name in assignments.items():
                    if old_name in info.name:
                        info.name = info.name.replace(old_name, new_name)
            for field_info in info.fields:
                for old_name, new_name in assignments.items():
                    field_info.descriptor = field_info.descriptor.replace(
                        old_name, new_name)
            for method in info.methods:
                for old_name, new_name in assignments.items():
                    method.descriptor = method.descriptor.replace(old_name,
                                                                  new_name)

        # Rebuild array descriptors from the now-packaged element classes.
        # A descriptor parsed before this point can otherwise retain the
        # package inferred for an adjacent class rather than its real element.
        for info in self.classes.values():
            if info.access_rom & ROM_ARRAY_CLASS:
                info.name = None
        self._name_array_classes()
        array_renames = {
            old_array_names[class_id]: info.name
            for class_id, info in self.classes.items()
            if class_id in old_array_names and old_array_names[class_id] and
            info.name and old_array_names[class_id] != info.name
        }
        for info in self.classes.values():
            for field_info in info.fields:
                for old_name, new_name in array_renames.items():
                    field_info.descriptor = field_info.descriptor.replace(
                        old_name, new_name)
            for method in info.methods:
                for old_name, new_name in array_renames.items():
                    method.descriptor = method.descriptor.replace(old_name,
                                                                  new_name)

    def type_descriptor(self, raw: bytes, method: bool) -> str:
        if method:
            if len(raw) < 3:
                raise ValueError("short encoded method signature")
            pos = 2
            ret, pos = self._type_token(raw, pos)
            params: list[str] = []
            while pos < len(raw):
                item, pos = self._type_token(raw, pos)
                params.append(item)
            return "(" + "".join(params) + ")" + ret
        value, pos = self._type_token(raw, 0)
        if pos != len(raw):
            raise ValueError("trailing bytes in encoded field type")
        return value

    def _type_token(self, raw: bytes, pos: int) -> tuple[str, int]:
        if pos >= len(raw):
            raise ValueError("missing encoded type")
        first = raw[pos]
        if first < 0x80:
            value = chr(first)
            if value not in "BCDFIJSZV":
                raise ValueError(f"bad primitive type 0x{first:02x}")
            return value, pos + 1
        if pos + 1 >= len(raw) or raw[pos + 1] < 0x80:
            raise ValueError("bad encoded class id")
        class_id = ((first & 0x7f) << 7) | (raw[pos + 1] & 0x7f)
        core_array = CORE_ARRAY_BY_CLASS_ID.get(class_id)
        if core_array is not None:
            return core_array, pos + 2
        info = self.classes.get(class_id)
        if info is None or info.name is None:
            return f"Lunknown/Class{class_id};", pos + 2
        if info.name.startswith("["):
            return info.name, pos + 2
        return f"L{info.name};", pos + 2

    def _array_payload(self, pointer: int, element_size: int, max_length: int) -> tuple[int, int]:
        if pointer == 0:
            return 0, 0
        offset = self.image.off(pointer)
        direct = self.image.u32o(offset)
        with_header = self.image.u32o(offset + 4)
        direct_end = offset + 4 + direct * element_size
        header_end = offset + 8 + with_header * element_size
        if direct <= max_length and direct_end <= len(self.image.data):
            return direct, pointer + 4
        if with_header <= max_length and header_end <= len(self.image.data):
            return with_header, pointer + 8
        raise ValueError(f"invalid ROM array at 0x{pointer:08x}")

    def _method_pointers(self, pointer: int) -> list[int]:
        if pointer == 0:
            return []
        # Method tables occur both with a retained klass header (segment
        # boundary/special arrays) and with that header removed.
        candidates: list[list[int]] = []
        for length_address, data_address in ((pointer, pointer + 4), (pointer + 4, pointer + 8)):
            try:
                length = self.image.u32(length_address)
                if not 0 <= length <= 4096:
                    continue
                values = [self.image.u32(data_address + i * 4) for i in range(length)]
                if all(value == 0 or self._looks_like_method(value) for value in values):
                    candidates.append(values)
            except ValueError:
                pass
        if candidates:
            return max(candidates, key=len)
        raise ValueError(f"invalid method table at 0x{pointer:08x}")

    def _looks_like_method(self, pointer: int) -> bool:
        try:
            access = self.image.u16(pointer + 24)
            holder = self.image.u16(pointer + 26)
            code_size = self.image.u16(pointer + 38)
            name_index = self.image.u16(pointer + 34)
            sig_index = self.image.u16(pointer + 36)
            constants = self.cp_pointer if access & 0x0200 else self.image.u32(pointer + 4)
            cp_length = self.image.u16(constants + 4)
            if not (holder in self.classes and code_size < 0x8000 and name_index < cp_length and sig_index < cp_length):
                return False
            name = self.cp_symbol_from(constants, name_index)
            if not name or any(value < 0x20 or value >= 0x7f for value in name):
                return False
            self.type_descriptor(self.cp_symbol_from(constants, sig_index), method=True)
            return True
        except (ValueError, UnicodeDecodeError):
            return False

    def parse_method(self, pointer: int) -> MethodInfo:
        access = self.image.u16(pointer + 24)
        name_index = self.image.u16(pointer + 34)
        signature_index = self.image.u16(pointer + 36)
        code_size = self.image.u16(pointer + 38)
        constants = self.cp_pointer if access & 0x0200 else self.image.u32(pointer + 4)
        name = self.cp_symbol_from(constants, name_index).decode("ascii", "replace")
        descriptor = self.type_descriptor(self.cp_symbol_from(constants, signature_index), method=True)
        synthetic_name = name in {".unknown.", "<unknown>"}
        if synthetic_name:
            name = synthetic_method_name(pointer)
        exception_pointer = None if access & ROM_NO_EXCEPTIONS else self.image.u32(pointer + 8)
        if exception_pointer == 0:
            exception_pointer = None
        return MethodInfo(
            address=pointer,
            access_rom=access,
            holder_id=self.image.u16(pointer + 26),
            max_stack=self.image.u16(pointer + 28),
            max_locals=self.image.u16(pointer + 30),
            attributes=self.image.u16(pointer + 32),
            name=name,
            descriptor=descriptor,
            constants_pointer=constants,
            code=self.image.bytes(pointer + 40, code_size),
            exception_table_pointer=exception_pointer,
            synthetic_name=synthetic_name,
        )

    def parse_class(self, info: ClassInfo) -> ClassInfo:
        if info.access_rom & ROM_ARRAY_CLASS:
            return info
        methods: list[MethodInfo] = []
        for pointer in self._method_pointers(info.methods_pointer):
            if pointer:
                methods.append(self.parse_method(pointer))
        info.methods = methods

        length, data_pointer = self._array_payload(info.fields_pointer, 2, 65535)
        if length % 5:
            # Retry the alternative header interpretation.
            off = self.image.off(info.fields_pointer)
            alt = self.image.u32o(off + 4)
            if alt <= 65535 and alt % 5 == 0:
                length, data_pointer = alt, info.fields_pointer + 8
        fields: list[FieldInfo] = []
        for index in range(0, length, 5):
            values = [self.image.u16(data_pointer + 2 * (index + j)) for j in range(5)]
            try:
                name = self.cp_symbol_from(info.constants_pointer, values[1]).decode("ascii", "replace")
                descriptor = self.type_descriptor(self.cp_symbol_from(info.constants_pointer, values[2]), method=False)
            except ValueError:
                continue
            synthetic_name = name in {".unknown.", "<unknown>"}
            if synthetic_name:
                prefix = "staticField" if values[0] & ACC_STATIC else "field"
                name = f"{prefix}{values[4]:04X}{descriptor_name(descriptor)}"
            fields.append(FieldInfo(values[0], name, descriptor, values[3],
                                    values[4], synthetic_name))
        info.fields = fields

        # A source-ROM TypeArray may retain its klass word or have it removed.
        # Small klass pointers can look like plausible lengths, so choose the
        # layout whose elements are actual interface class IDs.
        interface_candidates: list[list[int]] = []
        if info.interfaces_pointer:
            for length_address, data_pointer in (
                    (info.interfaces_pointer, info.interfaces_pointer + 4),
                    (info.interfaces_pointer + 4, info.interfaces_pointer + 8)):
                try:
                    length = self.image.u32(length_address)
                    if length > 256:
                        continue
                    values = [self.image.u16(data_pointer + i * 2) for i in range(length)]
                    if all(0 < value < 4096 and
                           (value not in self.classes or
                            self.classes[value].access_rom & ACC_INTERFACE)
                           for value in values):
                        interface_candidates.append(values)
                except ValueError:
                    pass
        if not interface_candidates:
            raise ValueError(f"invalid interface table at 0x{info.interfaces_pointer:08x}")
        info.interface_ids = max(interface_candidates, key=len)
        return info

    def superclass(self, info: ClassInfo) -> Optional[ClassInfo]:
        return self.class_by_object.get(info.super_pointer or 0)

    def rom_string(self, pointer: int) -> str:
        array = self.image.u32(pointer + 4)
        offset = self.image.u32(pointer + 8)
        count = self.image.u32(pointer + 12)
        array_length = self.image.u32(array + 4)
        if count > 0x10000 or offset > array_length or count > array_length - offset:
            raise ValueError(f"0x{pointer:08x} is not a plausible ROM String")
        # The shared char array retains klass + length, hence data starts at +8.
        raw = self.image.bytes(array + 8 + offset * 2, count * 2)
        return raw.decode("utf-16le", "surrogatepass")


class ConstantPoolBuilder:
    def __init__(self):
        self.entries: list[bytes] = []
        self.cache: dict[tuple[str, ...], int] = {}

    def utf8(self, value: str) -> int:
        key = ("utf8", value)
        if key not in self.cache:
            raw = modified_utf8(value)
            self.entries.append(b"\x01" + struct.pack(">H", len(raw)) + raw)
            self.cache[key] = len(self.entries)
        return self.cache[key]

    def klass(self, value: str) -> int:
        key = ("class", value)
        if key not in self.cache:
            name_index = self.utf8(value)
            self.entries.append(b"\x07" + struct.pack(">H", name_index))
            self.cache[key] = len(self.entries)
        return self.cache[key]

    def name_and_type(self, name: str, descriptor: str) -> int:
        key = ("name_type", name, descriptor)
        if key not in self.cache:
            name_index = self.utf8(name)
            descriptor_index = self.utf8(descriptor)
            self.entries.append(b"\x0c" + struct.pack(">HH", name_index, descriptor_index))
            self.cache[key] = len(self.entries)
        return self.cache[key]

    def fieldref(self, owner: str, name: str, descriptor: str) -> int:
        key = ("field", owner, name, descriptor)
        if key not in self.cache:
            class_index = self.klass(owner)
            type_index = self.name_and_type(name, descriptor)
            self.entries.append(b"\x09" + struct.pack(">HH", class_index, type_index))
            self.cache[key] = len(self.entries)
        return self.cache[key]

    def methodref(self, owner: str, name: str, descriptor: str,
                  interface: bool = False) -> int:
        kind = "interface_method" if interface else "method"
        key = (kind, owner, name, descriptor)
        if key not in self.cache:
            class_index = self.klass(owner)
            type_index = self.name_and_type(name, descriptor)
            tag = b"\x0b" if interface else b"\x0a"
            self.entries.append(tag + struct.pack(">HH", class_index, type_index))
            self.cache[key] = len(self.entries)
        return self.cache[key]

    def string(self, value: str) -> int:
        key = ("string", value)
        if key not in self.cache:
            utf8_index = self.utf8(value)
            self.entries.append(b"\x08" + struct.pack(">H", utf8_index))
            self.cache[key] = len(self.entries)
        return self.cache[key]

    def integer_bits(self, value: int) -> int:
        key = ("integer", str(value & 0xffffffff))
        if key not in self.cache:
            self.entries.append(b"\x03" + struct.pack(">I", value & 0xffffffff))
            self.cache[key] = len(self.entries)
        return self.cache[key]

    def float_bits(self, value: int) -> int:
        key = ("float", str(value & 0xffffffff))
        if key not in self.cache:
            self.entries.append(b"\x04" + struct.pack(">I", value & 0xffffffff))
            self.cache[key] = len(self.entries)
        return self.cache[key]

    def wide_bits(self, value: int, is_double: bool) -> int:
        kind = "double" if is_double else "long"
        key = (kind, str(value & 0xffffffffffffffff))
        if key not in self.cache:
            tag = b"\x06" if is_double else b"\x05"
            self.entries.append(tag + struct.pack(">Q", value & 0xffffffffffffffff))
            self.cache[key] = len(self.entries)
            self.entries.append(b"")  # long/double reserve the following CP slot
        return self.cache[key]

    def render(self) -> bytes:
        return struct.pack(">H", len(self.entries) + 1) + b"".join(self.entries)


def modified_utf8(value: str) -> bytes:
    """Encode a CONSTANT_Utf8 payload, including unpaired UTF-16 surrogates."""
    out = bytearray()
    units: list[int] = []
    for character in value:
        codepoint = ord(character)
        if codepoint <= 0xffff:
            units.append(codepoint)
        else:
            codepoint -= 0x10000
            units.extend((0xd800 | (codepoint >> 10),
                          0xdc00 | (codepoint & 0x3ff)))
    for unit in units:
        if 0x01 <= unit <= 0x7f:
            out.append(unit)
        elif unit <= 0x7ff:
            out.extend((0xc0 | (unit >> 6), 0x80 | (unit & 0x3f)))
        else:
            out.extend((0xe0 | (unit >> 12),
                        0x80 | ((unit >> 6) & 0x3f),
                        0x80 | (unit & 0x3f)))
    return bytes(out)


def clean_class_access(access: int) -> int:
    result = access & (ACC_PUBLIC | ACC_FINAL | 0x0020 | ACC_INTERFACE | ACC_ABSTRACT)
    # Package placement is inferred when ROMizer erased a class name.  Promote
    # visibility so an approximate package never makes otherwise recovered
    # source uncompilable.
    result |= ACC_PUBLIC
    if result & ACC_INTERFACE:
        result = (result | ACC_ABSTRACT) & ~ACC_FINAL
    elif result & ACC_ABSTRACT:
        result &= ~ACC_FINAL
    if access & ACC_SYNTHETIC_ROM:
        result |= 0x1000
    return result


def clean_field_access(access: int) -> int:
    result = access & 0x00df
    result = (result & ~(ACC_PRIVATE | ACC_PROTECTED)) | ACC_PUBLIC
    if access & ACC_SYNTHETIC_ROM:
        result |= 0x1000
    return result


def clean_method_access(access: int) -> int:
    # 0x40/0x80 and 0x200/0x1000/0x4000/0x8000 are phoneME-internal.
    result = access & (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC |
                       ACC_FINAL | ACC_SYNCHRONIZED | ACC_NATIVE |
                       ACC_ABSTRACT | ACC_STRICT)
    result = (result & ~(ACC_PRIVATE | ACC_PROTECTED)) | ACC_PUBLIC
    if access & ACC_SYNTHETIC_ROM:
        result |= 0x1000
    if result & ACC_ABSTRACT:
        result &= ~(ACC_NATIVE | ACC_FINAL | ACC_SYNCHRONIZED | ACC_STRICT)
    return result


def descriptor_name(descriptor: Optional[str]) -> str:
    """Return a compact Java-like type label for a synthetic field name."""
    if not descriptor:
        return "value"
    dimensions = len(descriptor) - len(descriptor.lstrip("["))
    base = descriptor[dimensions:]
    primitive = {
        "Z": "boolean", "B": "byte", "C": "char", "S": "short",
        "I": "int", "J": "long", "F": "float", "D": "double",
    }
    if base in primitive:
        label = primitive[base]
    elif base.startswith("L") and base.endswith(";"):
        label = base[1:-1].rsplit("/", 1)[-1]
    else:
        label = "Object"
    label = re.sub(r"[^0-9A-Za-z_]", "_", label)
    return label + "Array" * dimensions


def synthetic_method_name(address: int) -> str:
    return f"method{address:08X}"


def assign_synthetic_member_names(info: ClassInfo) -> None:
    """Assign short, unique Java-style names after discovery settles."""
    used = {item.name for item in info.fields if not item.synthetic_name}
    for item in sorted((field for field in info.fields if field.synthetic_name),
                       key=lambda field: (field.offset, field.descriptor,
                                          bool(field.access & ACC_STATIC))):
        prefix = "static" if item.access & ACC_STATIC else "field"
        base = f"{prefix}{item.offset:04X}"
        name = base
        serial = 2
        while name in used:
            name = f"{base}_{serial}"
            serial += 1
        item.name = name
        used.add(name)

    used_methods = {item.name for item in info.methods
                    if not item.synthetic_name}
    serial = 1
    for item in (method for method in info.methods if method.synthetic_name):
        name = f"method{serial}"
        while name in used_methods:
            serial += 1
            name = f"method{serial}"
        item.name = name
        used_methods.add(name)
        serial += 1


def emitted_member_name(name: str, address_or_offset: int, kind: str,
                        descriptor: Optional[str] = None,
                        is_static: bool = False) -> str:
    """Make a Java-style JVM name for metadata removed by ROMizer."""
    if name not in {".unknown.", "<unknown>"} and not any(ch in name for ch in ".;[/"):
        return name
    if kind == "method":
        return synthetic_method_name(address_or_offset)
    prefix = "staticField" if is_static else "field"
    return f"{prefix}{address_or_offset:04X}{descriptor_name(descriptor)}"


def return_opcode(descriptor: str) -> bytes:
    ret = descriptor[descriptor.rfind(")") + 1:]
    if ret == "V":
        return b"\xb1"
    if ret in {"J"}:
        return b"\x09\xad"  # lconst_0; lreturn
    if ret in {"D"}:
        return b"\x0e\xaf"  # dconst_0; dreturn
    if ret in {"F"}:
        return b"\x0b\xae"  # fconst_0; freturn
    if ret.startswith("L") or ret.startswith("["):
        return b"\x01\xb0"  # aconst_null; areturn
    return b"\x03\xac"      # iconst_0; ireturn


def descriptor_parameters(descriptor: str) -> list[str]:
    """Split a JVM method descriptor into parameter descriptors."""
    result: list[str] = []
    pos = 1
    while descriptor[pos] != ")":
        start = pos
        while descriptor[pos] == "[":
            pos += 1
        if descriptor[pos] == "L":
            pos = descriptor.index(";", pos) + 1
        else:
            pos += 1
        result.append(descriptor[start:pos])
    return result


# Fixed instruction lengths for the standard JVM opcodes whose length exceeds
# one byte.  Switch and wide are handled separately below.
JVM_LENGTHS = {16: 2, 17: 3, 18: 2, 19: 3, 20: 3, 132: 3, 169: 2,
               178: 3, 179: 3, 180: 3, 181: 3, 182: 3, 183: 3,
               184: 3, 185: 5, 187: 3, 188: 2, 189: 3, 192: 3,
               193: 3, 197: 4, 198: 3, 199: 3, 200: 5}
for _first, _last, _length in ((21, 25, 2), (54, 58, 2), (153, 168, 3)):
    JVM_LENGTHS.update({_opcode: _length for _opcode in range(_first, _last + 1)})

# Even an unquickened occurrence of one of these needs a class-file constant
# pool entry.  ROM indices cannot be copied into the newly built pool.
JVM_CP_OPCODES = {18, 19, 20, 178, 179, 180, 181, 182, 183, 184, 185,
                  186, 187, 189, 192, 193, 197}


def bytecode_length(code: bytes, bci: int) -> int:
    """Return the phoneME/JVM instruction length at bci.

    EL71 uses the no-Java-stack-tags, no-CPU-variant private bytecode enum.
    The only variable private instruction, init_static_array (0xf1), is
    deliberately rejected because its inline payload is VM-specific.
    """
    opcode = code[bci]
    if opcode == 0xaa:  # tableswitch
        aligned = (bci + 4) & ~3
        if aligned + 12 > len(code):
            raise ValueError("truncated tableswitch")
        low = int.from_bytes(code[aligned + 4:aligned + 8], "big", signed=True)
        high = int.from_bytes(code[aligned + 8:aligned + 12], "big", signed=True)
        if high < low:
            raise ValueError("invalid tableswitch range")
        return aligned - bci + 12 + 4 * (high - low + 1)
    if opcode == 0xab:  # lookupswitch
        aligned = (bci + 4) & ~3
        if aligned + 8 > len(code):
            raise ValueError("truncated lookupswitch")
        pairs = int.from_bytes(code[aligned + 4:aligned + 8], "big", signed=True)
        if pairs < 0:
            raise ValueError("invalid lookupswitch pair count")
        return aligned - bci + 8 + 8 * pairs
    if opcode == 0xc4:  # wide
        if bci + 2 > len(code):
            raise ValueError("truncated wide")
        return 6 if code[bci + 1] == 0x84 else 4
    if opcode == 0xf1:
        raise ValueError("phoneME init_static_array has a variable payload")
    if opcode == 0xe4:  # fast_invokeinterface keeps count + reserved operands
        return 5
    if 0xcb <= opcode <= 0xd2 or 0xd3 <= opcode <= 0xeb or 0xf6 <= opcode <= 0xfc:
        return {0xcb: 2, 0xec: 2, 0xed: 2, 0xee: 2, 0xef: 2}.get(opcode, 3)
    if 0xec <= opcode <= 0xef:
        return 2
    if 0xf0 <= opcode <= 0xf5:
        return 1
    return JVM_LENGTHS.get(opcode, 1)


INSTANCE_FIELD_OPS = {
    0xd3: (0xb5, "B", 1), 0xd4: (0xb5, "S", 1),
    0xd5: (0xb5, "I", 4), 0xd6: (0xb5, "J", 4),
    0xd7: (0xb5, "F", 4), 0xd8: (0xb5, "D", 4),
    0xd9: (0xb5, "Ljava/lang/Object;", 4),
    0xda: (0xb4, "B", 1), 0xdb: (0xb4, "S", 1),
    0xdc: (0xb4, "I", 4), 0xdd: (0xb4, "J", 4),
    0xde: (0xb4, "F", 4), 0xdf: (0xb4, "D", 4),
    0xe0: (0xb4, "Ljava/lang/Object;", 4), 0xe1: (0xb4, "C", 1),
}


def _descriptor_matches(actual: str, inferred: str) -> bool:
    if inferred == "B":
        return actual in {"B", "Z"}
    if inferred == "Ljava/lang/Object;":
        return actual.startswith("L") or actual.startswith("[")
    return actual == inferred


ARRAY_DESCRIPTOR_BY_OPCODE = {
    0x2e: "[I", 0x2f: "[J", 0x30: "[F", 0x31: "[D",
    0x32: "[Ljava/lang/Object;", 0x33: "[B", 0x34: "[C", 0x35: "[S",
    0x4f: "[I", 0x50: "[J", 0x51: "[F", 0x52: "[D",
    0x53: "[Ljava/lang/Object;", 0x54: "[B", 0x55: "[C", 0x56: "[S",
}

FLOAT_CONSUMERS = ({0x30, 0x38, 0x51, 0xae, 0x62, 0x66, 0x6a, 0x6e, 0x72, 0x76,
                    0x8b, 0x8c, 0x8d, 0x95, 0x96, 0xd7, 0xde} |
                   set(range(0x43, 0x47)))
INT_CONSUMERS = ({0x2e, 0x33, 0x34, 0x35, 0x36, 0x4f, 0x54, 0x55, 0x56,
                  0xac, 0x60, 0x64, 0x68, 0x6c, 0x70, 0x74,
                  0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x85, 0x86,
                  0x87, 0xd3, 0xd4, 0xd5} | set(range(0x3b, 0x3f)) |
                 set(range(0x99, 0xa5)))
DOUBLE_CONSUMERS = ({0x31, 0x39, 0x52, 0xaf, 0x63, 0x67, 0x6b, 0x6f, 0x73, 0x77,
                     0x8e, 0x8f, 0x90, 0x97, 0x98, 0xd8, 0xdf} |
                    set(range(0x47, 0x4b)))
LONG_CONSUMERS = ({0x2f, 0x37, 0x50, 0xad, 0x61, 0x65, 0x69, 0x6d, 0x71, 0x75,
                   0x79, 0x7b, 0x7d, 0x7f, 0x81, 0x83, 0x88, 0x89,
                   0x8a, 0x94, 0xd6, 0xdd} | set(range(0x3f, 0x43)))


def infer_numeric_ldc_kind(code: bytes, bci: int, two_word: bool) -> Optional[str]:
    """Infer an erased numeric constant tag from nearby typed consumers."""
    cursor = bci + bytecode_length(code, bci)
    for _ in range(10):
        if cursor >= len(code):
            break
        opcode = code[cursor]
        if two_word:
            if opcode in DOUBLE_CONSUMERS:
                return "double"
            if opcode in LONG_CONSUMERS:
                return "long"
        else:
            if opcode in FLOAT_CONSUMERS:
                return "float"
            if opcode in INT_CONSUMERS:
                return "int"
        # Crossing a control-flow boundary makes proximity unreliable.
        if opcode in set(range(0x99, 0xaa)) | {0xaa, 0xab, 0xac, 0xad,
                                               0xae, 0xaf, 0xb0, 0xb1,
                                               0xbf, 0xc6, 0xc7, 0xc8}:
            break
        cursor += bytecode_length(code, cursor)
    return None


def infer_numeric_bits_kind(value: int, two_word: bool) -> str:
    """Last-resort classification after bytecode/signature evidence.

    Source ROMs built without Java stack tags erase the distinction.  IEEE
    special values and ordinary finite floating-point encodings remain
    recognizable; firmware resource IDs use tagged 0x1000/0x4000 high words.
    """
    if two_word:
        exponent = (value >> 52) & 0x7ff
        return "double" if exponent == 0x7ff else "long"
    exponent = (value >> 23) & 0xff
    if exponent == 0xff:
        return "float"
    if (value >> 16) in {0x1000, 0x4000}:
        return "int"
    magnitude = value & 0x7fffffff
    if 0x38000000 <= magnitude <= 0x4f000000:
        return "float"
    return "int"


def infer_reference_field_descriptors(info: ClassInfo) -> dict[int, str]:
    """Infer erased reference-field types from their observable array use."""
    evidence: dict[int, set[str]] = {}
    for method in info.methods:
        instructions: list[tuple[int, int]] = []
        bci = 0
        try:
            while bci < len(method.code):
                instructions.append((bci, method.code[bci]))
                bci += bytecode_length(method.code, bci)
        except ValueError:
            continue
        local_origin: dict[int, int] = {}
        for position, (at, opcode) in enumerate(instructions):
            offset: Optional[int] = None
            if opcode == 0xe0:
                offset = int.from_bytes(method.code[at + 1:at + 3], "big") * 4
            elif opcode == 0xed:
                offset = method.code[at + 1] * 4
            elif opcode == 0xee:
                offset = method.code[at + 1] * 4
            elif opcode in {0xf2, 0xf4}:
                offset = 4 if opcode == 0xf2 else 8
            if offset is not None:
                # Track the common getfield; astore[_n] form.
                if position + 1 < len(instructions):
                    next_at, next_opcode = instructions[position + 1]
                    if next_opcode == 0x3a:
                        local_origin[method.code[next_at + 1]] = offset
                    elif 0x4b <= next_opcode <= 0x4e:
                        local_origin[next_opcode - 0x4b] = offset
                # Also catch a directly consumed array reference.
                for _, following in instructions[position + 1:position + 8]:
                    if following in ARRAY_DESCRIPTOR_BY_OPCODE:
                        evidence.setdefault(offset, set()).add(
                            ARRAY_DESCRIPTOR_BY_OPCODE[following])
                        break
            local: Optional[int] = None
            if opcode == 0x19:
                local = method.code[at + 1]
            elif 0x2a <= opcode <= 0x2d:
                local = opcode - 0x2a
            if local is not None and local in local_origin:
                for _, following in instructions[position + 1:position + 8]:
                    if following in ARRAY_DESCRIPTOR_BY_OPCODE:
                        evidence.setdefault(local_origin[local], set()).add(
                            ARRAY_DESCRIPTOR_BY_OPCODE[following])
                        break
    return {offset: next(iter(types)) for offset, types in evidence.items()
            if len(types) == 1}


def recover_fast_accessor(extractor: ROMExtractor, info: ClassInfo,
                          method: MethodInfo,
                          cp: ConstantPoolBuilder) -> Optional[bytes]:
    """Rebuild a 5-byte getter removed by optimize_fast_accessors()."""
    if method.code or method.access_rom & (ACC_NATIVE | ACC_ABSTRACT):
        return None
    return_descriptor = method.descriptor[method.descriptor.rfind(")") + 1:]
    expected_types = {
        4: {"Z", "I"}, 5: {"C", "I"}, 6: {"F"}, 7: {"D"},
        8: {"B", "Z", "I"}, 9: {"S", "I"}, 10: {"I"}, 11: {"J"},
        12: {"L"}, 13: {"["},
    }.get(method.max_stack)
    if expected_types is None or return_descriptor[:1] not in expected_types:
        return None
    params = descriptor_parameters(method.descriptor)
    if method.access_rom & ACC_STATIC:
        if len(params) != 1 or not params[0].startswith("L"):
            return None
        owner_name = params[0][1:-1]
        owner = next((item for item in extractor.classes.values()
                      if item.name == owner_name), None)
        if owner is None:
            return None
    else:
        if params:
            return None
        owner = info
    if not owner.fields:
        extractor.parse_class(owner)
    accessor_descriptor = {
        4: "Z", 5: "C", 6: "F", 7: "D", 8: "B",
        9: "S", 10: "I", 11: "J",
    }.get(method.max_stack, return_descriptor)
    candidates = [field for field in owner.fields
                  if not (field.access & ACC_STATIC) and
                  field.offset == method.max_locals and
                  field.descriptor == accessor_descriptor]
    if candidates:
        field_info = candidates[0]
    else:
        field_info = FieldInfo(
            ACC_PRIVATE | ACC_SYNTHETIC_ROM,
            f"field{method.max_locals:04X}{descriptor_name(accessor_descriptor)}",
            accessor_descriptor,
            0,
            method.max_locals,
            True,
        )
        owner.fields.append(field_info)
    name = emitted_member_name(field_info.name, field_info.offset, "field",
                               field_info.descriptor,
                               bool(field_info.access & ACC_STATIC))
    field_index = cp.fieldref(owner.name or "unknown/Class", name,
                              field_info.descriptor)
    return_instruction = {
        "J": 0xad, "F": 0xae, "D": 0xaf,
        "L": 0xb0, "[": 0xb0,
    }.get(return_descriptor[:1], 0xac)
    return b"\x2a\xb4" + struct.pack(">H", field_index) + bytes([return_instruction])


def infer_quick_field_owners(extractor: ROMExtractor, info: ClassInfo,
                             method: MethodInfo
                             ) -> tuple[dict[int, ClassInfo], dict[int, str]]:
    """Best-effort receiver typing for quick instance-field instructions.

    A phoneME quick field operand contains an object offset, but no declaring
    class.  Treating every such access as a field of the method holder creates
    valid bytecode with the wrong Java model (Hashtable.Entry fields end up on
    Hashtable, for example).  This small abstract interpreter retains only
    reference types; unknown stack values are represented by ``None``.
    """
    owners: dict[int, ClassInfo] = {}
    value_types: dict[int, str] = {}
    locals_: list[Optional[str]] = [None] * max(1, method.max_locals)
    local = 0
    if not method.access_rom & ACC_STATIC:
        locals_[0] = f"L{info.name};"
        local = 1
    for descriptor in descriptor_parameters(method.descriptor):
        if local < len(locals_):
            locals_[local] = descriptor
        local += 2 if descriptor in {"J", "D"} else 1
    stack: list[Optional[str]] = []

    def pop() -> Optional[str]:
        return stack.pop() if stack else None

    def class_for(descriptor: Optional[str]) -> Optional[ClassInfo]:
        if not descriptor or not descriptor.startswith("L") or not descriptor.endswith(";"):
            return None
        name = descriptor[1:-1]
        if name == "java/lang/Object":
            return None
        return next((item for item in extractor.classes.values()
                     if item.name == name), None)

    def rom_entry(index: int) -> int:
        return extractor.cp_entry_from(method.constants_pointer, index)

    def target_method(index: int, direct: bool) -> Optional[MethodInfo]:
        try:
            value = rom_entry(index)
            if direct or value >= extractor.image.flash_base:
                return extractor.parse_method(value)
            owner = extractor.classes.get(value >> 16)
            slot = value & 0xffff
            if owner is None or slot >= owner.vtable_length:
                return None
            pointer = extractor.image.u32(owner.vtable_pointer + slot * 4)
            return extractor.parse_method(pointer)
        except (IndexError, ValueError):
            return None

    def invoke(target: Optional[MethodInfo], is_static: bool) -> None:
        if target is None:
            stack.clear()
            return
        for _ in descriptor_parameters(target.descriptor):
            pop()
        if not is_static:
            pop()
        result = target.descriptor[target.descriptor.rfind(")") + 1:]
        if result != "V":
            stack.append(result)

    bci = 0
    try:
        while bci < len(method.code):
            opcode = method.code[bci]
            length = bytecode_length(method.code, bci)
            if opcode == 0x01:                         # aconst_null
                stack.append(None)
            elif 0x02 <= opcode <= 0x14:              # constants / ldc
                stack.append(None)
            elif opcode in {0xcb, 0xcc}:              # fast_aldc / fast_aldc_w
                index = (method.code[bci + 1] if opcode == 0xcb else
                         int.from_bytes(method.code[bci + 1:bci + 3], "big"))
                try:
                    extractor.rom_string(rom_entry(index))
                    stack.append("Ljava/lang/String;")
                except (IndexError, ValueError, UnicodeDecodeError):
                    stack.append(None)
            elif opcode == 0xcd:                      # fast_aldc2_w
                stack.append(None)
            elif opcode == 0x19:                       # aload
                index = method.code[bci + 1]
                stack.append(locals_[index] if index < len(locals_) else None)
            elif 0x2a <= opcode <= 0x2d:              # aload_0 .. aload_3
                index = opcode - 0x2a
                stack.append(locals_[index] if index < len(locals_) else None)
            elif opcode in {0x15, 0x16, 0x17, 0x18} or 0x1a <= opcode <= 0x29:
                stack.append(None)
            elif opcode == 0x3a:                       # astore
                index = method.code[bci + 1]
                value = pop()
                if index < len(locals_):
                    locals_[index] = value
            elif 0x4b <= opcode <= 0x4e:              # astore_0 .. astore_3
                index = opcode - 0x4b
                value = pop()
                if index < len(locals_):
                    locals_[index] = value
            elif opcode in {0x36, 0x37, 0x38, 0x39} or 0x3b <= opcode <= 0x4a:
                pop()
            elif opcode == 0x57:
                pop()
            elif opcode == 0x58:
                pop(); pop()
            elif opcode == 0x59 and stack:
                stack.append(stack[-1])
            elif opcode == 0x5a and len(stack) >= 2:
                value = stack.pop(); stack.insert(len(stack) - 1, value); stack.append(value)
            elif opcode == 0x5f and len(stack) >= 2:
                stack[-1], stack[-2] = stack[-2], stack[-1]
            elif 0x2e <= opcode <= 0x35:              # xaload
                pop()
                array = pop()
                if opcode == 0x32 and array and array.startswith("["):
                    stack.append(array[1:])
                else:
                    stack.append(None)
            elif 0x4f <= opcode <= 0x56:              # xastore
                pop(); pop(); pop()
            elif opcode == 0xbe:                       # arraylength
                pop(); stack.append(None)
            elif opcode in INSTANCE_FIELD_OPS:
                normal_opcode, inferred, scale = INSTANCE_FIELD_OPS[opcode]
                operand = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                offset = operand * scale
                if normal_opcode == 0xb5:
                    value = pop()
                    receiver = pop()
                    if value:
                        value_types[bci] = value
                else:
                    receiver = pop()
                owner = class_for(receiver)
                if owner is not None:
                    owners[bci] = owner
                if normal_opcode == 0xb4:
                    field_owner = owner or info
                    known = next((field.descriptor for field in field_owner.fields
                                  if not field.access & ACC_STATIC and
                                  field.offset == offset), None)
                    stack.append(known or inferred)
            elif opcode in {0xec, 0xed}:              # getfield
                receiver = pop()
                owner = class_for(receiver)
                if owner is not None:
                    owners[bci] = owner
                offset = method.code[bci + 1] * 4
                field_owner = owner or info
                known = next((field.descriptor for field in field_owner.fields
                              if not field.access & ACC_STATIC and
                              field.offset == offset), None)
                stack.append(known or ("Ljava/lang/Object;" if opcode == 0xed else "I"))
            elif opcode in {0xee, 0xef, 0xf2, 0xf3, 0xf4, 0xf5}:
                owners[bci] = info                    # fused aload_0/getfield
                offset = (method.code[bci + 1] * 4 if opcode in {0xee, 0xef}
                          else 4 if opcode in {0xf2, 0xf3} else 8)
                known = next((field.descriptor for field in info.fields
                              if not field.access & ACC_STATIC and
                              field.offset == offset), None)
                stack.append(known or ("Ljava/lang/Object;"
                                       if opcode in {0xee, 0xf2, 0xf4} else "I"))
            elif opcode in {0xce, 0xcf, 0xd0, 0xd1, 0xd2}:
                # Quick static fields do not consume a receiver.
                if opcode in {0xce, 0xcf}:
                    stack.append(None)
                else:
                    pop()
            elif opcode in {0xbb, 0xe8}:              # new / fast_new
                index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                target = extractor.classes.get(rom_entry(index))
                stack.append(f"L{target.name};" if target and target.name else None)
            elif opcode in {0xbd, 0xe9}:              # anewarray
                pop()
                index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                target = extractor.classes.get(rom_entry(index))
                stack.append(("[" + target.name if target and target.name and
                              target.name.startswith("[") else
                              f"[L{target.name};" if target and target.name else None))
            elif opcode == 0xbc:                      # newarray
                pop()
                stack.append({4: "[Z", 5: "[C", 6: "[F", 7: "[D",
                              8: "[B", 9: "[S", 10: "[I", 11: "[J"}.get(
                                  method.code[bci + 1]))
            elif opcode in {0xc0, 0xea}:              # checkcast
                index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                target = extractor.classes.get(rom_entry(index))
                pop(); stack.append((target.name if target and target.name and target.name.startswith("[")
                                     else f"L{target.name};" if target and target.name else None))
            elif opcode in {0xc1, 0xeb}:              # instanceof
                pop(); stack.append(None)
            elif opcode in {0xe2, 0xe3, 0xe6, 0xe7, 0xb6, 0xb7, 0xb8}:
                index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                invoke(target_method(index, opcode in {0xe3, 0xe7, 0xb8}),
                       opcode in {0xe3, 0xb8})
            elif opcode == 0xe4:                      # invokeinterface
                index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                invoke(target_method(index, False), False)
            elif 0x60 <= opcode <= 0x83:              # arithmetic
                pop(); pop(); stack.append(None)
            elif 0x85 <= opcode <= 0x98:              # conversions/comparisons
                pop(); stack.append(None)
            elif 0x99 <= opcode <= 0x9e or opcode in {0xc6, 0xc7}:
                pop()
            elif 0x9f <= opcode <= 0xa6:
                pop(); pop()
            elif opcode in {0xac, 0xad, 0xae, 0xaf, 0xb0, 0xbf}:
                pop()
            elif opcode == 0xc4:                      # wide load/store
                nested = method.code[bci + 1]
                index = int.from_bytes(method.code[bci + 2:bci + 4], "big")
                if nested == 0x19:
                    stack.append(locals_[index] if index < len(locals_) else None)
                elif nested == 0x3a:
                    value = pop()
                    if index < len(locals_):
                        locals_[index] = value
                elif nested in {0x15, 0x16, 0x17, 0x18}:
                    stack.append(None)
                elif nested in {0x36, 0x37, 0x38, 0x39}:
                    pop()
            bci += length
    except (IndexError, ValueError):
        pass
    return owners, value_types


def recover_method_body(extractor: ROMExtractor, info: ClassInfo,
                        method: MethodInfo, cp: ConstantPoolBuilder,
                        reference_types: dict[int, str]
                        ) -> tuple[Optional[bytes], str, list[tuple[int, int, int, int]]]:
    """Recover a body using only information present in the ROM image.

    This intentionally errs on the conservative side.  Branch offsets and
    switch padding stay exact: supported quick bytecodes have the same length
    as their class-file replacements.
    """
    if not method.code:
        accessor = recover_fast_accessor(extractor, info, method, cp)
        if accessor is not None:
            return accessor, "restored ROM fast field accessor", []
        return None, "empty ROM body", []

    quick_field_owners, quick_field_value_types = infer_quick_field_owners(
        extractor, info, method)

    def rom_entry(index: int) -> int:
        return extractor.cp_entry_from(method.constants_pointer, index)
    def fieldref(byte_offset: int, inferred_descriptor: str,
                 bci: int) -> int:
        owner = quick_field_owners.get(bci, info)
        # A receiver's static type may be an interface, but an instance-field
        # quick opcode necessarily addresses storage in the concrete class.
        if owner.access_rom & ACC_INTERFACE:
            owner = info
        value_descriptor = quick_field_value_types.get(bci)
        if (inferred_descriptor == "Ljava/lang/Object;" and value_descriptor and
                (value_descriptor.startswith("L") or value_descriptor.startswith("["))):
            inferred_descriptor = value_descriptor
        elif inferred_descriptor == "B" and value_descriptor == "Z":
            inferred_descriptor = "Z"
        if inferred_descriptor == "Ljava/lang/Object;":
            inferred_descriptor = (direct_field_descriptor(bci) or
                                   inferred_descriptor)
        if inferred_descriptor == "Ljava/lang/Object;" and owner is info:
            inferred_descriptor = reference_types.get(byte_offset, inferred_descriptor)
        if not owner.fields:
            extractor.parse_class(owner)
        candidates = [field for field in owner.fields
                      if not (field.access & ACC_STATIC) and
                      field.offset == byte_offset]
        field_info = next((field for field in candidates
                           if _descriptor_matches(field.descriptor,
                                                  inferred_descriptor)), None)
        if field_info is None:
            field_info = FieldInfo(
                ACC_PRIVATE | ACC_SYNTHETIC_ROM,
                f"field{byte_offset:04X}{descriptor_name(inferred_descriptor)}",
                inferred_descriptor,
                0,
                byte_offset,
                True,
            )
            owner.fields.append(field_info)
        field_name = emitted_member_name(field_info.name, field_info.offset,
                                         "field", field_info.descriptor,
                                         bool(field_info.access & ACC_STATIC))
        return cp.fieldref(owner.name or "unknown/Class", field_name,
                           field_info.descriptor)

    def static_fieldref(rom_cp_index: int, inferred_descriptor: str) -> int:
        value = rom_entry(rom_cp_index)
        byte_offset = value >> 16
        class_id = value & 0xffff
        owner = extractor.classes.get(class_id)
        if owner is None or owner.name is None or owner.name.startswith("["):
            raise ValueError(f"static field owner class {class_id} is unavailable")
        if not owner.fields:
            extractor.parse_class(owner)
        candidates = [field for field in owner.fields
                      if field.access & ACC_STATIC and field.offset == byte_offset]
        field_info = next((field for field in candidates
                           if not field.synthetic_name), None)
        if field_info is None:
            field_info = next((field for field in candidates
                               if _descriptor_matches(field.descriptor,
                                                      inferred_descriptor)), None)
        if field_info is None:
            field_info = FieldInfo(
                ACC_PRIVATE | ACC_STATIC | ACC_SYNTHETIC_ROM,
                f"staticField{byte_offset:04X}{descriptor_name(inferred_descriptor)}",
                inferred_descriptor,
                0,
                byte_offset,
                True,
            )
            owner.fields.append(field_info)
        field_name = emitted_member_name(field_info.name, field_info.offset,
                                         "field", field_info.descriptor,
                                         bool(field_info.access & ACC_STATIC))
        return cp.fieldref(owner.name, field_name, field_info.descriptor)

    def resolved_instance_fieldref(rom_cp_index: int, bci: int,
                                   is_get: bool) -> int:
        value = rom_entry(rom_cp_index)
        byte_offset = value >> 16
        class_id = value & 0xffff
        owner = extractor.classes.get(class_id)
        if owner is None or owner.name is None:
            raise ValueError(f"instance field owner class {class_id} is unavailable")
        if not owner.fields:
            extractor.parse_class(owner)
        candidates = [field for field in owner.fields
                      if not (field.access & ACC_STATIC) and field.offset == byte_offset]
        inferred = direct_field_descriptor(bci) if is_get else None
        field_info = (next((field for field in candidates
                            if inferred and
                            _descriptor_matches(field.descriptor, inferred)), None)
                      or next((field for field in candidates
                               if not field.synthetic_name), None))
        if field_info is None and inferred:
            field_info = FieldInfo(
                ACC_PRIVATE | ACC_SYNTHETIC_ROM,
                f"field{byte_offset:04X}{descriptor_name(inferred)}",
                inferred, 0, byte_offset, True)
            owner.fields.append(field_info)
        if field_info is None:
            raise ValueError(f"instance field class={class_id} offset={byte_offset} is unavailable")
        name = emitted_member_name(field_info.name, field_info.offset, "field",
                                   field_info.descriptor,
                                   bool(field_info.access & ACC_STATIC))
        return cp.fieldref(owner.name, name, field_info.descriptor)

    def classref(rom_cp_index: int) -> int:
        class_id = rom_entry(rom_cp_index)
        target = extractor.classes.get(class_id)
        if target is None or target.name is None:
            raise ValueError(f"class constant {class_id} is unavailable")
        return cp.klass(target.name)

    def resolved_method(rom_cp_index: int, direct: bool) -> MethodInfo:
        value = rom_entry(rom_cp_index)
        if direct or value >= extractor.image.flash_base:
            pointer = value
        else:
            class_id = value >> 16
            vtable_index = value & 0xffff
            owner = extractor.classes.get(class_id)
            if owner is None or vtable_index >= owner.vtable_length:
                raise ValueError(f"invalid vtable reference class={class_id} slot={vtable_index}")
            pointer = extractor.image.u32(owner.vtable_pointer + vtable_index * 4)
        target = extractor.parse_method(pointer)
        owner = extractor.classes.get(target.holder_id)
        if owner is not None:
            if not owner.methods:
                extractor.parse_class(owner)
            canonical = next((item for item in owner.methods
                              if item.address == target.address), None)
            if canonical is None:
                # ROMizer may remove non-reflective direct methods (most
                # visibly private constructors) from the retained method
                # table.  A bytecode reference proves that the method exists;
                # emit it in its owner so decompilers and linkers see a
                # self-consistent class set.
                owner.methods.append(target)
            else:
                target = canonical
        return target

    def direct_field_descriptor(start_bci: int) -> Optional[str]:
        """Infer a quick field type from its immediate stack consumers.

        ROMizer erases reference field types. Preserve the field value's
        origin through array loads and argument setup until a typed operation
        constrains it. This also recovers multidimensional arrays.
        """
        marker: tuple[str, int] = ("field", 0)
        stack: list[Optional[tuple[str, int]]] = [marker]
        locals_: dict[int, Optional[tuple[str, int]]] = {}
        best: Optional[str] = None

        def pop() -> Optional[tuple[str, int]]:
            return stack.pop() if stack else None

        def constrained(item: Optional[tuple[str, int]],
                        descriptor: str) -> Optional[str]:
            if item is None:
                return None
            return "[" * item[1] + descriptor

        cursor = start_bci + bytecode_length(method.code, start_bci)
        for _ in range(32):
            if cursor >= len(method.code):
                break
            opcode = method.code[cursor]
            length = bytecode_length(method.code, cursor)

            if opcode == 0x01 or 0x02 <= opcode <= 0x14 or opcode in {
                    0xcb, 0xcc, 0xcd, 0xbb, 0xe8}:
                stack.append(None)
            elif opcode in {0x15, 0x16, 0x17, 0x18, 0x19}:
                index = method.code[cursor + 1]
                stack.append(locals_.get(index))
            elif 0x1a <= opcode <= 0x2d:
                index = ((opcode - 0x1a) & 3)
                stack.append(locals_.get(index))
            elif opcode in {0x36, 0x37, 0x38, 0x39, 0x3a}:
                locals_[method.code[cursor + 1]] = pop()
            elif 0x3b <= opcode <= 0x4e:
                locals_[(opcode - 0x3b) & 3] = pop()
            elif opcode == 0x57:
                if pop() is not None:
                    break
            elif opcode == 0x58:
                if pop() is not None or pop() is not None:
                    break
            elif opcode == 0x59 and stack:
                stack.append(stack[-1])
            elif opcode in ARRAY_DESCRIPTOR_BY_OPCODE:
                pop()  # index or value
                if opcode >= 0x4f:
                    pop()  # index
                item = pop()
                descriptor = constrained(
                    item, ARRAY_DESCRIPTOR_BY_OPCODE[opcode])
                if descriptor is not None:
                    best = descriptor
                if opcode == 0x32 and item is not None:
                    stack.append((item[0], item[1] + 1))
                elif opcode < 0x36:
                    stack.append(None)
            elif opcode == 0xbe:
                item = pop()
                descriptor = constrained(item, "[Ljava/lang/Object;")
                if descriptor is not None:
                    best = descriptor
                stack.append(None)
            elif opcode in {0xc0, 0xea}:
                item = pop()
                index = int.from_bytes(method.code[cursor + 1:cursor + 3], "big")
                class_id = rom_entry(index)
                target = extractor.classes.get(class_id)
                name = (target.name if target and target.name else
                        CORE_ARRAY_BY_CLASS_ID.get(class_id))
                if name:
                    expected = name if name.startswith("[") else f"L{name};"
                    descriptor = constrained(item, expected)
                    if descriptor is not None:
                        return descriptor
                stack.append(item)
            elif opcode in {0xe2, 0xe3, 0xe6, 0xe7,
                            0xb6, 0xb7, 0xb8}:
                index = int.from_bytes(method.code[cursor + 1:cursor + 3], "big")
                target = resolved_method(index, direct=(opcode == 0xe3))
                for expected in reversed(descriptor_parameters(target.descriptor)):
                    descriptor = constrained(pop(), expected)
                    if descriptor is not None:
                        return descriptor
                if opcode not in {0xe3, 0xb8}:
                    receiver = pop()
                    owner = extractor.classes.get(target.holder_id)
                    if owner and owner.name:
                        descriptor = constrained(receiver, f"L{owner.name};")
                        if descriptor is not None:
                            return descriptor
                result = target.descriptor[target.descriptor.rfind(")") + 1:]
                if result != "V":
                    stack.append(None)
            elif opcode == 0xe4:
                index = int.from_bytes(method.code[cursor + 1:cursor + 3], "big")
                target = resolved_method(index, direct=False)
                for expected in reversed(descriptor_parameters(target.descriptor)):
                    descriptor = constrained(pop(), expected)
                    if descriptor is not None:
                        return descriptor
                receiver = pop()
                owner = extractor.classes.get(target.holder_id)
                if owner and owner.name:
                    descriptor = constrained(receiver, f"L{owner.name};")
                    if descriptor is not None:
                        return descriptor
                result = target.descriptor[target.descriptor.rfind(")") + 1:]
                if result != "V":
                    stack.append(None)
            elif opcode in {0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
                            0xc6, 0xc7}:
                if pop() is not None:
                    break
            elif 0x9f <= opcode <= 0xa6:
                if pop() is not None or pop() is not None:
                    break
            elif opcode in {0xac, 0xad, 0xae, 0xaf, 0xb0}:
                item = pop()
                if item is not None:
                    result = method.descriptor[method.descriptor.rfind(")") + 1:]
                    return constrained(item, result)
                break
            elif opcode in {0xaa, 0xab, 0xa7, 0xa8, 0xc8, 0xc9, 0xbf}:
                break
            cursor += length
        return best

    def methodref(target: MethodInfo) -> int:
        owner = extractor.classes.get(target.holder_id)
        if owner is None or owner.name is None:
            raise ValueError(f"method holder class {target.holder_id} is unavailable")
        name = emitted_member_name(target.name, target.address, "method")
        return cp.methodref(owner.name, name, target.descriptor)

    def ensure_constructor(owner_name: str, descriptor: str,
                           template: Optional[MethodInfo] = None) -> None:
        owner = next((item for item in extractor.classes.values()
                      if item.name == owner_name), None)
        if owner is None:
            raise ValueError(f"constructor owner {owner_name} is unavailable")
        if not owner.methods:
            extractor.parse_class(owner)
        if any(item.name == "<init>" and item.descriptor == descriptor
               for item in owner.methods):
            return
        if template is not None:
            constructor = replace(template, holder_id=owner.class_id)
        else:
            constructor = MethodInfo(
                address=owner.info_physical,
                access_rom=0,
                holder_id=owner.class_id,
                max_stack=1,
                max_locals=1,
                attributes=0,
                name="<init>",
                descriptor=descriptor,
                constants_pointer=owner.constants_pointer,
                code=b"",
                exception_table_pointer=None,
            )
        owner.methods.append(constructor)

    def kind_from_descriptor(descriptor: str, two_word: bool) -> Optional[str]:
        if two_word:
            return {"J": "long", "D": "double"}.get(descriptor)
        if descriptor == "F":
            return "float"
        if descriptor in {"B", "C", "I", "S", "Z"}:
            return "int"
        return None

    def infer_constant_kind(bci: int, two_word: bool) -> Optional[str]:
        kind = infer_numeric_ldc_kind(method.code, bci, two_word)
        if kind is not None:
            return kind
        # The no-stack-tags VM merges numeric ldc opcodes, but resolved method
        # signatures survive.  A constant consumed immediately by a call is
        # the call's last argument and therefore has an exact retained type.
        next_bci = bci + bytecode_length(method.code, bci)
        if next_bci >= len(method.code):
            return None
        next_opcode = method.code[next_bci]
        if next_opcode in {0xe2, 0xe3, 0xe6, 0xe7, 0xb6, 0xb7, 0xb8}:
            rom_cp_index = int.from_bytes(
                method.code[next_bci + 1:next_bci + 3], "big")
            target = resolved_method(
                rom_cp_index, direct=(next_opcode in {0xe3, 0xb8}))
            params = descriptor_parameters(target.descriptor)
            if params:
                return kind_from_descriptor(params[-1], two_word)
        return None

    def static_descriptor(bci: int, is_put: bool) -> str:
        """Recover the erased type of an unquickened static field access."""
        if not is_put:
            wide = infer_numeric_ldc_kind(method.code, bci, two_word=True)
            if wide == "long":
                return "J"
            if wide == "double":
                return "D"
            narrow = infer_numeric_ldc_kind(method.code, bci, two_word=False)
            if narrow == "float":
                return "F"
            return "I"

        previous = instructions[-1][2] if instructions else -1
        if previous in ({0x09, 0x0a, 0x16, 0x1e, 0x1f, 0x20, 0x21,
                         0x2f, 0x61, 0x65, 0x69, 0x6d, 0x71, 0x75,
                         0x79, 0x7b, 0x7d, 0x7f, 0x81, 0x83, 0x85,
                         0x8c, 0x8f, 0x94}):
            return "J"
        if previous in ({0x0e, 0x0f, 0x18, 0x26, 0x27, 0x28, 0x29,
                         0x31, 0x63, 0x67, 0x6b, 0x6f, 0x73, 0x77,
                         0x87, 0x8a, 0x8d, 0x97, 0x98}):
            return "D"
        if previous in ({0x0b, 0x0c, 0x0d, 0x17, 0x22, 0x23, 0x24,
                         0x25, 0x30, 0x62, 0x66, 0x6a, 0x6e, 0x72,
                         0x76, 0x86, 0x8b, 0x90, 0x95, 0x96}):
            return "F"
        if previous in ({0x01, 0x19, 0x2a, 0x2b, 0x2c, 0x2d, 0x32,
                         0xbb, 0xbd, 0xc0, 0xe8, 0xe9, 0xea}):
            return "Ljava/lang/Object;"
        return "I"

    # (old bci, new bci, opcode, old length, initial replacement)
    instructions: list[tuple[int, int, int, int, bytes]] = []
    old_to_new: dict[int, int] = {}
    bci = 0
    new_bci = 0
    dequickened_ops = 0
    last_new_owner: Optional[str] = None
    try:
        while bci < len(method.code):
            opcode = method.code[bci]
            length = bytecode_length(method.code, bci)
            if length <= 0 or bci + length > len(method.code):
                raise ValueError("instruction extends beyond method")
            replacement = method.code[bci:bci + length]
            if (opcode == 0x04 and bci + 1 < len(method.code) and
                    method.code[bci + 1] == 0x79):
                # Fernflower incorrectly widens the iconst shift count in
                # some old CLDC loop shapes and then casts Integer to Long
                # while rendering. Multiplication by two has the same JVM
                # two's-complement result as `lshl 1`.
                cp_index = cp.wide_bits(2, is_double=False)
                replacement = b"\x14" + struct.pack(">H", cp_index)
            elif (opcode == 0x79 and bci > 0 and
                  method.code[bci - 1] == 0x04):
                replacement = b"\x69"  # lmul
            elif opcode in {0xcb, 0xcc}:
                rom_cp_index = (method.code[bci + 1] if opcode == 0xcb else
                                int.from_bytes(method.code[bci + 1:bci + 3], "big"))
                value = rom_entry(rom_cp_index)
                try:
                    cp_index = cp.string(extractor.rom_string(value))
                except (ValueError, UnicodeDecodeError):
                    kind = infer_constant_kind(bci, two_word=False)
                    if kind is None:
                        kind = infer_numeric_bits_kind(value, two_word=False)
                    if kind == "float":
                        cp_index = cp.float_bits(value)
                    elif kind == "int":
                        cp_index = cp.integer_bits(value)
                    else:
                        raise ValueError(
                            f"cannot distinguish int/float ldc at bci {bci} cp {rom_cp_index}")
                replacement = (bytes([0x12, cp_index]) if cp_index <= 0xff
                               else b"\x13" + struct.pack(">H", cp_index))
                dequickened_ops += 1
            elif opcode == 0xcd:
                rom_cp_index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                low = rom_entry(rom_cp_index)
                high = rom_entry(rom_cp_index + 1)
                value = low | (high << 32)
                kind = infer_constant_kind(bci, two_word=True)
                if kind is None:
                    kind = infer_numeric_bits_kind(value, two_word=True)
                if kind not in {"long", "double"}:
                    raise ValueError(
                        f"cannot distinguish long/double ldc at bci {bci} cp {rom_cp_index}")
                cp_index = cp.wide_bits(value, is_double=(kind == "double"))
                replacement = b"\x14" + struct.pack(">H", cp_index)
                dequickened_ops += 1
            elif opcode in INSTANCE_FIELD_OPS:
                normal_opcode, inferred_descriptor, scale = INSTANCE_FIELD_OPS[opcode]
                operand = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                byte_offset = operand * scale
                cp_index = fieldref(byte_offset, inferred_descriptor, bci)
                replacement = bytes([normal_opcode]) + struct.pack(">H", cp_index)
                dequickened_ops += 1
            elif opcode in {0xec, 0xed}:             # fast_{i,a}getfield_1
                descriptor = "I" if opcode == 0xec else "Ljava/lang/Object;"
                cp_index = fieldref(method.code[bci + 1] * 4, descriptor, bci)
                replacement = b"\xb4" + struct.pack(">H", cp_index)
                dequickened_ops += 1
            elif opcode in {0xee, 0xef}:             # aload_0 + fast getfield_1
                descriptor = "Ljava/lang/Object;" if opcode == 0xee else "I"
                cp_index = fieldref(method.code[bci + 1] * 4, descriptor, bci)
                replacement = b"\x2a\xb4" + struct.pack(">H", cp_index)
                dequickened_ops += 1
            elif opcode in {0xf2, 0xf3, 0xf4, 0xf5}: # fixed offset 4/8 forms
                descriptor = "Ljava/lang/Object;" if opcode in {0xf2, 0xf4} else "I"
                byte_offset = 4 if opcode in {0xf2, 0xf3} else 8
                cp_index = fieldref(byte_offset, descriptor, bci)
                replacement = b"\x2a\xb4" + struct.pack(">H", cp_index)
                dequickened_ops += 1
            elif opcode == 0xf0:
                if last_new_owner is not None:
                    # ROMizer replaces an empty constructor call following
                    # `new; dup` with its null-check pseudo instruction.
                    ensure_constructor(last_new_owner, "()V")
                    cp_index = cp.methodref(last_new_owner, "<init>", "()V")
                    replacement = b"\xb7" + struct.pack(">H", cp_index)
                    last_new_owner = None
                elif method.name == "<init>":
                    # ROMizer collapses an empty superclass constructor call
                    # to aload_0; pop_and_npe_if_null. Restore the verifier's
                    # required initialization transition.
                    super_info = extractor.superclass(info)
                    if super_info is None or super_info.name is None:
                        raise ValueError("constructor superclass is unavailable")
                    cp_index = cp.methodref(super_info.name, "<init>", "()V")
                    replacement = b"\xb7" + struct.pack(">H", cp_index)
                else:
                    # Net stack effect is pop, but null must still throw.
                    cp_index = cp.methodref("java/lang/Object", "getClass",
                                            "()Ljava/lang/Class;")
                    replacement = b"\xb6" + struct.pack(">H", cp_index) + b"\x57"
                dequickened_ops += 1
            elif opcode in {0xce, 0xcf, 0xd0, 0xd1, 0xd2,
                            0xf6, 0xf7, 0xf8, 0xf9, 0xfa}:
                rom_cp_index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                descriptor = ("Ljava/lang/Object;" if opcode in {0xd0, 0xf8}
                              else "J" if opcode in {0xcf, 0xd2, 0xf7, 0xfa}
                              else "I")
                cp_index = static_fieldref(rom_cp_index, descriptor)
                normal_opcode = 0xb3 if opcode in {0xce, 0xcf, 0xd0, 0xf6, 0xf7, 0xf8} else 0xb2
                replacement = bytes([normal_opcode]) + struct.pack(">H", cp_index)
                dequickened_ops += 1
            elif opcode in {0xe8, 0xe9, 0xea, 0xeb}:
                rom_cp_index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                class_id = rom_entry(rom_cp_index)
                target = extractor.classes.get(class_id)
                if target is None or target.name is None:
                    raise ValueError(f"class constant {class_id} is unavailable")
                target_name = target.name
                cp_index = cp.klass(target_name)
                normal_opcode = {0xe8: 0xbb, 0xe9: 0xbd, 0xea: 0xc0, 0xeb: 0xc1}[opcode]
                replacement = bytes([normal_opcode]) + struct.pack(">H", cp_index)
                if opcode == 0xe8:
                    last_new_owner = target_name
                dequickened_ops += 1
            elif opcode in {0xe2, 0xe3, 0xe6, 0xe7}:
                rom_cp_index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                target = resolved_method(rom_cp_index, direct=(opcode == 0xe3))
                if target.name == "<init>" and last_new_owner is not None:
                    # Direct constructor bodies are shared/deduplicated by the
                    # ROMizer.  Re-materialize the referenced signature in the
                    # class instantiated by the preceding `new`.
                    ensure_constructor(last_new_owner, target.descriptor, target)
                    cp_index = cp.methodref(last_new_owner, "<init>", target.descriptor)
                    last_new_owner = None
                else:
                    cp_index = methodref(target)
                if opcode == 0xe3:
                    normal_opcode = 0xb8
                elif opcode == 0xe7 or target.name == "<init>":
                    normal_opcode = 0xb7
                else:
                    normal_opcode = 0xb6
                replacement = bytes([normal_opcode]) + struct.pack(">H", cp_index)
                dequickened_ops += 1
            elif opcode == 0xe4:
                rom_cp_index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                value = rom_entry(rom_cp_index)
                interface_id = value >> 16
                method_index = value & 0xffff
                interface = extractor.classes.get(interface_id)
                if interface is None or interface.name is None or not (
                        interface.access_rom & ACC_INTERFACE):
                    raise ValueError(f"invalid interface method reference 0x{value:08x}")
                if not interface.methods:
                    extractor.parse_class(interface)
                if method_index >= len(interface.methods):
                    raise ValueError(f"interface method index {method_index} is unavailable")
                target = interface.methods[method_index]
                target_name = emitted_member_name(target.name, target.address, "method")
                cp_index = cp.methodref(interface.name, target_name,
                                        target.descriptor, interface=True)
                # The verifier uses this count; ROM quickening preserves it.
                replacement = b"\xb9" + struct.pack(">H", cp_index) + method.code[bci + 3:bci + 5]
                dequickened_ops += 1
            elif opcode in {0x12, 0x13}:
                rom_cp_index = (method.code[bci + 1] if opcode == 0x12 else
                                int.from_bytes(method.code[bci + 1:bci + 3], "big"))
                value = rom_entry(rom_cp_index)
                try:
                    cp_index = cp.string(extractor.rom_string(value))
                except (ValueError, UnicodeDecodeError):
                    kind = infer_constant_kind(bci, two_word=False)
                    if kind is None:
                        kind = infer_numeric_bits_kind(value, two_word=False)
                    if kind == "float":
                        cp_index = cp.float_bits(value)
                    elif kind == "int":
                        cp_index = cp.integer_bits(value)
                    else:
                        raise ValueError(
                            f"cannot distinguish int/float ldc at bci {bci} cp {rom_cp_index}")
                replacement = (bytes([0x12, cp_index]) if cp_index <= 0xff
                               else b"\x13" + struct.pack(">H", cp_index))
            elif opcode == 0x14:
                rom_cp_index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                value = rom_entry(rom_cp_index) | (rom_entry(rom_cp_index + 1) << 32)
                kind = infer_constant_kind(bci, two_word=True)
                if kind is None:
                    kind = infer_numeric_bits_kind(value, two_word=True)
                if kind not in {"long", "double"}:
                    raise ValueError(
                        f"cannot distinguish long/double ldc at bci {bci} cp {rom_cp_index}")
                cp_index = cp.wide_bits(value, is_double=(kind == "double"))
                replacement = b"\x14" + struct.pack(">H", cp_index)
            elif opcode in {0xb2, 0xb3}:
                rom_cp_index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                cp_index = static_fieldref(
                    rom_cp_index, static_descriptor(bci, opcode == 0xb3))
                replacement = bytes([opcode]) + struct.pack(">H", cp_index)
            elif opcode in {0xb4, 0xb5}:
                rom_cp_index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                cp_index = resolved_instance_fieldref(
                    rom_cp_index, bci, opcode == 0xb4)
                replacement = bytes([opcode]) + struct.pack(">H", cp_index)
            elif opcode in {0xbb, 0xbd, 0xc0, 0xc1}:
                rom_cp_index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                class_id = rom_entry(rom_cp_index)
                target = extractor.classes.get(class_id)
                if target is None or target.name is None:
                    raise ValueError(f"class constant {class_id} is unavailable")
                cp_index = cp.klass(target.name)
                replacement = bytes([opcode]) + struct.pack(">H", cp_index)
                if opcode == 0xbb:
                    last_new_owner = target.name
            elif opcode == 0xc5:
                rom_cp_index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                cp_index = classref(rom_cp_index)
                replacement = bytes([opcode]) + struct.pack(">H", cp_index) + method.code[bci + 3:bci + 4]
            elif opcode in {0xb6, 0xb7, 0xb8}:
                rom_cp_index = int.from_bytes(method.code[bci + 1:bci + 3], "big")
                target = resolved_method(rom_cp_index, direct=(opcode == 0xb8))
                cp_index = methodref(target)
                replacement = bytes([opcode]) + struct.pack(">H", cp_index)
            elif opcode >= 0xcb:
                return None, f"private phoneME opcode 0x{opcode:02x} at bci {bci}", []
            elif opcode in JVM_CP_OPCODES:
                return None, f"ROM constant-pool operand at bci {bci}", []
            # Switch padding depends on its new address and is rebuilt below.
            if opcode in {0xaa, 0xab}:
                old_aligned = (bci + 4) & ~3
                payload = len(replacement) - (old_aligned - bci)
                new_aligned = (new_bci + 4) & ~3
                replacement = bytes(new_aligned - new_bci) + bytes(payload)
            old_to_new[bci] = new_bci
            instructions.append((bci, new_bci, opcode, length, replacement))
            bci += length
            new_bci += len(replacement)
        old_to_new[len(method.code)] = new_bci
    except ValueError as error:
        return None, f"invalid/unsupported bytecode: {error}", []

    def relocated(old_origin: int, new_origin: int, delta: int) -> int:
        target = old_origin + delta
        if target not in old_to_new:
            raise ValueError(f"branch target {target} is not an instruction boundary")
        return old_to_new[target] - new_origin

    result = bytearray()
    try:
        for old_pos, new_pos, opcode, length, replacement in instructions:
            if 0x99 <= opcode <= 0xa8 or opcode in {0xc6, 0xc7}:
                delta = int.from_bytes(method.code[old_pos + 1:old_pos + 3], "big", signed=True)
                replacement = bytes([opcode]) + struct.pack(">h", relocated(old_pos, new_pos, delta))
            elif opcode in {0xc8, 0xc9}:
                delta = int.from_bytes(method.code[old_pos + 1:old_pos + 5], "big", signed=True)
                replacement = bytes([opcode]) + struct.pack(">i", relocated(old_pos, new_pos, delta))
            elif opcode in {0xaa, 0xab}:
                old_aligned = (old_pos + 4) & ~3
                new_aligned = (new_pos + 4) & ~3
                rebuilt = bytearray([opcode])
                rebuilt += bytes(new_aligned - new_pos - 1)
                default = int.from_bytes(method.code[old_aligned:old_aligned + 4], "big", signed=True)
                rebuilt += struct.pack(">i", relocated(old_pos, new_pos, default))
                if opcode == 0xaa:
                    low = int.from_bytes(method.code[old_aligned + 4:old_aligned + 8], "big", signed=True)
                    high = int.from_bytes(method.code[old_aligned + 8:old_aligned + 12], "big", signed=True)
                    rebuilt += struct.pack(">ii", low, high)
                    cursor = old_aligned + 12
                    for _ in range(high - low + 1):
                        delta = int.from_bytes(method.code[cursor:cursor + 4], "big", signed=True)
                        rebuilt += struct.pack(">i", relocated(old_pos, new_pos, delta))
                        cursor += 4
                else:
                    pairs = int.from_bytes(method.code[old_aligned + 4:old_aligned + 8], "big", signed=True)
                    rebuilt += struct.pack(">i", pairs)
                    cursor = old_aligned + 8
                    for _ in range(pairs):
                        match = method.code[cursor:cursor + 4]
                        delta = int.from_bytes(method.code[cursor + 4:cursor + 8], "big", signed=True)
                        rebuilt += match + struct.pack(">i", relocated(old_pos, new_pos, delta))
                        cursor += 8
                replacement = bytes(rebuilt)
            result += replacement
    except (ValueError, struct.error) as error:
        return None, f"relocation failed: {error}", []

    exception_rows: list[tuple[int, int, int, int]] = []
    if method.exception_table_pointer is not None:
        try:
            table_layouts: list[tuple[int, int]] = []
            pointer = method.exception_table_pointer
            for length_address, data_address in ((pointer, pointer + 4),
                                                 (pointer + 4, pointer + 8)):
                length = extractor.image.u32(length_address)
                if length <= 65535 and length % 4 == 0:
                    values = [extractor.image.u16(data_address + i * 2)
                              for i in range(length)]
                    if all(values[i] <= len(method.code) and
                           values[i + 1] <= len(method.code) and
                           values[i + 2] < len(method.code)
                           for i in range(0, length, 4)):
                        catches_valid = True
                        for i in range(0, length, 4):
                            catch_rom_index = values[i + 3]
                            if catch_rom_index:
                                try:
                                    catch_class_id = rom_entry(catch_rom_index)
                                except ValueError:
                                    catches_valid = False
                                    break
                                catch_class = extractor.classes.get(catch_class_id)
                                if catch_class is None or catch_class.name is None:
                                    catches_valid = False
                                    break
                        if catches_valid:
                            table_layouts.append((length, data_address))
            if not table_layouts:
                raise ValueError("no valid ROM TypeArray layout")
            table_length, table_data = max(table_layouts, key=lambda item: item[0])
            for index in range(0, table_length, 4):
                start = extractor.image.u16(table_data + (index + 0) * 2)
                end = extractor.image.u16(table_data + (index + 1) * 2)
                handler = extractor.image.u16(table_data + (index + 2) * 2)
                catch_rom_index = extractor.image.u16(table_data + (index + 3) * 2)
                if start not in old_to_new or end not in old_to_new or handler not in old_to_new:
                    raise ValueError("exception boundary is not an instruction boundary")
                if catch_rom_index:
                    catch_class_id = rom_entry(catch_rom_index)
                    catch_class = extractor.classes.get(catch_class_id)
                    if catch_class is None or catch_class.name is None:
                        raise ValueError(f"catch class {catch_class_id} is unavailable")
                    catch_index = cp.klass(catch_class.name)
                else:
                    catch_index = 0
                exception_rows.append((old_to_new[start], old_to_new[end],
                                       old_to_new[handler], catch_index))
        except ValueError as error:
            return None, f"exception table reconstruction failed: {error}", []
    if dequickened_ops:
        return bytes(result), f"dequickened {dequickened_ops} opcode(s)", exception_rows
    return bytes(result), "verbatim JVM bytecode", exception_rows


def field_constant_index(extractor: ROMExtractor, info: ClassInfo,
                         item: FieldInfo,
                         cp: ConstantPoolBuilder) -> Optional[int]:
    """Recover a ConstantValue entry, falling back to a legal zero value."""
    if not (item.access & ACC_STATIC and item.access & ACC_FINAL):
        return None
    descriptor = item.descriptor
    if descriptor not in {"Z", "B", "C", "S", "I", "J", "F", "D",
                          "Ljava/lang/String;"}:
        return None
    try:
        value = extractor.cp_entry_from(info.constants_pointer,
                                        item.initial_index)
        if descriptor in {"Z", "B", "C", "S", "I"}:
            return cp.integer_bits(value)
        if descriptor == "F":
            return cp.float_bits(value)
        if descriptor in {"J", "D"}:
            high = extractor.cp_entry_from(info.constants_pointer,
                                           item.initial_index + 1)
            bits = value | high << 32
            return cp.wide_bits(bits, is_double=(descriptor == "D"))
        return cp.string(extractor.rom_string(value))
    except (IndexError, ValueError, UnicodeDecodeError):
        if descriptor in {"Z", "B", "C", "S", "I"}:
            return cp.integer_bits(0)
        if descriptor == "F":
            return cp.float_bits(0)
        if descriptor in {"J", "D"}:
            return cp.wide_bits(0, is_double=(descriptor == "D"))
        return cp.string("")


def build_stub_class(extractor: ROMExtractor, info: ClassInfo,
                     recover_bodies: bool = False) -> tuple[bytes, int, dict[int, str]]:
    if info.name is None or info.name.startswith("["):
        raise ValueError("only ordinary instance classes can be emitted")
    cp = ConstantPoolBuilder()
    this_class = cp.klass(info.name)
    super_info = extractor.superclass(info)
    super_class = cp.klass(super_info.name) if super_info and super_info.name else 0
    interface_names = [
        extractor.classes[class_id].name
        if class_id in extractor.classes and extractor.classes[class_id].name
        else f"unknown/Interface{class_id}"
        for class_id in info.interface_ids
    ]
    interface_indices = [cp.klass(name) for name in interface_names]

    method_models = []
    recovered_count = 0
    statuses: dict[int, str] = {}
    reference_types = infer_reference_field_descriptors(info)
    for item in info.methods:
        access = clean_method_access(item.access_rom)
        if item.name in {"<init>", "<clinit>"}:
            access &= ~ACC_STRICT
        if item.name == "<clinit>":
            access &= ~(ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED)
        emitted_name = emitted_member_name(item.name, item.address, "method")
        name_index = cp.utf8(emitted_name)
        descriptor_index = cp.utf8(item.descriptor)
        if access & (ACC_NATIVE | ACC_ABSTRACT):
            attributes = b""
            attribute_count = 0
            statuses[item.address] = "native/abstract"
        else:
            recovered, status, exception_rows = (
                recover_method_body(extractor, info, item, cp, reference_types)
                if recover_bodies else (None, "recovery disabled", []))
            if recovered is not None:
                code = recovered
            elif item.name == "<init>":
                # A constructor must not return with an uninitialized `this`.
                # Throwing is verifier-safe and makes an unrecovered body loud.
                code = b"\x01\xbf"  # aconst_null; athrow
            else:
                code = return_opcode(item.descriptor)
            if recovered is not None:
                recovered_count += 1
            statuses[item.address] = status if recovered is not None else f"stub: {status}"
            code_name = cp.utf8("Code")
            exception_bytes = b"".join(struct.pack(">HHHH", *row)
                                       for row in exception_rows)
            body = (struct.pack(">HHI", max(2, item.max_stack),
                                max(1, item.max_locals), len(code)) + code +
                    struct.pack(">H", len(exception_rows)) + exception_bytes +
                    struct.pack(">H", 0))
            attributes = struct.pack(">HI", code_name, len(body)) + body
            attribute_count = 1
        method_models.append((access, name_index, descriptor_index, attribute_count, attributes))

    # Body recovery may discover fields that ROMizer removed from the retained
    # reflection table.  Emit them after processing methods.
    field_rows = []
    for item in info.fields:
        emitted_name = emitted_member_name(item.name, item.offset, "field",
                                           item.descriptor,
                                           bool(item.access & ACC_STATIC))
        constant_index = field_constant_index(extractor, info, item, cp)
        if (constant_index is None and info.access_rom & ACC_INTERFACE and
                item.descriptor in {"Z", "B", "C", "S", "I", "J", "F", "D"}):
            if item.descriptor in {"J", "D"}:
                constant_index = cp.wide_bits(0, is_double=item.descriptor == "D")
            elif item.descriptor == "F":
                constant_index = cp.float_bits(0)
            else:
                constant_index = cp.integer_bits(0)
        if constant_index is None:
            attributes = b""
            attribute_count = 0
        else:
            attribute_name = cp.utf8("ConstantValue")
            attributes = struct.pack(">HIH", attribute_name, 2,
                                     constant_index)
            attribute_count = 1
        field_access = clean_field_access(item.access)
        if info.access_rom & ACC_INTERFACE:
            field_access |= ACC_PUBLIC | ACC_STATIC | ACC_FINAL
        field_rows.append(
            struct.pack(">HHHH", field_access,
                        cp.utf8(emitted_name), cp.utf8(item.descriptor),
                        attribute_count) + attributes)

    out = bytearray(struct.pack(">IHH", 0xCAFEBABE, 3, 45))
    # All entries have now been interned.
    out += cp.render()
    out += struct.pack(">HHH", clean_class_access(info.access_rom), this_class, super_class)
    out += struct.pack(">H", len(interface_indices))
    out += b"".join(struct.pack(">H", value) for value in interface_indices)
    out += struct.pack(">H", len(field_rows)) + b"".join(field_rows)
    out += struct.pack(">H", len(method_models))
    for access, name_index, descriptor_index, count, attributes in method_models:
        out += struct.pack(">HHHH", access, name_index, descriptor_index, count) + attributes
    out += struct.pack(">H", 0)
    return bytes(out), recovered_count, statuses


def metadata(extractor: ROMExtractor, info: ClassInfo,
             statuses: Optional[dict[int, str]] = None) -> dict:
    super_info = extractor.superclass(info)
    return {
        "format": "phoneme-source-rom-v1",
        "class_id": info.class_id,
        "name": info.name,
        "super": super_info.name if super_info else None,
        "access_rom": f"0x{info.access_rom:08x}",
        "class_info": f"0x{info.info_pointer:08x}",
        "java_class": f"0x{info.java_class_pointer:08x}" if info.java_class_pointer else None,
        "interfaces": [extractor.classes[i].name if i in extractor.classes
                       else f"unknown/Interface{i}" for i in info.interface_ids],
        "fields": [vars(item) for item in info.fields],
        "methods": [
            {
                "address": f"0x{item.address:08x}",
                "access_rom": f"0x{item.access_rom:04x}",
                "holder_id": item.holder_id,
                "name": item.name,
                "emitted_name": emitted_member_name(item.name, item.address, "method"),
                "descriptor": item.descriptor,
                "constants_pointer": f"0x{item.constants_pointer:08x}",
                "max_stack": item.max_stack,
                "max_locals": item.max_locals,
                "method_attributes": f"0x{item.attributes:04x}",
                "quickened_code": item.code.hex(),
                "emitted_body": (statuses or {}).get(item.address, "not emitted"),
                "exception_table_pointer": f"0x{item.exception_table_pointer:08x}" if item.exception_table_pointer else None,
            }
            for item in info.methods
        ],
    }


def write_native_symbols(extractor: ROMExtractor, path: Path) -> tuple[int, int]:
    """Write Ghidra function symbols for every retained native method.

    Quick natives keep their direct target in the max-stack/max-locals union.
    Ordinary natives keep a direct target in the bytecode payload, while a
    minority also have a useful method-specific execution stub. Prefer that
    stub when it is a real, non-shared flash address; otherwise naming the
    common interpreter dispatcher would collapse hundreds of Java methods.
    """
    native_methods: list[tuple[ClassInfo, MethodInfo]] = []
    for info in extractor.classes.values():
        if info.name is None or info.name.startswith("["):
            continue
        if not info.methods:
            extractor.parse_class(info)
        for method in info.methods:
            if method.access_rom & ACC_NATIVE:
                native_methods.append((info, method))

    execution_entries = [extractor.image.u32(method.address + 16)
                         for _, method in native_methods if method.code]
    execution_counts = collections.Counter(execution_entries)

    def in_firmware(address: int) -> bool:
        return (extractor.image.flash_base <= address <
                extractor.image.flash_base + len(extractor.image.data))

    used_names: collections.Counter[str] = collections.Counter()
    rows: list[tuple[int, str]] = []
    quick_count = 0
    for info, method in native_methods:
        if not method.code:
            address = extractor.image.u32(method.address + 28)
            quick_count += 1
        else:
            execution = extractor.image.u32(method.address + 16)
            direct = extractor.image.u32(method.address + 44)
            address = (execution if in_firmware(execution) and
                       execution_counts[execution] <= 2 else direct)
        if not in_firmware(address):
            continue
        class_name = re.sub(r"[^0-9A-Za-z_]", "_", info.name)
        method_name = emitted_member_name(method.name, method.address, "method")
        method_name = {"<init>": "init", "<clinit>": "clinit"}.get(
            method_name, method_name)
        method_name = re.sub(r"[^0-9A-Za-z_]", "_", method_name)
        base = f"{class_name}_{method_name}"
        used_names[base] += 1
        name = base if used_names[base] == 1 else f"{base}_{used_names[base]}"
        rows.append((address, name))

    rows.sort(key=lambda item: (item[0], item[1]))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"F\t{address:08X}\t{name}\n"
                            for address, name in rows))
    return len(rows), quick_count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", type=Path)
    parser.add_argument("class_names", nargs="*", help="internal names, e.g. java/lang/Object")
    parser.add_argument("-o", "--output", type=Path, default=Path("phoneme-classes"))
    parser.add_argument("--list", action="store_true", help="list recovered instance classes")
    parser.add_argument("--all", action="store_true", help="emit every recovered instance class")
    parser.add_argument("--recover-bodies", action=argparse.BooleanOptionalAction,
                        default=True,
                        help="dequicken and recover Java method bodies (default: enabled)")
    parser.add_argument("--package-unknown", action="store_true",
                        help="place ROMizer-renamed classes in inferred packages")
    parser.add_argument("--metadata", action="store_true",
                        help="write optional adjacent .rom.json files")
    parser.add_argument("--base-address", type=parse_address, default=FLASH_BASE,
                        help="firmware base, e.g. A0000000 (default: A0000000)")
    parser.add_argument("--structure-address", type=parse_address,
                        help="java/lang/Object ClassInfo body address")
    parser.add_argument("--constant-pool-address", type=parse_address,
                        help="override the detected system ConstantPool address")
    parser.set_defaults(metadata=False)
    args = parser.parse_args()

    extractor = ROMExtractor(
        Image(args.firmware, args.base_address),
        cp_pointer=args.constant_pool_address,
        structure_address=args.structure_address,
    )
    try:
        extractor.scan_classes()
    except ValueError as error:
        raise SystemExit(f"ROM layout detection failed: {error}") from error
    assert extractor.structure_address is not None
    assert extractor.cp_pointer is not None
    print("ROM layout: "
          f"base=0x{extractor.image.flash_base:08X}, "
          f"object_classinfo=0x{extractor.structure_address:08X}, "
          f"constant_pool=0x{extractor.cp_pointer:08X}, "
          f"classes={len(extractor.classes)}")
    for info in extractor.classes.values():
        if info.name and not info.name.startswith("["):
            extractor.parse_class(info)
    if args.package_unknown:
        extractor.assign_unknown_packages()
    instance_classes = {item.name: item for item in extractor.classes.values() if item.name and not item.name.startswith("[")}
    if args.list:
        for name in sorted(instance_classes):
            print(f"{instance_classes[name].class_id:4d} {name}")
    list_only = args.list and not args.class_names and not args.all
    names = (sorted(instance_classes) if args.all else
             args.class_names if args.class_names else
             [] if list_only else ["java/lang/Object"])
    selected: list[ClassInfo] = []
    for name in names:
        info = instance_classes.get(name)
        if info is None:
            raise SystemExit(f"class not found: {name}")
        selected.append(info)

    if args.recover_bodies:
        # Dequickening can reveal fields and directly referenced methods that
        # ROMizer removed from reflection metadata.  Iterate to a fixed point
        # before serializing any owner, including owners that sort before
        # their first caller.
        while True:
            before = tuple((info.class_id,
                            tuple((field.offset, field.descriptor)
                                  for field in info.fields),
                            tuple(method.address for method in info.methods))
                           for info in selected)
            for info in selected:
                build_stub_class(extractor, info, recover_bodies=True)
            after = tuple((info.class_id,
                           tuple((field.offset, field.descriptor)
                                 for field in info.fields),
                           tuple(method.address for method in info.methods))
                          for info in selected)
            if after == before:
                break

        # Interfaces have no instance storage. Any synthetic instance field
        # attributed to one came from a receiver's static interface type and
        # is superseded by the concrete-owner fallback above.
        for info in selected:
            if info.access_rom & ACC_INTERFACE:
                info.fields[:] = [field for field in info.fields
                                  if not field.synthetic_name]

    for info in extractor.classes.values():
        if info.name and not info.name.startswith("["):
            assign_synthetic_member_names(info)

    native_symbols = args.output / "native-symbols.txt"
    count, quick_count = write_native_symbols(extractor, native_symbols)
    print(f"native symbols: {count} functions ({quick_count} quick) -> "
          f"{native_symbols}")

    for info in selected:
        name = info.name
        assert name is not None
        target = args.output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        class_bytes, recovered, statuses = build_stub_class(extractor, info, args.recover_bodies)
        target.with_suffix(".class").write_bytes(class_bytes)
        if args.metadata:
            target.with_suffix(".rom.json").write_text(
                json.dumps(metadata(extractor, info, statuses), indent=2) + "\n")
        detail = f", {recovered} recovered bodies" if args.recover_bodies else ""
        print(f"{name}: {len(info.fields)} fields, {len(info.methods)} methods{detail} -> {target.with_suffix('.class')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
