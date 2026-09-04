# phoneME / KVM ROM extractor

Extracts valid Java `.class` files and native method symbols from a Siemens
phoneME (SGOLD) or C166 KVM (EGOLD) fullflash. Tested with EL71, CX75, M55 v91 and A31.

## Usage

Extract all classes:

```sh
python3 phoneme_rom_extract.py firmware.bin \
  --all --package-unknown \
  -o extracted
```

Extract selected classes:

```sh
python3 phoneme_rom_extract.py firmware.bin \
  java/lang/Object java/lang/Math \
  -o extracted
```

The script scans the complete image and detects the ROM format automatically.
EGOLD works the same way:

```sh
python3 phoneme_rom_extract.py M55_v91.bin --all -o m55-classes
```

For a non-standard image
mapping or manual structure selection, use:

```sh
python3 phoneme_rom_extract.py firmware.bin \
  --base-address A0000000 \
  --structure-address 0xA04029BC \
  --all -o extracted
```

## Options

- `--all` — extract all classes.
- `--list` — list detected classes.
- `--no-recover-bodies` — emit structural classes without recovered bodies.
- `--package-unknown` — infer packages for classes with erased names.
- `--metadata` — enable `.rom.json` output.
- `--format auto|phoneme|kvm` — force a ROM format (default: auto).
- `--base-address ADDRESS` — firmware base, e.g. `A0000000`; KVM detects `0x200000` or `0`.
- `--structure-address ADDRESS` — `java/lang/Object` structure address in flash.
- `--constant-pool-address ADDRESS` — override phoneME ConstantPool detection.

## Output

The output directory contains:

- recovered `.class` files;
- `native-symbols.txt` for Ghidra, one native method per line:

```text
F    A0A94A20    java_lang_Math_sin
```

To decompile the result with Fernflower:

```sh
fernflower -dgs=true -rsy=false extracted sources
```

KVM preserves method bytecode, exception handlers, names and static constants.
Its VM-only `Class.runCustomCode()` is restored to an empty Java placeholder.
Native implementations, local variable names and declared `throws` are not
reconstructed. Native methods remain native; decompilation is not a guarantee
that the sources compile unchanged against a desktop JDK.
Native targets outside the dump or in erased areas are retained in the symbol
file with a warning (e.g. A31 `System.arraycopy`).
