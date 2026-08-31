# phoneME ROM extractor

Extracts valid Java `.class` files and native method symbols from a Siemens
phoneME fullflash.

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

The script scans the complete image automatically. For a non-standard image
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
- `--base-address ADDRESS` — firmware base, e.g. `A0000000`.
- `--structure-address ADDRESS` — `java/lang/Object` `ClassInfo` address.
- `--constant-pool-address ADDRESS` — override ConstantPool detection.

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
