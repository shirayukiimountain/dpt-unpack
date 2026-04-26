# DPT-Shell Unpacker

A command-line tool written in Kotlin designed to statically unpack Android applications that are protected by DPT-Shell.

## Key Features

*   **Automatic Extraction:** Automatically extracts the compressed and hidden DEX data from within `classes.dex`.
*   **Method Body Patching:** Replaces empty or junk method instructions with the correct instructions from the `assets/OoooooOooo` file.
*   **Compatibility Parser:** Supports the standard DPT-Shell code-item layout and a size-first XOR-encoded variant found in newer/protected samples.
*   **DEX Header Correction:** Automatically fixes the SHA-1 and checksum headers on the patched DEX files.
*   **Optional:** Provides an option to remove the JNI bridge call from the static constructor (`<clinit>`).
*   **Application Class Identification:** Attempts to identify the app's original `Application` class.

## Local Dependency Setup

This project requires the Android `dx.jar` (Dex parser) as a dependency. This JAR is not available on public Maven repositories and must be installed into your local Maven repository (`~/.m2`).

Before building, run the following command from the project root directory:

```bash
mvn install:install-file \
  -Dfile=libs/dx.jar \
  -DgroupId=com.android \
  -DartifactId=dx \
  -Dversion=1.0 \
  -Dpackaging=jar \
  -DgeneratePom=true \
  -DcreateChecksum=true
```

## How to Build

1.  Ensure you have Java (JDK 8 or higher) and Maven installed.
2.  Build the project using the Maven command:
    ```bash
    mvn package
    ```
3.  An `unpack-dpt.jar` file will be created in the `target` directory.

## Usage

Run the tool using the following command:

```bash
java -jar target/unpack-dpt.jar -f /path/to/your/app.apk
```

Replace `/path/to/your/app.apk` with the actual path to the Android application package file.
By default, patched DEX files are written to the `unpacked/patched_dex` directory.

To choose a custom output directory:

```bash
java -jar target/unpack-dpt.jar -f /path/to/your/app.apk -o /path/to/output_dir
```

> Note: `-o` expects a directory path, not an APK file path.

To see the available options:

```bash
java -jar target/unpack-dpt.jar -h
```

## How It Works

DPT-Shell stores the protected application's DEX files and original method instructions separately:

1.  The original/hollowed DEX files are compressed into `i11111i111.zip`.
2.  That ZIP is appended to the shell `classes.dex`.
3.  The last 4 bytes of the shell `classes.dex` store the ZIP size.
4.  Original method instruction bytes are stored in `assets/OoooooOooo`.

The unpacker reverses that process:

1.  Reads the ZIP size from the last 4 bytes of `classes.dex`.
2.  Extracts the appended `i11111i111.zip`.
3.  Parses `assets/OoooooOooo`.
4.  Matches each stored method body by `methodIndex`.
5.  Writes the restored instructions to each method's `code_item` at `codeOffset + 16`.
6.  Recomputes the DEX SHA-1 and Adler32 checksum headers.

The normal `OoooooOooo` instruction record layout is:

```text
u16 version
u16 dexCount
u32 dexCodeOffset[dexCount]

per dex section:
  u16 methodCount
  repeated method records:
    u32 methodIndex
    u32 instructionSize
    byte[instructionSize] instructions
```

Some protected samples use a compatible variant:

```text
u32 instructionSize
u32 methodIndex
byte[instructionSize] xor_0x6f_instructions
```

For that variant, the unpacker automatically detects the size-first layout and decodes each instruction byte with:

```text
decoded = encoded XOR 0x6f
```

This is why the parser validates record sizes before patching. If the original layout produces impossible instruction sizes, the tool retries with the size-first compatibility layout.

## Thanks to

· NullRE / NullPointerException - For providing insights into the unpacking workflow of DPT-Shell and explaining how the protector works.

· Android Reverse Engineering Community - For discussions, insights, and shared knowledge that helped in understanding the DPT-Shell protection mechanism.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
