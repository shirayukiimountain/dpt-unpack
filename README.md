# DPT-Shell Unpacker

A command-line tool written in Kotlin designed to statically unpack Android applications that are protected by DPT-Shell.

## Key Features

*   **Automatic Extraction:** Automatically extracts the compressed and hidden DEX data from within `classes.dex`.
*   **Method Body Patching:** Replaces empty or junk method instructions with the correct instructions from the `assets/OoooooOooo` file.
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

To see the available options:

```bash
java -jar target/unpack-dpt.jar -h
```

## Thanks to

· NullRE / NullPointerException - For providing insights into the unpacking workflow of DPT-Shell and explaining how the protector works.

· Android Reverse Engineering Community - For discussions, insights, and shared knowledge that helped in understanding the DPT-Shell protection mechanism.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
