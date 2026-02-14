# OpenAPI-NG

A next-generation Burp Suite extension for loading OpenAPI specifications and sending parsed endpoints to the Scanner, Repeater, and Intruder tools. A successor to the legacy OpenAPI Parser.

## Features

- **Multiple loading methods:** Drag-and-drop, URL, file path (including network drives), or paste raw JSON/YAML
- **Base URL override:** Override the server URL from the spec for different environments
- **Endpoint table:** View all parsed endpoints with method, path, parameters, and description
- **Regex filter:** Filter endpoints by path or other columns
- **Request preview:** See the generated HTTP request for the selected endpoint
- **Actively Scan:** Send selected endpoints to Burp Scanner (Professional only)
- **Send to Repeater/Intruder:** Open requests in Repeater or Intruder with auto-highlighted insertion points
- **Keyboard shortcut:** Ctrl+I / Cmd+I sends selection to Intruder
- **Shell prompt stripping:** Automatically ignores leading terminal output when pasting specs

## Supported Specs

OpenAPI 2.0 (Swagger) and OpenAPI 3.x, in JSON or YAML format.

## Installation

1. Build the extension: `./gradlew build` (or `gradlew.bat build` on Windows)
2. Load the JAR in Burp: **Extensions** → **Installed** → **Add** → **Extension type: Java** → select `build/libs/OpenAPI-NG-1.0.jar`

## Build

```bash
./gradlew build
```

Requires Java 17+.

## License

MIT. See [LICENSE](LICENSE).
