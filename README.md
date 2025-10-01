# Hiding Shellcode in Image Files with Python and C/C++
**-> A project that demonstrates embedding shellcode payloads into image files (like PNGs) using Python and extracting them using C/C++. Payloads can be retrieved directly from the file on disk or from the image stored in a binary's resources section (.rsrc)**

#### Note: This repository just hit 187 stars ⭐! Thank you guys so much for your support!

### 🔍 Learn more about this in my blog post:
- **[Blog post link](https://andrecrafts.com/posts/hide-shellcode-in-images/)**

### Code of this Project
- [payload-embedder.py](https://github.com/andrecrafts/hide-payload-in-images/blob/main/code/payload-embedder.py)
  - Append shellcode payloads to the end of an image file.
- [payload-extractor-from-file.cpp](https://github.com/andrecrafts/hide-payload-in-images/blob/main/code/payload-extractor/payload-extractor-from-file/payload-extractor-from-file.cpp)
  - Extract payloads from modified image files stored on disk.
- [payload-extractor-from-resource.cpp](https://github.com/andrecrafts/hide-payload-in-images/blob/main/code/payload-extractor/payload-extractor-from-rsrc/payload-extractor-from-rsrc.cpp)
  - Extracts payloads from image files stored in the binary's resources section (.rsrc) using WinAPI functions like `FindResource` and `LockResource`. 
- **(NEW)** [payload-extractor-from-resource-via-peb.cpp](https://github.com/andrecrafts/hide-payload-in-images/blob/main/code/payload-extractor/payload-extractor-from-rsrc-via-peb/payload-extractor-from-rsrc-via-peb.cpp)
  - Extracts payloads from image files stored in the binary's resources section by manually parsing the Process Environment Block (PEB) and PE headers, **avoiding WinAPI functions for increased stealth**. 

#### ❗ Updates ❗
1. **Stealthier Payload Extraction:** Implemented manual PE header parsing to retrieve resources without WinAPI calls, avoiding detection vectors.
2. **PEB Reliability Fix:** Replaced function `hGetCurrentModuleHandle`'s unsafe backward header parsing with direct PEB access via __readgsqword/__readfsdword, resolving compiler-optimization crashes and supporting x86/x64. This new function has two alternatives, based on whether the project is a DLL or a EXE.
3. **PEB Structure Support:** Added `PEB_Structs.h` for portable PEB/PE definitions, eliminating dependencies on Windows headers.

### 🎥 Video Demo
👉 Watch the full video demo here:
<img src="https://github.com/user-attachments/assets/daee10b0-196f-4961-8153-0dcf81f8b5db" width="767" height="361"/>
- Updated to include payload-extractor-from-resource-via-peb.cpp demo.

## Support & Contributions
Enjoying my content? Show your support by sharing or starring the repo! 

You can also support me on buy me a ko-fi to fuel more awesome content:

[![Buy me a KO-FI](https://img.shields.io/badge/-Buy%20me%20a%20KOFI-FF5F1D?style=for-the-badge&logo=KO-FI&logoColor=fff)](https://ko-fi.com/wafflesexploits)

💬 Have feedback or ideas? I’d love to hear your thoughts or suggestions!

#### Looking for a Pentester? I’m open for contracts and full-time opportunities – feel free to DM me!

## Credits 
- The `GetResourceData` function is based on code from [@NUL0x4C's AtomLdr](https://github.com/NUL0x4C/AtomLdr)

Made with 💙 by [@andrecrafts](https://github.com/andrecrafts)

