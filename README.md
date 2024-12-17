# 👾 Hide Shellcode Payload in Images 👾
**-> A project that demonstrates embedding shellcode payloads into image files (like PNGs) using Python and extracting them using C/C++. Payloads can be retrieved directly from the file on disk or from the image stored in a binary's resources section (.rsrc)**

### 🔍 Learn more about this in my blog post:
- **[Blog post link](https://wafflesexploits.github.io/posts/Hide_a_Payload_in_Plain_Sight_Embedding_Shellcode_in_a_Image_file/#store-the-image-file-in-the-resources-section-rsrc-of-a-binary-file)**

### Code of this Project
- [payload-embedder.py](https://github.com/WafflesExploits/hide-payload-in-images/blob/main/code/payload-embedder.py)
  - Append shellcode payloads to the end of an image file.
- [payload-extractor-from-file.cpp](https://github.com/WafflesExploits/hide-payload-in-images/blob/main/code/payload-extractor/payload-extractor-from-file/payload-extractor-from-file.cpp)
  - Extract payloads from modified image files stored on disk.
- [payload-extractor-from-resource.cpp](https://github.com/WafflesExploits/hide-payload-in-images/blob/main/code/payload-extractor/payload-extractor-from-rsrc/payload-extractor-from-rsrc.cpp)
  - Extract payloads from image files stored in the binary's resources section (.rsrc).

### 🎥 Video Demo
👉 Watch the full video demo here:
<img src="https://github.com/user-attachments/assets/29ce7210-ae42-40bb-a759-2d89cefd0e0c" width="767" height="361"/>


## Support & Contributions
Enjoying my content? Show your support by sharing or starring the repo! 

You can also support me on buy me a ko-fi to fuel more awesome content:

[![Buy me a KO-FI](https://img.shields.io/badge/-Buy%20me%20a%20KOFI-FF5F1D?style=for-the-badge&logo=KO-FI&logoColor=fff)](https://ko-fi.com/wafflesexploits)

💬 Have feedback or ideas? I’d love to hear your thoughts or suggestions!

#### Looking for a Pentester? I’m open for contracts and full-time opportunities – feel free to DM me!

