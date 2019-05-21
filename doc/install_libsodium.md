# Installing Libsodium

## Windows
1. Libsodium can be downloaded from https://download.libsodium.org/libsodium/releases/  
         For eg. https://download.libsodium.org/libsodium/releases/libsodium-1.0.17-msvc.zip
2. Extract the files from the zip file
3. There are two extracted directories: `x64` and `Win32`. Select `x64` for 64-bit or `Win32` for 32-bit versions of Windows, and search for `libsodium.dll`. You can find one inside `Release/v141/dynamic/libsodium.dll`
4. Copy this `libsodium.dll` file and paste it in `C:\Windows\system32`

## MacOS
Homebrew can be used to install libsodium:
```
brew install libsodium
```
For details, check [here](http://macappstore.org/libsodium/).