# crypto-algorithms
Different popular cryptography algorithms, like:
- Symmetric cypher algorithm DES, Triple DES
- Symmetric cypher algorithm GOST 28147-89
- Asymmetric cypher algorithm RSA
- Hash function GOST 34.11-94
- Digital Signature Algorithm
- Elliptical Signature Algorithm (Gost 34.10-2012)

### How to build?
Currently, project supports only Windows and Macos platforms, but it also can be easily configured for Linux.

### Macos
```
$ mkdir build
$ cd build
$ CMake -G Xcode ..
```

And then you can select needed algorithm via `Product`->`Scheme`->`Choose scheme`

### Windows (Using VS generator)
```
$ CMake -G "Visual Studio 16 2019"
```

And then you can select needed algorithm in project explorer, right click, `Set as StartUp project`
